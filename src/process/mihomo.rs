use std::{
    fs,
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{mpsc, watch},
    time,
};
use tracing::{info, warn};

const MIHOMO_BIN: &str = "/data/adb/f50mgr/bin/mihomo";
const CLASH_DIR: &str = "/data/adb/f50mgr/config/clash";
const CONFIG_FILE: &str = "/data/adb/f50mgr/config/clash/config.yaml";
const F50MGR_CONFIG_FILE: &str = "/data/adb/f50mgr/config/f50mgr.toml";
const RUN_DIR: &str = "/data/adb/f50mgr/run";
const PID_FILE: &str = "/data/adb/f50mgr/run/mihomo.pid";
const RESTART_DELAY: Duration = Duration::from_secs(3);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const STABLE_RUN: Duration = Duration::from_secs(60);
const MAX_FAILURES: u32 = 3;
/// 连续失败达 MAX_FAILURES 后的长退避。watchdog 永不放弃：daemon 是 mihomo 的唯一
/// 拉起者，watchdog 退出（旧行为 bail）会连带打死整个 daemon（含 Web 面板），
/// 且 TPROXY 规则残留 fail-closed 黑洞 —— 只能退避重试，不能返回 Err。
const FAILURE_BACKOFF: Duration = Duration::from_secs(60);
/// API 健康探测参数。真机事故（2026-07-16）：蜂窝数据切换触发 mihomo 监听器
/// 重建失败，进程存活但所有端口消失（"活着但聋了"）——进程 watchdog 不重启、
/// iptables watchdog 永远等不到健康，代理永久停在直连。探测本机 API 端口补上
/// 这个盲区：豁免启动期后连续 HEALTH_MAX_FAILURES 次连不上就强制重启。
const HEALTH_GRACE: Duration = Duration::from_secs(60);
const HEALTH_INTERVAL: Duration = Duration::from_secs(15);
const HEALTH_MAX_FAILURES: u32 = 3;
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const UPDATE_HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
const UPDATE_HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const UPDATE_VERSION_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
struct Paths {
    mihomo_bin: PathBuf,
    clash_dir: PathBuf,
    config_file: PathBuf,
    run_dir: PathBuf,
    pid_file: PathBuf,
}

impl Paths {
    fn runtime() -> Self {
        Self {
            mihomo_bin: PathBuf::from(MIHOMO_BIN),
            clash_dir: PathBuf::from(CLASH_DIR),
            config_file: PathBuf::from(CONFIG_FILE),
            run_dir: PathBuf::from(RUN_DIR),
            pid_file: PathBuf::from(PID_FILE),
        }
    }
}

/// 运行期 API 健康探测配置；None 表示不探测（部分单测场景）。
#[derive(Debug, Clone)]
struct HealthOptions {
    api_addr: SocketAddr,
    grace: Duration,
    interval: Duration,
    max_failures: u32,
    probe: HealthProbe,
}

#[derive(Debug, Clone)]
enum HealthProbe {
    Tcp,
    #[cfg(test)]
    Fixed(bool),
}

#[derive(Debug, Clone)]
struct WatchdogOptions {
    paths: Paths,
    management_secret: String,
    restart_delay: Duration,
    stop_timeout: Duration,
    stable_run: Duration,
    max_failures: u32,
    failure_backoff: Duration,
    health: Option<HealthOptions>,
    disable_rules: fn() -> Result<()>,
    record_restart: fn(bool),
}

impl WatchdogOptions {
    fn runtime() -> Result<Self> {
        let management_secret = crate::web::auth_store::read_management_key()
            .context("读取 Mihomo Controller 管理密钥失败")?;
        Ok(Self {
            paths: Paths::runtime(),
            management_secret,
            restart_delay: RESTART_DELAY,
            stop_timeout: STOP_TIMEOUT,
            stable_run: STABLE_RUN,
            max_failures: MAX_FAILURES,
            failure_backoff: FAILURE_BACKOFF,
            health: Some(HealthOptions {
                api_addr: crate::MIHOMO_API_ADDR
                    .parse()
                    .expect("MIHOMO_API_ADDR 是合法的 SocketAddr 字面量"),
                grace: HEALTH_GRACE,
                interval: HEALTH_INTERVAL,
                max_failures: HEALTH_MAX_FAILURES,
                probe: HealthProbe::Tcp,
            }),
            disable_rules: crate::iptables::rules::disable,
            record_restart,
        })
    }
}

#[derive(Debug)]
pub struct Status {
    pub pid: Option<u32>,
    pub running: bool,
}

/// watchdog 可观测快照（R4）：/api/status 暴露，用户可判断 mihomo 是否在反复重启。
#[derive(Debug, serde::Serialize)]
pub struct WatchdogSnapshot {
    /// 异常退出后的重启次数（daemon 本次运行内累计）
    pub restarts: u32,
    /// 聋态（进程活但 API 死）强制重启次数
    pub deaf_restarts: u32,
    /// 上次任意重启的 unix 秒；从未重启过为 None
    pub last_restart_unix: Option<u64>,
}

pub fn watchdog_snapshot() -> WatchdogSnapshot {
    let last = stats::LAST_RESTART_UNIX.load(Ordering::Relaxed);
    WatchdogSnapshot {
        restarts: stats::RESTARTS.load(Ordering::Relaxed),
        deaf_restarts: stats::DEAF_RESTARTS.load(Ordering::Relaxed),
        last_restart_unix: (last != 0).then_some(last),
    }
}

mod stats {
    use std::sync::atomic::{AtomicU32, AtomicU64};

    pub static RESTARTS: AtomicU32 = AtomicU32::new(0);
    pub static DEAF_RESTARTS: AtomicU32 = AtomicU32::new(0);
    pub static LAST_RESTART_UNIX: AtomicU64 = AtomicU64::new(0);
}

fn record_restart(deaf: bool) {
    if deaf {
        stats::DEAF_RESTARTS.fetch_add(1, Ordering::Relaxed);
    } else {
        stats::RESTARTS.fetch_add(1, Ordering::Relaxed);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    stats::LAST_RESTART_UNIX.store(now, Ordering::Relaxed);
}

pub async fn run_watchdog_with_updates(
    mut shutdown: watch::Receiver<bool>,
    updates: mpsc::Receiver<crate::update::PreparedUpdate>,
) -> Result<()> {
    run_watchdog_core(&mut shutdown, WatchdogOptions::runtime()?, Some(updates)).await
}

#[cfg(test)]
async fn run_watchdog_with_options(
    shutdown: &mut watch::Receiver<bool>,
    options: WatchdogOptions,
) -> Result<()> {
    run_watchdog_core(shutdown, options, None).await
}

async fn run_watchdog_core(
    shutdown: &mut watch::Receiver<bool>,
    options: WatchdogOptions,
    mut updates: Option<mpsc::Receiver<crate::update::PreparedUpdate>>,
) -> Result<()> {
    let mut failures = 0_u32;
    let mut last_missing = None;
    let mut installed_update: Option<crate::update::InstalledUpdate> = None;

    // 上一代 daemon 非正常退出（kill -9）会留下孤儿 Mihomo，先回收再进入主循环
    while !reap_stale_instance(&options.paths, options.stop_timeout).await {
        if wait_or_shutdown(shutdown, options.restart_delay).await {
            return Ok(());
        }
    }

    'main: loop {
        if is_shutdown(shutdown) {
            break;
        }
        // 配置读取/解析失败不打死 watchdog（daemon 是 mihomo 唯一拉起者），按默认值继续。
        let auto_start = auto_start_enabled().unwrap_or_else(|err| {
            warn!(error = %err, "读取 mihomo.auto_start 失败，按默认 true 处理");
            true
        });
        if !auto_start {
            remove_pid_file(&options.paths)?;
            if wait_or_shutdown(shutdown, options.restart_delay).await {
                break;
            }
            continue;
        }

        if let Some(path) = missing_prerequisite(&options.paths) {
            if last_missing != Some(path) {
                warn!(path = %path.display(), "Mihomo 运行文件未就绪，暂不启动");
                last_missing = Some(path);
            }
            if wait_or_shutdown(shutdown, options.restart_delay).await {
                break;
            }
            continue;
        }
        last_missing = None;

        let started_at = Instant::now();
        let mut child = match spawn_mihomo(&options.paths, &options.management_secret) {
            Ok(child) => child,
            Err(err) => {
                if let Some(installed) = installed_update.take() {
                    let message = format!("新版本启动失败: {err}");
                    crate::update::rollback_candidate(&installed)
                        .context("Mihomo 新版本启动失败后回滚失败")?;
                    crate::update::activation_failed(&installed.prepared, message.clone());
                    warn!(error = %message, "Mihomo 更新已回滚");
                    failures = 0;
                    continue;
                }
                failures += 1;
                warn!(error = %err, failures, "启动 Mihomo 失败");
                if backoff_or_shutdown(shutdown, &options, &mut failures).await {
                    break;
                }
                continue;
            }
        };
        let pid = child.id().context("Mihomo 子进程缺少 PID")?;
        write_pid_file(&options.paths, pid)?;
        info!(pid, "Mihomo 已启动");

        if let Some(installed) = installed_update.take() {
            match validate_updated_child(
                &mut child,
                &options,
                &installed.prepared.version,
                shutdown,
            )
            .await?
            {
                UpdateValidation::Healthy => {
                    if let Err(commit_err) = installed.commit() {
                        stop_child(&mut child, &options.paths, options.stop_timeout).await?;
                        crate::update::rollback_candidate(&installed).with_context(|| {
                            format!("提交 Mihomo 更新失败（{commit_err}）且回滚失败")
                        })?;
                        let error = format!("提交已验证 Mihomo 更新失败: {commit_err}");
                        crate::update::activation_failed(&installed.prepared, error.clone());
                        warn!(version = %installed.prepared.version, %error, "Mihomo 更新已回滚");
                        failures = 0;
                        continue;
                    }
                    crate::update::activation_succeeded(&installed.prepared);
                    info!(version = %installed.prepared.version, "Mihomo 更新已通过启动健康验证");
                }
                UpdateValidation::Failed { child_exited, error } => {
                    if !child_exited {
                        stop_child(&mut child, &options.paths, options.stop_timeout).await?;
                    } else {
                        remove_pid_file(&options.paths)?;
                    }
                    crate::update::rollback_candidate(&installed)
                        .context("Mihomo 更新健康验证失败后回滚失败")?;
                    crate::update::activation_failed(&installed.prepared, error.clone());
                    warn!(version = %installed.prepared.version, %error, "Mihomo 更新已回滚");
                    failures = 0;
                    continue;
                }
                UpdateValidation::Shutdown => {
                    stop_child(&mut child, &options.paths, options.stop_timeout).await?;
                    crate::update::rollback_candidate(&installed)
                        .context("daemon 退出时回滚未验证 Mihomo 更新失败")?;
                    crate::update::activation_failed(
                        &installed.prepared,
                        "daemon 在更新验证期间退出".to_owned(),
                    );
                    break 'main;
                }
            }
        }

        let mut health_failures = 0_u32;
        loop {
            tokio::select! {
                status = child.wait() => {
                    remove_pid_file(&options.paths)?;
                    let status = status.context("等待 Mihomo 退出状态失败")?;
                    if is_shutdown(shutdown) {
                        break 'main;
                    }

                    if started_at.elapsed() >= options.stable_run {
                        failures = 0;
                    }
                    failures += 1;
                    (options.record_restart)(false);
                    warn!(pid, ?status, failures, "Mihomo 异常退出，准备重启");
                    if backoff_or_shutdown(shutdown, &options, &mut failures).await {
                        break 'main;
                    }
                    break;
                }
                // 进程存活 ≠ 服务可用：真机实测蜂窝数据切换可让 mihomo 监听器
                // 全部消失（活着但聋了），必须靠 API 探测发现并强制重启。
                _ = health_wait(options.health.as_ref(), started_at), if options.health.is_some() => {
                    let health = options.health.as_ref().expect("guard 保证 health 存在");
                    // 顺带兜底日志上界：warning 级 spam（如坏节点拨号失败）单次运行
                    // 无法靠 spawn 时轮转控制，超限原地截断
                    crate::process::truncate_oversized_log(
                        &options.paths.run_dir.join("mihomo.log"),
                        crate::process::LOG_MAX_SIZE,
                    );
                    if api_responsive(health).await {
                        health_failures = 0;
                    } else {
                        health_failures += 1;
                        warn!(pid, health_failures, "Mihomo API 探测失败");
                        if health_failures >= health.max_failures {
                            warn!(pid, "Mihomo 进程存活但 API 持续不可连，强制重启");
                            (options.record_restart)(true);
                            stop_child(&mut child, &options.paths, options.stop_timeout).await?;
                            if started_at.elapsed() >= options.stable_run {
                                failures = 0;
                            }
                            failures += 1;
                            if backoff_or_shutdown(shutdown, &options, &mut failures).await {
                                break 'main;
                            }
                            break;
                        }
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || is_shutdown(shutdown) {
                        stop_child(&mut child, &options.paths, options.stop_timeout).await?;
                        break 'main;
                    }
                }
                update = receive_update(&mut updates) => {
                    let Some(prepared) = update else {
                        updates = None;
                        continue;
                    };
                    crate::update::activation_started(&prepared);
                    if let Err(err) = (options.disable_rules)() {
                        crate::update::activation_failed(
                            &prepared,
                            format!("撤除 TPROXY 规则失败: {err}"),
                        );
                        warn!(error = %err, "无法安全进入 Mihomo 更新窗口，保留当前版本");
                        continue;
                    }
                    stop_child(&mut child, &options.paths, options.stop_timeout).await?;
                    let activation_descriptor = prepared.clone();
                    match crate::update::activate_candidate(prepared, &options.paths.mihomo_bin) {
                        Ok(installed) => installed_update = Some(installed),
                        Err(err) => {
                            warn!(error = %err, "激活 Mihomo 更新候选失败，重新启动当前版本");
                            // activate_candidate 在第二次 rename 失败时已恢复 current；此处只清状态。
                            crate::update::activation_failed(
                                &activation_descriptor,
                                err.to_string(),
                            );
                        }
                    }
                    break;
                }
            }
        }
    }

    remove_pid_file(&options.paths)?;
    Ok(())
}

enum UpdateValidation {
    Healthy,
    Failed { child_exited: bool, error: String },
    Shutdown,
}

async fn validate_updated_child(
    child: &mut Child,
    options: &WatchdogOptions,
    expected_version: &str,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<UpdateValidation> {
    let Some(health) = &options.health else {
        return Ok(match child.try_wait().context("检查更新后 Mihomo 进程失败")? {
            Some(status) => UpdateValidation::Failed {
                child_exited: true,
                error: format!("新版本启动后立即退出: {status}"),
            },
            None => UpdateValidation::Healthy,
        });
    };
    let deadline = Instant::now() + UPDATE_HEALTH_TIMEOUT;
    loop {
        tokio::select! {
            status = child.wait() => {
                return Ok(UpdateValidation::Failed {
                    child_exited: true,
                    error: format!("新版本健康验证前退出: {}", status?),
                });
            }
            _ = time::sleep(UPDATE_HEALTH_INTERVAL) => {
                if updated_api_matches(
                    health,
                    &options.management_secret,
                    expected_version,
                ).await {
                    return Ok(UpdateValidation::Healthy);
                }
                if Instant::now() >= deadline {
                    return Ok(UpdateValidation::Failed {
                        child_exited: false,
                        error: "新版本 30 秒内未通过 API 健康验证".to_owned(),
                    });
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || is_shutdown(shutdown) {
                    return Ok(UpdateValidation::Shutdown);
                }
            }
        }
    }
}

async fn receive_update(
    updates: &mut Option<mpsc::Receiver<crate::update::PreparedUpdate>>,
) -> Option<crate::update::PreparedUpdate> {
    match updates {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

pub fn status() -> Result<Status> {
    let paths = Paths::runtime();
    status_with_paths(&paths)
}

fn status_with_paths(paths: &Paths) -> Result<Status> {
    let Some(pid) = read_pid_file(paths)? else {
        return Ok(Status {
            pid: None,
            running: false,
        });
    };

    Ok(Status {
        pid: Some(pid),
        running: match crate::process::PidFd::open_verified(pid, &paths.mihomo_bin) {
            Ok(Some(process)) => process.is_alive()?,
            Ok(None) => false,
            Err(err) => return Err(err).context("无法通过 pidfd 检查 Mihomo 进程"),
        },
    })
}

pub fn auto_start_enabled() -> Result<bool> {
    match fs::read_to_string(F50MGR_CONFIG_FILE) {
        Ok(config) => parse_mihomo_auto_start(&config),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err).with_context(|| format!("读取配置文件失败: {F50MGR_CONFIG_FILE}")),
    }
}

pub fn set_auto_start(enabled: bool) -> Result<()> {
    update_bool_config(F50MGR_CONFIG_FILE, "mihomo", "auto_start", enabled)
}

pub fn stop_running() -> Result<()> {
    let paths = Paths::runtime();
    stop_running_with_paths(&paths)
}

fn stop_running_with_paths(paths: &Paths) -> Result<()> {
    stop_running_with_opener(
        paths,
        crate::process::PidFd::open_verified,
        |process, signal| process.send_signal(signal),
    )
}

fn stop_running_with_opener<H>(
    paths: &Paths,
    open: impl Fn(u32, &Path) -> std::io::Result<Option<H>>,
    send_signal: impl Fn(&H, libc::c_int) -> std::io::Result<()>,
) -> Result<()> {
    let Some(pid) = read_pid_file(paths)? else {
        return Ok(());
    };
    let Some(process) = open(pid, &paths.mihomo_bin)
        .with_context(|| format!("无法通过 pidfd 固定 Mihomo 进程: pid={pid}"))?
    else {
        return remove_pid_file(paths);
    };
    match send_signal(&process, libc::SIGTERM) {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {
            remove_pid_file(paths)?;
            Ok(())
        }
        Err(err) => Err(err).with_context(|| format!("停止 Mihomo 失败: pid={pid}")),
    }
}

fn parse_mihomo_auto_start(config: &str) -> Result<bool> {
    let mut in_mihomo = false;
    for line in config.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_mihomo = line == "[mihomo]";
            continue;
        }
        if !in_mihomo {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "auto_start" {
            continue;
        }
        return match value.trim() {
            "true" => Ok(true),
            "false" => Ok(false),
            value => anyhow::bail!("mihomo.auto_start 只能是 true/false，当前值: {value}"),
        };
    }
    Ok(true)
}

pub(crate) fn update_bool_config(
    path: &str,
    section: &str,
    key: &str,
    enabled: bool,
) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建配置目录失败: {}", parent.display()))?;
    }
    // Mihomo / EasyTier 开关和订阅导入都会写配置目录：共用配置写锁，
    // 避免并发读-改-写互相覆盖另一边的开关（#11）。
    crate::subscription::with_config_write_lock(Path::new(path), || {
        update_bool_config_unlocked(path, section, key, enabled)
    })
}

fn update_bool_config_unlocked(path: &str, section: &str, key: &str, enabled: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let original = fs::read_to_string(path).unwrap_or_default();
    let mut output = Vec::<String>::new();
    let mut in_section = false;
    let mut saw_section = false;
    let mut wrote_key = false;
    let value = if enabled { "true" } else { "false" };

    for line in original.lines() {
        let trimmed = line.split('#').next().unwrap_or_default().trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_section && !wrote_key {
                output.push(format!("{key} = {value}"));
                wrote_key = true;
            }
            in_section = trimmed == format!("[{section}]");
            saw_section |= in_section;
            output.push(line.to_owned());
            continue;
        }
        if in_section {
            if let Some((current_key, _)) = trimmed.split_once('=') {
                if current_key.trim() == key {
                    output.push(format!("{key} = {value}"));
                    wrote_key = true;
                    continue;
                }
            }
        }
        output.push(line.to_owned());
    }

    if saw_section {
        if in_section && !wrote_key {
            output.push(format!("{key} = {value}"));
        }
    } else {
        if !output.is_empty() {
            output.push(String::new());
        }
        output.push(format!("[{section}]"));
        output.push(format!("{key} = {value}"));
    }

    // 原子替换：watchdog 不会读到写了一半的文件。write_atomic 固定 0600，
    // 这里恢复原权限（customize.sh 把 f50mgr.toml 设为 644）。
    let mode = fs::metadata(path)
        .map(|meta| meta.permissions().mode() & 0o7777)
        .unwrap_or(0o644);
    crate::subscription::write_atomic(
        Path::new(path),
        format!("{}\n", output.join("\n")).as_bytes(),
    )
    .with_context(|| format!("写入配置文件失败: {path}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("恢复配置文件权限失败: {path}"))
}

fn missing_prerequisite(paths: &Paths) -> Option<&Path> {
    if !paths.mihomo_bin.is_file() {
        return Some(paths.mihomo_bin.as_path());
    }
    if !paths.config_file.is_file() {
        return Some(paths.config_file.as_path());
    }
    None
}

fn spawn_mihomo(paths: &Paths, management_secret: &str) -> Result<Child> {
    fs::create_dir_all(&paths.run_dir)
        .with_context(|| format!("创建运行目录失败: {}", paths.run_dir.display()))?;
    if crate::subscription::enforce_runtime_defaults_with_secret(
        &paths.config_file,
        management_secret,
    )? {
        info!(
            config = %paths.config_file.display(),
            "Mihomo 配置监听地址已收敛到 F50 内网 IP"
        );
    }

    // stdout/stderr 落盘：daemon 自身由 service.sh 拉起时 stdout 被 Magisk 丢弃，
    // 继承式输出会让 mihomo 日志全部蒸发。打开失败时退回 inherit（日志不阻断启动）。
    let (stdout, stderr) = crate::process::log_stdio_or_inherit(&paths.run_dir.join("mihomo.log"));
    Command::new(&paths.mihomo_bin)
        .arg("-d")
        .arg(&paths.clash_dir)
        .arg("-f")
        .arg(&paths.config_file)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("启动 Mihomo 失败: {}", paths.mihomo_bin.display()))
}

async fn stop_child(child: &mut Child, paths: &Paths, stop_timeout: Duration) -> Result<()> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    return stop_child_with_opener(
        child,
        paths,
        stop_timeout,
        crate::process::PidFd::open_verified,
        |process, signal| process.send_signal(signal),
    )
    .await;

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    return stop_child_with_opener(
        child,
        paths,
        stop_timeout,
        |pid, _| Ok(Some(pid)),
        |pid, signal| signal_process(*pid, signal),
    )
    .await;
}

async fn stop_child_with_opener<H>(
    child: &mut Child,
    paths: &Paths,
    stop_timeout: Duration,
    open: impl Fn(u32, &Path) -> std::io::Result<Option<H>>,
    mut send_signal: impl FnMut(&H, libc::c_int) -> std::io::Result<()>,
) -> Result<()> {
    let Some(pid) = child.id() else {
        remove_pid_file(paths)?;
        return Ok(());
    };

    let Some(process) = open(pid, &paths.mihomo_bin)
        .with_context(|| format!("无法通过 pidfd 固定 Mihomo 子进程: pid={pid}"))?
    else {
        return match child.try_wait().context("检查 Mihomo 是否已退出失败")? {
            Some(status) => {
                info!(pid, ?status, "Mihomo 已先行退出");
                remove_pid_file(paths)
            }
            None => anyhow::bail!("Mihomo 子进程身份不匹配，拒绝按 PID 终止: pid={pid}"),
        };
    };

    info!(pid, "向 Mihomo 发送 SIGTERM");
    match send_signal(&process, libc::SIGTERM) {
        Ok(()) => {}
        Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {
            let _ = child.wait().await;
            remove_pid_file(paths)?;
            return Ok(());
        }
        Err(err) => return Err(err).with_context(|| format!("发送 SIGTERM 失败: pid={pid}")),
    }

    match time::timeout(stop_timeout, child.wait()).await {
        Ok(status) => {
            let status = status.context("等待 Mihomo 优雅退出失败")?;
            info!(pid, ?status, "Mihomo 已退出");
        }
        Err(_) => {
            warn!(pid, "Mihomo 5 秒内未退出，发送 SIGKILL");
            match send_signal(&process, libc::SIGKILL) {
                Ok(()) => {}
                Err(err) if err.raw_os_error() == Some(libc::ESRCH) => {}
                Err(err) => return Err(err).context("通过 pidfd 强制终止 Mihomo 失败"),
            }
            child.wait().await.context("等待 Mihomo 强制退出失败")?;
        }
    }

    remove_pid_file(paths)
}

/// 失败退避：连续失败达上限后转入长退避并清零计数，永不放弃。
/// 返回 true 表示收到退出信号。
async fn backoff_or_shutdown(
    shutdown: &mut watch::Receiver<bool>,
    options: &WatchdogOptions,
    failures: &mut u32,
) -> bool {
    let delay = if *failures >= options.max_failures {
        warn!(
            failures = *failures,
            backoff_secs = options.failure_backoff.as_secs(),
            "Mihomo 连续异常，转入长退避后继续重试"
        );
        *failures = 0;
        options.failure_backoff
    } else {
        options.restart_delay
    };
    wait_or_shutdown(shutdown, delay).await
}

async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        _ = time::sleep(delay) => false,
        changed = shutdown.changed() => changed.is_err() || is_shutdown(shutdown),
    }
}

fn is_shutdown(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

fn write_pid_file(paths: &Paths, pid: u32) -> Result<()> {
    fs::write(&paths.pid_file, format!("{pid}\n"))
        .with_context(|| format!("写入 Mihomo PID 文件失败: {}", paths.pid_file.display()))
}

fn read_pid_file(paths: &Paths) -> Result<Option<u32>> {
    let pid = match fs::read_to_string(&paths.pid_file) {
        Ok(pid) => pid,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("读取 Mihomo PID 文件失败: {}", paths.pid_file.display()))
        }
    };

    Ok(crate::process::parse_pid(&pid))
}

fn remove_pid_file(paths: &Paths) -> Result<()> {
    match fs::remove_file(&paths.pid_file) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err)
            .with_context(|| format!("删除 Mihomo PID 文件失败: {}", paths.pid_file.display())),
    }
}

async fn reap_stale_instance(paths: &Paths, stop_timeout: Duration) -> bool {
    crate::process::reap_stale_process("mihomo", &paths.pid_file, &paths.mihomo_bin, stop_timeout)
        .await
}

/// 等到下一次 API 健康探测时刻：启动豁免期内等到豁免期结束，之后按固定间隔。
/// health 为 None（未启用探测）时永不就绪——select! 即使分支带 if guard
/// 也会先求值表达式，这里必须自己兜住 None。
async fn health_wait(health: Option<&HealthOptions>, started_at: Instant) {
    let Some(health) = health else {
        return std::future::pending().await;
    };
    let since_start = started_at.elapsed();
    if since_start < health.grace {
        time::sleep(health.grace - since_start).await;
    } else {
        time::sleep(health.interval).await;
    }
}

async fn api_responsive(health: &HealthOptions) -> bool {
    match health.probe {
        HealthProbe::Tcp => {
            time::timeout(
                HEALTH_PROBE_TIMEOUT,
                tokio::net::TcpStream::connect(health.api_addr),
            )
            .await
            .map(|result| result.is_ok())
            .unwrap_or(false)
        }
        #[cfg(test)]
        HealthProbe::Fixed(result) => result,
    }
}

async fn updated_api_matches(
    health: &HealthOptions,
    management_secret: &str,
    expected_version: &str,
) -> bool {
    match health.probe {
        HealthProbe::Tcp => time::timeout(
            HEALTH_PROBE_TIMEOUT,
            fetch_matching_controller_version(
                health.api_addr,
                management_secret,
                expected_version,
            ),
        )
        .await
        .map(|result| result.unwrap_or(false))
        .unwrap_or(false),
        #[cfg(test)]
        HealthProbe::Fixed(result) => result,
    }
}

async fn fetch_matching_controller_version(
    api_addr: SocketAddr,
    management_secret: &str,
    expected_version: &str,
) -> std::io::Result<bool> {
    let mut stream = tokio::net::TcpStream::connect(api_addr).await?;
    let request = format!(
        "GET /version HTTP/1.1\r\nHost: {api_addr}\r\nAuthorization: Bearer {management_secret}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(1024);
    stream
        .take(UPDATE_VERSION_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut response)
        .await?;
    if response.len() > UPDATE_VERSION_RESPONSE_BYTES {
        return Ok(false);
    }
    Ok(update_version_response_matches(&response, expected_version))
}

fn update_version_response_matches(response: &[u8], expected_version: &str) -> bool {
    let Some(header_end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&response[..header_end]) else {
        return false;
    };
    if headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        != Some("200")
    {
        return false;
    }

    #[derive(serde::Deserialize)]
    struct VersionResponse {
        version: String,
    }

    let Ok(body) = serde_json::from_slice::<VersionResponse>(&response[header_end + 4..]) else {
        return false;
    };
    body.version.strip_prefix('v').unwrap_or(&body.version)
        == expected_version.strip_prefix('v').unwrap_or(expected_version)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn signal_process(pid: u32, signal: libc::c_int) -> std::io::Result<()> {
    // libc::kill 只读取 pid/signal，不涉及 Rust 引用别名；错误通过 errno 返回。
    let result = unsafe { libc::kill(pid as libc::pid_t, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use anyhow::bail;
    use std::{env, os::unix::fs::PermissionsExt};

    struct TestEnv {
        root: PathBuf,
        paths: Paths,
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn updated_controller_response_requires_authenticated_matching_version() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"meta\":true,\"version\":\"1.19.29\"}";
        assert!(update_version_response_matches(ok, "v1.19.29"));

        let unauthorized = b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"message\":\"Unauthorized\"}";
        assert!(!update_version_response_matches(unauthorized, "v1.19.29"));

        let malformed = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nnot-json";
        assert!(!update_version_response_matches(malformed, "v1.19.29"));

        let wrong_version = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"version\":\"v1.19.28\"}";
        assert!(!update_version_response_matches(wrong_version, "v1.19.29"));
    }

    #[tokio::test]
    async fn planned_update_restarts_without_counting_failure_and_preserves_previous() -> Result<()> {
        let test_env = test_env("planned-update")?;
        let starts = test_env.root.join("starts");
        write_script(
            &test_env.paths.mihomo_bin,
            &format!("#!/bin/bash\nprintf o >> {}\nexec -a \"$0\" sleep 30\n", sh_quote(&starts)),
        )?;
        let candidate = test_env.root.join("mihomo.candidate");
        write_script(
            &candidate,
            &format!("#!/bin/bash\nprintf n >> {}\nexec -a \"$0\" sleep 30\n", sh_quote(&starts)),
        )?;
        let prepared = crate::update::PreparedUpdate {
            candidate_path: candidate,
            version: "v1.19.29".into(),
            source: crate::update::UpdateSource::GitHub,
            sha256: "a".repeat(64),
        };
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (update_tx, update_rx) = mpsc::channel(1);
        let mut options = test_options(test_env.paths.clone());
        options.record_restart = |_| panic!("计划更新不得计为异常重启");
        let handle = tokio::spawn(async move {
            run_watchdog_core(&mut shutdown_rx, options, Some(update_rx)).await
        });

        wait_for_path(&starts, Duration::from_secs(10)).await?;
        update_tx.send(prepared).await.context("发送计划更新")?;
        wait_for(
            || fs::read_to_string(&starts).map(|value| value.contains('n')).unwrap_or(false),
            Duration::from_secs(10),
            "等待新版本启动",
        )
        .await?;

        assert!(!crate::update::activation_pending());
        assert!(test_env.paths.mihomo_bin.with_extension("previous").is_file());
        shutdown_tx.send(true).ok();
        time::timeout(Duration::from_secs(2), handle)
            .await
            .context("等待更新 watchdog 退出超时")?
            .context("更新 watchdog panic")??;
        Ok(())
    }

    #[tokio::test]
    async fn watchdog_keeps_retrying_after_failure_limit_instead_of_bailing() -> Result<()> {
        // 契约：连续崩溃达 max_failures 后 watchdog 转入长退避继续重试，绝不返回 Err。
        // 旧行为（bail）会连带打死整个 daemon 并残留 fail-closed 的 TPROXY 规则。
        let test_env = test_env("retry-forever")?;
        let starts = test_env.root.join("starts");
        write_script(
            &test_env.paths.mihomo_bin,
            &format!("#!/bin/sh\nprintf x >> {}\nexit 42\n", sh_quote(&starts)),
        )?;

        let (tx, mut rx) = watch::channel(false);
        let options = test_options(test_env.paths.clone());
        let handle = tokio::spawn(async move { run_watchdog_with_options(&mut rx, options).await });

        // 第 4 次启动出现 = 已越过旧的 3 次放弃点
        wait_for(
            || fs::read_to_string(&starts).map(|s| s.len() >= 4).unwrap_or(false),
            Duration::from_secs(10),
            "等待第 4 次 Mihomo 启动",
        )
        .await?;
        assert!(tx.send(true).is_ok());
        let result = time::timeout(Duration::from_secs(2), handle)
            .await
            .context("等待 watchdog 退出超时")?
            .context("watchdog 任务 panic")?;
        assert!(result.is_ok(), "watchdog 不应以 Err 退出: {result:?}");
        assert!(!test_env.paths.pid_file.exists());
        Ok(())
    }

    #[tokio::test]
    async fn watchdog_survives_unspawnable_binary() -> Result<()> {
        // 契约：二进制存在但无法执行（权限/架构错误）时 spawn 失败不得冒泡 Err，
        // watchdog 保持运行等待环境修复。
        let test_env = test_env("unspawnable")?;
        fs::write(&test_env.paths.mihomo_bin, "not a binary")?; // 无执行权限

        let (tx, mut rx) = watch::channel(false);
        let options = test_options(test_env.paths.clone());
        let handle = tokio::spawn(async move { run_watchdog_with_options(&mut rx, options).await });

        time::sleep(Duration::from_millis(300)).await;
        assert!(!handle.is_finished(), "watchdog 不应因 spawn 失败而退出");
        assert!(tx.send(true).is_ok());
        let result = time::timeout(Duration::from_secs(2), handle)
            .await
            .context("等待 watchdog 退出超时")?
            .context("watchdog 任务 panic")?;
        assert!(result.is_ok(), "watchdog 不应以 Err 退出: {result:?}");
        Ok(())
    }

    #[tokio::test]
    async fn watchdog_restarts_mihomo_when_process_alive_but_api_dead() -> Result<()> {
        // 契约：进程存活但 API 过豁免期后连续 max_failures 次不可连 → 强制重启。
        // 真机事故（2026-07-16）：蜂窝数据切换后 mihomo 监听器全部消失（活着但聋了），
        // 旧版无人重启，TPROXY 永久停在直连。
        let test_env = test_env("deaf")?;
        let starts = test_env.root.join("starts");
        write_script(
            &test_env.paths.mihomo_bin,
            &format!("#!/bin/bash\nprintf x >> {}\nexec -a \"$0\" sleep 30\n", sh_quote(&starts)),
        )?;

        let (tx, mut rx) = watch::channel(false);
        let mut options = test_options(test_env.paths.clone());
        options.health = Some(HealthOptions {
            api_addr: "127.0.0.1:9".parse()?,
            grace: Duration::from_millis(50),
            interval: Duration::from_millis(30),
            max_failures: 2,
            probe: HealthProbe::Fixed(false),
        });
        let handle = tokio::spawn(async move { run_watchdog_with_options(&mut rx, options).await });

        let deaf_before = watchdog_snapshot().deaf_restarts;
        // 第 2 次启动出现 = 聋进程被强制重启过
        wait_for(
            || fs::read_to_string(&starts).map(|s| s.len() >= 2).unwrap_or(false),
            Duration::from_secs(10),
            "等待聋 Mihomo 被强制重启",
        )
        .await?;
        // R4 可观测化契约：聋态重启必须计入 watchdog 快照（/api/status 暴露）
        assert!(
            watchdog_snapshot().deaf_restarts > deaf_before,
            "聋态重启未计入 watchdog 快照"
        );
        assert!(
            watchdog_snapshot().last_restart_unix.is_some(),
            "缺少上次重启时间戳"
        );
        assert!(tx.send(true).is_ok());
        let result = time::timeout(Duration::from_secs(2), handle)
            .await
            .context("等待 watchdog 退出超时")?
            .context("watchdog 任务 panic")?;
        assert!(result.is_ok(), "watchdog 不应以 Err 退出: {result:?}");
        Ok(())
    }

    #[tokio::test]
    async fn watchdog_leaves_healthy_mihomo_alone() -> Result<()> {
        // 契约：API 可连时健康探测绝不触发重启（防误杀）。
        let test_env = test_env("healthy")?;
        let starts = test_env.root.join("starts");
        write_script(
            &test_env.paths.mihomo_bin,
            &format!("#!/bin/bash\nprintf x >> {}\nexec -a \"$0\" sleep 30\n", sh_quote(&starts)),
        )?;

        let (tx, mut rx) = watch::channel(false);
        let mut options = test_options(test_env.paths.clone());
        options.health = Some(HealthOptions {
            api_addr: "127.0.0.1:9".parse()?,
            grace: Duration::from_millis(10),
            interval: Duration::from_millis(20),
            max_failures: 2,
            probe: HealthProbe::Fixed(true),
        });
        let handle = tokio::spawn(async move { run_watchdog_with_options(&mut rx, options).await });

        wait_for_path(&starts, Duration::from_secs(10)).await?;
        // 跨过多个探测周期，健康进程不得被重启
        time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fs::read_to_string(&starts)?, "x", "健康 Mihomo 不应被重启");
        assert!(tx.send(true).is_ok());
        time::timeout(Duration::from_secs(2), handle)
            .await
            .context("等待 watchdog 退出超时")?
            .context("watchdog 任务 panic")??;
        Ok(())
    }

    #[tokio::test]
    async fn mihomo_stdout_lands_in_log_file() -> Result<()> {
        // 契约：mihomo 子进程 stdout/stderr 落盘到 run/mihomo.log。
        // 背景：service.sh 拉起的 daemon stdout 被 Magisk 丢弃，继承式
        // Stdio::inherit() 让 mihomo 日志全部蒸发，真机排障两次抓瞎。
        let test_env = test_env("logfile")?;
        write_script(
            &test_env.paths.mihomo_bin,
            "#!/bin/bash\necho hello-from-mihomo\nexec -a \"$0\" sleep 30\n",
        )?;

        let (tx, mut rx) = watch::channel(false);
        let options = test_options(test_env.paths.clone());
        let log_path = test_env.paths.run_dir.join("mihomo.log");
        let handle = tokio::spawn(async move { run_watchdog_with_options(&mut rx, options).await });

        wait_for(
            || {
                fs::read_to_string(&log_path)
                    .map(|s| s.contains("hello-from-mihomo"))
                    .unwrap_or(false)
            },
            Duration::from_secs(10),
            "等待 mihomo.log 出现子进程输出",
        )
        .await?;
        assert!(tx.send(true).is_ok());
        time::timeout(Duration::from_secs(2), handle)
            .await
            .context("等待 watchdog 退出超时")?
            .context("watchdog 任务 panic")??;
        Ok(())
    }

    #[tokio::test]
    #[cfg(any(target_os = "android", target_os = "linux"))]
    async fn reap_cleans_pid_file_of_dead_process() -> Result<()> {
        // pid 文件指向已死进程 → 回收时清掉陈旧 pid 文件
        let test_env = test_env("reap-dead")?;
        fs::write(&test_env.paths.pid_file, "3999999\n")?; // 超出 pid_max，必然不存在
        reap_stale_instance(&test_env.paths, Duration::from_millis(100)).await;
        assert!(!test_env.paths.pid_file.exists(), "陈旧 pid 文件应被清理");
        Ok(())
    }

    #[tokio::test]
    async fn stop_child_accepts_exit_before_pidfd_open() -> Result<()> {
        let test_env = test_env("stop-race-open")?;
        let mut child = Command::new("sh").args(["-c", "exit 0"]).spawn()?;
        let pid = child.id().context("测试子进程缺少 PID")?;
        fs::write(&test_env.paths.pid_file, format!("{pid}\n"))?;
        time::sleep(Duration::from_millis(50)).await;

        stop_child_with_opener(
            &mut child,
            &test_env.paths,
            Duration::from_millis(100),
            |_, _| Ok(None::<()>),
            |_, _| panic!("已退出进程不得发送信号"),
        )
        .await?;

        assert!(!test_env.paths.pid_file.exists(), "正常退出后应清理 PID 文件");
        Ok(())
    }

    #[tokio::test]
    async fn stop_child_accepts_esrch_after_term_timeout() -> Result<()> {
        let test_env = test_env("stop-race-kill")?;
        let mut child = Command::new("sh").args(["-c", "sleep 0.05"]).spawn()?;
        let pid = child.id().context("测试子进程缺少 PID")?;
        fs::write(&test_env.paths.pid_file, format!("{pid}\n"))?;

        stop_child_with_opener(
            &mut child,
            &test_env.paths,
            Duration::ZERO,
            |_, _| Ok(Some(())),
            |_, signal| {
                if signal == libc::SIGTERM {
                    Ok(())
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ESRCH))
                }
            },
        )
        .await?;

        assert!(!test_env.paths.pid_file.exists(), "竞态退出后应清理 PID 文件");
        Ok(())
    }

    #[tokio::test]
    async fn watchdog_stops_running_mihomo_with_sigterm() -> Result<()> {
        let test_env = test_env("sigterm")?;
        let events = test_env.root.join("events");
        write_script(
            &test_env.paths.mihomo_bin,
            &format!(
                "#!/bin/bash\nexec -a \"$0\" bash -c 'printf start >> \"$1\"; trap \"printf term >> \\\"$1\\\"; exit 0\" TERM; while :; do sleep 0.05; done' _ {}\n",
                sh_quote(&events)
            ),
        )?;

        let (tx, mut rx) = watch::channel(false);
        let options = test_options(test_env.paths.clone());
        let handle = tokio::spawn(async move { run_watchdog_with_options(&mut rx, options).await });

        wait_for_path(&test_env.paths.pid_file, Duration::from_secs(10)).await?;
        // 文件在重定向 open 时就会出现，早于 shell builtin 写入完成；只等路径会
        // 偶发过早发送 TERM，导致尚未写入的 start 事件丢失。
        wait_for(
            || {
                fs::read_to_string(&events)
                    .map(|value| value.contains("start"))
                    .unwrap_or(false)
            },
            Duration::from_secs(10),
            "等待 Mihomo 测试进程完成启动事件写入",
        )
        .await?;
        assert!(tx.send(true).is_ok());
        time::timeout(Duration::from_secs(2), handle)
            .await
            .context("等待 watchdog 测试任务超时")?
            .context("watchdog 测试任务 panic")??;

        let events = fs::read_to_string(events)?;
        assert!(events.contains("start"));
        assert!(events.contains("term"));
        assert!(!test_env.paths.pid_file.exists());
        Ok(())
    }

    fn test_env(name: &str) -> Result<TestEnv> {
        let unique = format!(
            "f50mgr-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let root = env::temp_dir().join(unique);
        let paths = Paths {
            mihomo_bin: root.join("bin/mihomo"),
            clash_dir: root.join("config/clash"),
            config_file: root.join("config/clash/config.yaml"),
            run_dir: root.join("run"),
            pid_file: root.join("run/mihomo.pid"),
        };

        fs::create_dir_all(paths.mihomo_bin.parent().context("缺少 bin 目录")?)?;
        fs::create_dir_all(&paths.clash_dir)?;
        fs::create_dir_all(&paths.run_dir)?;
        fs::write(&paths.config_file, "mixed-port: 14190\n")?;

        Ok(TestEnv { root, paths })
    }

    fn test_options(paths: Paths) -> WatchdogOptions {
        WatchdogOptions {
            paths,
            management_secret: "test-management-secret".to_owned(),
            restart_delay: Duration::from_millis(20),
            stop_timeout: Duration::from_secs(1),
            stable_run: Duration::from_secs(60),
            max_failures: 3,
            failure_backoff: Duration::from_millis(40),
            health: None,
            disable_rules: || Ok(()),
            record_restart,
        }
    }

    fn write_script(path: &Path, content: &str) -> Result<()> {
        fs::write(path, content)?;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }

    async fn wait_for_path(path: &Path, timeout: Duration) -> Result<()> {
        let display = path.display().to_string();
        wait_for(|| path.exists(), timeout, &format!("等待路径出现: {display}")).await
    }

    #[test]
    fn stop_running_ignores_pid_reused_by_unrelated_process() -> Result<()> {
        let test_env = test_env("pid-reuse")?;
        let mut unrelated = std::process::Command::new("sleep").arg("30").spawn()?;
        fs::write(&test_env.paths.pid_file, format!("{}\n", unrelated.id()))?;

        stop_running_with_opener(
            &test_env.paths,
            |_, _| Ok(None::<()>),
            |_, _| panic!("身份不匹配时不得发送信号"),
        )?;

        assert!(
            unrelated.try_wait()?.is_none(),
            "陈旧 PID 被复用时不得终止无关进程"
        );
        assert!(!test_env.paths.pid_file.exists(), "陈旧 PID 文件应被清理");
        unrelated.kill()?;
        unrelated.wait()?;
        Ok(())
    }

    async fn wait_for(
        mut condition: impl FnMut() -> bool,
        timeout: Duration,
        what: &str,
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if condition() {
                return Ok(());
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        bail!("超时: {what}");
    }

    fn sh_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }

    #[test]
    fn concurrent_toggles_keep_both_sections() -> Result<()> {
        // #11：Mihomo / EasyTier 开关并发写同一个 f50mgr.toml，不得互相覆盖
        use std::sync::{Arc, Barrier};

        let root = env::temp_dir().join(format!("f50mgr-toggle-race-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let path = root.join("f50mgr.toml");
        let path = path.to_str().context("临时路径不是 UTF-8")?.to_owned();
        for round in 0..200 {
            fs::write(
                &path,
                "[mihomo]\nauto_start = false\n\n[easytier]\nenabled = false\n",
            )?;
            let barrier = Arc::new(Barrier::new(2));
            let handles: Vec<_> = [("mihomo", "auto_start"), ("easytier", "enabled")]
                .into_iter()
                .map(|(section, key)| {
                    let barrier = Arc::clone(&barrier);
                    let path = path.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        update_bool_config(&path, section, key, true)
                    })
                })
                .collect();
            for handle in handles {
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("并发切换线程 panic"))??;
            }
            let after = fs::read_to_string(&path)?;
            if !after.contains("[mihomo]\nauto_start = true")
                || !after.contains("[easytier]\nenabled = true")
            {
                let _ = fs::remove_dir_all(&root);
                bail!("第 {round} 轮并发切换后丢失了另一边的开关:\n{after}");
            }
        }
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn toggle_keeps_config_file_mode() -> Result<()> {
        let root = env::temp_dir().join(format!("f50mgr-toggle-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let path = root.join("f50mgr.toml");
        fs::write(&path, "[mihomo]\nauto_start = true\n")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let path_str = path.to_str().context("临时路径不是 UTF-8")?;

        update_bool_config(path_str, "easytier", "enabled", true)?;

        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o644);
        assert_eq!(
            fs::read_to_string(&path)?,
            "[mihomo]\nauto_start = true\n\n[easytier]\nenabled = true\n"
        );
        fs::remove_dir_all(&root)?;
        Ok(())
    }
}
