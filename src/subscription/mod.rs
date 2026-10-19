pub mod easytier;

use std::{
    fs,
    io::{ErrorKind, Write},
    net::IpAddr,
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde_yml::{Mapping, Value};
use tracing::warn;

const CONFIG_FILE: &str = "/data/adb/f50mgr/config/clash/config.yaml";
const SECRETS_FILE: &str = "/data/adb/f50mgr/config/secrets.toml";
pub const MAX_IMPORT_BYTES: usize = 2 * 1024 * 1024;
static CONFIG_WRITE_MUTEX: Mutex<()> = Mutex::new(());
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SUBSCRIPTION_BYTES: u64 = MAX_IMPORT_BYTES as u64;
const LAN_BIND_IP: &str = "192.168.0.1";
const HTTP_PORT: u16 = 14191;
const SOCKS_PORT: u16 = 14192;
const REDIR_PORT: u16 = 14194;
const MIXED_PORT: u16 = 14190;
const TPROXY_PORT: u16 = 14198;
const DNS_LISTEN: &str = "192.168.0.1:14153";
const EXTERNAL_CONTROLLER: &str = "192.168.0.1:14193";
/// 本地 MetaCubeXD 目录，由 Magisk 模块安装时铺设；Mihomo 在 external-controller 的 /ui/ 提供。
/// 必须放在 mihomo 工作目录（-d clash 目录）下，否则 mihomo 以 "not subpath of home directory" 拒绝。
const EXTERNAL_UI_DIR: &str = "/data/adb/f50mgr/config/clash/dashboard";
const FALLBACK_BOOTSTRAP_DNS: [&str; 2] = ["43.239.172.1", "43.239.172.2"];
const BOOTSTRAP_DNS_PROPS: [&str; 4] = [
    "vendor.net.sipa_eth0.dns1",
    "vendor.net.sipa_eth0.dns2",
    "net.dns1",
    "net.dns2",
];
const DIRECT_CN_POLICY_KEYS: [&str; 6] = [
    "geosite:cn",
    "geosite:geolocation-cn",
    "+.alicdn.com",
    "+.qpic.cn",
    "+.bdstatic.com",
    "+.gtimg.cn",
];
const DIRECT_BOOTSTRAP_POLICY_KEYS: [&str; 5] = [
    "cc.0x99.org",
    "std.hhh.sd",
    "+.a1.sd",
    "+.vcore.top",
    "+.duckdns.org",
];

pub fn render_from_file(input: &Path, output: &Path) -> Result<()> {
    let subscription = fs::read_to_string(input)
        .with_context(|| format!("读取订阅配置失败: {}", input.display()))?;
    with_config_write_lock(output, || {
        write_rendered_config_unlocked(&subscription, output)
    })
}

pub fn update_from_url(url: &str, output: &Path) -> Result<()> {
    let subscription = download_subscription(url)?;
    with_config_write_lock(output, || {
        write_rendered_config_unlocked(&subscription, output)
    })
}

pub fn import_from_url(url: &str) -> Result<()> {
    let subscription = download_subscription(url)?;
    let output = default_output();
    with_config_write_lock(&output, || {
        write_rendered_config_unlocked(&subscription, &output)?;
        write_subscription_secret_unlocked(url)
    })
}

pub fn import_from_yaml(subscription: &str) -> Result<()> {
    let output = default_output();
    with_config_write_lock(&output, || {
        write_rendered_config_unlocked(subscription, &output)
    })
}

pub fn read_subscription_url() -> Result<Option<String>> {
    match fs::read_to_string(SECRETS_FILE) {
        Ok(content) => Ok(parse_subscription_url(&content)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("读取订阅配置失败: {SECRETS_FILE}")),
    }
}

fn parse_subscription_url(content: &str) -> Option<String> {
    let mut in_subscription = false;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_subscription = line == "[subscription]";
            continue;
        }
        if !in_subscription {
            continue;
        }
        let Some((k, value)) = line.split_once('=') else {
            continue;
        };
        if k.trim() == "url" {
            let v = value.trim().trim_matches('"');
            return if v.is_empty() { None } else { Some(v.to_owned()) };
        }
    }
    None
}

#[cfg(test)]
pub fn render_config(subscription: &str) -> Result<String> {
    render_config_inner(subscription, None)
}

fn render_config_with_controller_secret(subscription: &str, secret: &str) -> Result<String> {
    render_config_inner(subscription, Some(secret))
}

fn render_config_inner(subscription: &str, controller_secret: Option<&str>) -> Result<String> {
    // Step 1: 兼容 base64 编码的订阅（部分机场默认提供）
    let normalized = decode_if_base64(subscription);
    // Step 2: 解析 YAML
    let mut root: Value = serde_yml::from_str(&normalized).context("解析订阅 YAML 失败")?;
    let root_map = root
        .as_mapping_mut()
        .context("订阅 YAML 顶层必须是 mapping")?;
    // Step 3: 警告外部 providers（F50 启动期可能拉不到）—— 仅 import 路径警告，避免每次启动刷屏
    warn_external_providers(root_map);
    // Step 4: 注入 F50 必需配置（含 sanitize_dangerous_fields）
    apply_f50_required_fields(root_map)?;
    if let Some(secret) = controller_secret {
        set(root_map, "secret", secret)?;
    }

    serde_yml::to_string(&root).context("序列化 Mihomo 配置失败")
}

/// 检测订阅是否是 base64 编码（trim 后只含 base64 字符且不含 YAML 标志符），
/// 是则解码后返回，否则返回原文。无法解码时也返回原文（让后续 YAML 解析自行报错）。
fn decode_if_base64(content: &str) -> String {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return content.to_owned();
    }
    // YAML 文档典型含 ":" / "-" 行首 / 换行键值，base64 不会出现
    if trimmed.contains(':') || trimmed.contains("---") || trimmed.contains("# ") {
        return content.to_owned();
    }
    // base64 字符集 + 末尾可能 = 填充。容忍内部空白（机场常带换行）
    let cleaned: String = trimmed
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.is_empty()
        || !cleaned
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '_' || c == '-')
    {
        return content.to_owned();
    }
    // 同时尝试 standard 与 url-safe 两种 alphabet
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
    ];
    for engine in engines {
        if let Ok(bytes) = engine.decode(&cleaned) {
            if let Ok(text) = String::from_utf8(bytes) {
                if text.contains(':') || text.contains("\n") {
                    return text;
                }
            }
        }
    }
    content.to_owned()
}

fn warn_external_providers(root: &Mapping) {
    for (field, kind) in [("proxy-providers", "代理"), ("rule-providers", "规则")] {
        if matches!(root.get(key(field)), Some(Value::Mapping(_))) {
            warn!(
                field,
                "订阅含 {kind} provider 远程拉取配置；F50 启动早期网络可能未就绪，mihomo 加载若失败请检查"
            );
        }
    }
}

/// 移除已知与 F50 TPROXY 路径冲突的字段。
/// 当前规则：删除整个 `tun` 段——任何 tun.enable=true 都会与 mangle TPROXY 抢流量。
fn sanitize_dangerous_fields(root: &mut Mapping) {
    if root.remove(key("tun")).is_some() {
        warn!("订阅含 tun 段，已移除（与 F50 TPROXY 冲突）");
    }
}

pub fn default_output() -> PathBuf {
    PathBuf::from(CONFIG_FILE)
}

pub(crate) fn enforce_runtime_defaults_with_secret(
    config_file: &Path,
    secret: &str,
) -> Result<bool> {
    with_config_write_lock(config_file, || {
        enforce_runtime_defaults_unlocked(config_file, secret)
    })
}

fn enforce_runtime_defaults_unlocked(config_file: &Path, secret: &str) -> Result<bool> {
    let current = fs::read_to_string(config_file)
        .with_context(|| format!("读取 Mihomo 配置失败: {}", config_file.display()))?;
    let mut root: Value = serde_yml::from_str(&current).context("解析 Mihomo YAML 失败")?;
    let root_map = root
        .as_mapping_mut()
        .context("Mihomo YAML 顶层必须是 mapping")?;

    apply_f50_required_fields(root_map)?;
    set(root_map, "secret", secret)?;

    let rendered = serde_yml::to_string(&root).context("序列化 Mihomo 配置失败")?;
    if rendered == current {
        return Ok(false);
    }

    write_atomic(config_file, rendered.as_bytes())?;
    Ok(true)
}

fn write_rendered_config_unlocked(subscription: &str, output: &Path) -> Result<()> {
    let secret = crate::web::auth_store::read_management_key()
        .context("读取 Mihomo Controller 管理密钥失败")?;
    let rendered = render_config_with_controller_secret(subscription, &secret)?;
    write_atomic(output, rendered.as_bytes())
}

fn write_subscription_secret_unlocked(url: &str) -> Result<()> {
    let new_section = format!("[subscription]\nurl = \"{}\"\n", escape_toml_string(url));
    let output = Path::new(SECRETS_FILE);
    let parent = output
        .parent()
        .with_context(|| format!("订阅密钥路径缺少父目录: {}", output.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("创建订阅密钥目录失败: {}", parent.display()))?;

    let original = match fs::read_to_string(output) {
        Ok(s) => s,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("读取既有订阅密钥失败: {}", output.display()))
        }
    };
    let merged = replace_or_append_section(&original, "subscription", &new_section);

    write_atomic(output, merged.as_bytes())
}

/// 替换 `[<section>]` 段为 `new_section`，保留其它段；若无该段则追加。
/// 与 easytier::replace_or_append_easytier_section 的语义一致，但通用化以避免循环依赖。
fn replace_or_append_section(original: &str, section: &str, new_section: &str) -> String {
    let target = format!("[{section}]");
    let lines: Vec<&str> = original.lines().collect();
    let mut start: Option<usize> = None;
    let mut end: usize = lines.len();

    for (i, raw) in lines.iter().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if start.is_none() {
            if line == target {
                start = Some(i);
            }
        } else if line.starts_with('[') && line.ends_with(']') && line != target {
            end = i;
            break;
        }
    }

    let mut out = String::new();
    if let Some(s_idx) = start {
        for line in &lines[..s_idx] {
            out.push_str(line);
            out.push('\n');
        }
        while out.ends_with("\n\n") {
            out.pop();
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(new_section);
        if end < lines.len() {
            out.push('\n');
            for line in &lines[end..] {
                out.push_str(line);
                out.push('\n');
            }
        }
    } else {
        out.push_str(original);
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(new_section);
    }
    out
}

fn escape_toml_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn download_subscription(url: &str) -> Result<String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        bail!("订阅 URL 必须使用 http:// 或 https://");
    }

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(DOWNLOAD_TIMEOUT))
        .build();
    let agent: ureq::Agent = config.into();

    agent
        .get(url)
        .call()
        .with_context(|| format!("下载订阅失败: {url}"))?
        .body_mut()
        .with_config()
        .limit(MAX_SUBSCRIPTION_BYTES)
        .read_to_string()
        .context("读取订阅响应失败")
}

fn apply_f50_required_fields(root_map: &mut Mapping) -> Result<()> {
    // 移除危险字段（tun 等）—— 每次都跑，包括 enforce_runtime_defaults 路径
    sanitize_dangerous_fields(root_map);
    set(root_map, "mixed-port", MIXED_PORT)?;
    set(root_map, "port", HTTP_PORT)?;
    set(root_map, "socks-port", SOCKS_PORT)?;
    set(root_map, "redir-port", REDIR_PORT)?;
    set(root_map, "tproxy-port", TPROXY_PORT)?;
    set(root_map, "allow-lan", true)?;
    set(root_map, "bind-address", LAN_BIND_IP)?;
    set(root_map, "mode", "rule")?;
    // 日志落盘 run/mihomo.log 后必须限量：info 级逐连接刷日志，单次运行无法轮转
    set(root_map, "log-level", "warning")?;
    set(root_map, "external-controller", EXTERNAL_CONTROLLER)?;
    set(root_map, "external-ui", EXTERNAL_UI_DIR)?;
    merge_dns(root_map)?;
    merge_sniffer(root_map)
}

fn merge_dns(root: &mut Mapping) -> Result<()> {
    let dns_key = key("dns");
    if !matches!(root.get(&dns_key), Some(Value::Mapping(_))) {
        root.insert(dns_key.clone(), Value::Mapping(Mapping::new()));
    }

    let dns = root
        .get_mut(&dns_key)
        .and_then(Value::as_mapping_mut)
        .context("dns 字段必须是 mapping")?;
    set(dns, "enable", true)?;
    set(dns, "listen", DNS_LISTEN)?;
    set(dns, "cache-algorithm", "arc")?;
    set(dns, "enhanced-mode", "fake-ip")?;
    set(dns, "fake-ip-range", "198.18.0.1/16")?;
    ensure_seq_contains(
        dns,
        "fake-ip-filter",
        &["*.lan", "localhost.ptlogin2.qq.com"],
    )?;
    let bootstrap_dns = bootstrap_dns();
    set_sequence(dns, "default-nameserver", &bootstrap_dns)?;
    set_sequence(dns, "proxy-server-nameserver", &bootstrap_dns)?;
    merge_nameserver_policy(dns, &bootstrap_dns)?;
    Ok(())
}

fn merge_sniffer(root: &mut Mapping) -> Result<()> {
    let sniffer = ensure_mapping(root, "sniffer")?;
    set(sniffer, "enable", true)?;
    set(sniffer, "force-dns-mapping", true)?;
    set(sniffer, "parse-pure-ip", true)?;
    set(sniffer, "override-destination", true)?;

    let sniff = ensure_mapping(sniffer, "sniff")?;
    let http = ensure_mapping(sniff, "HTTP")?;
    set(http, "override-destination", true)?;
    Ok(())
}

fn ensure_mapping<'a>(map: &'a mut Mapping, name: &str) -> Result<&'a mut Mapping> {
    let item_key = key(name);
    if !matches!(map.get(&item_key), Some(Value::Mapping(_))) {
        map.insert(item_key.clone(), Value::Mapping(Mapping::new()));
    }
    map.get_mut(&item_key)
        .and_then(Value::as_mapping_mut)
        .with_context(|| format!("{name} 字段必须是 mapping"))
}

fn set<T: serde::Serialize>(map: &mut Mapping, name: &str, value: T) -> Result<()> {
    map.insert(key(name), serde_yml::to_value(value)?);
    Ok(())
}

fn ensure_seq_contains(map: &mut Mapping, name: &str, values: &[&str]) -> Result<()> {
    let item_key = key(name);
    if !matches!(map.get(&item_key), Some(Value::Sequence(_))) {
        let mut sequence = Vec::with_capacity(values.len());
        for value in values {
            sequence.push(serde_yml::to_value(value)?);
        }
        map.insert(item_key, Value::Sequence(sequence));
        return Ok(());
    }

    let sequence = map
        .get_mut(&item_key)
        .and_then(Value::as_sequence_mut)
        .context("字段必须是 sequence")?;
    for value in values {
        let required = serde_yml::to_value(value)?;
        if !sequence.contains(&required) {
            sequence.push(required);
        }
    }
    Ok(())
}

fn set_sequence(map: &mut Mapping, name: &str, values: &[String]) -> Result<()> {
    let sequence = values
        .iter()
        .map(serde_yml::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    map.insert(key(name), Value::Sequence(sequence));
    Ok(())
}

fn merge_nameserver_policy(dns: &mut Mapping, bootstrap_dns: &[String]) -> Result<()> {
    let policy_key = key("nameserver-policy");
    if !matches!(dns.get(&policy_key), Some(Value::Mapping(_))) {
        dns.insert(policy_key.clone(), Value::Mapping(Mapping::new()));
    }

    let policy = dns
        .get_mut(&policy_key)
        .and_then(Value::as_mapping_mut)
        .context("nameserver-policy 字段必须是 mapping")?;

    let bootstrap_policy = values_from(bootstrap_dns)?;

    for name in DIRECT_CN_POLICY_KEYS {
        policy.insert(key(name), Value::Sequence(bootstrap_policy.clone()));
    }
    for name in DIRECT_BOOTSTRAP_POLICY_KEYS {
        policy.insert(key(name), Value::Sequence(bootstrap_policy.clone()));
    }
    Ok(())
}

fn bootstrap_dns() -> Vec<String> {
    let mut servers = Vec::new();
    for prop in BOOTSTRAP_DNS_PROPS {
        let Some(value) = getprop(prop) else {
            continue;
        };
        if value.parse::<IpAddr>().is_ok() && !servers.contains(&value) {
            servers.push(value);
        }
    }
    if servers.is_empty() {
        FALLBACK_BOOTSTRAP_DNS
            .iter()
            .map(|server| (*server).to_owned())
            .collect()
    } else {
        servers
    }
}

fn getprop(name: &str) -> Option<String> {
    let output = Command::new("getprop").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn values_from(values: &[String]) -> Result<Vec<Value>> {
    values
        .iter()
        .map(serde_yml::to_value)
        .collect::<Result<Vec<_>, _>>()
        .context("序列化 DNS 配置失败")
}

fn key(name: &str) -> Value {
    Value::String(name.to_owned())
}

pub(crate) fn with_config_write_lock<T>(
    output: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let parent = output
        .parent()
        .with_context(|| format!("配置路径缺少父目录: {}", output.display()))?;
    let config_root = match parent.file_name().and_then(|name| name.to_str()) {
        Some("clash" | "easytier") => parent
            .parent()
            .with_context(|| format!("配置子目录缺少根目录: {}", parent.display()))?,
        _ => parent,
    };
    let lock_path = config_root.join(".write.lock");
    fs::create_dir_all(parent)
        .with_context(|| format!("创建配置写锁目录失败: {}", parent.display()))?;
    with_file_lock(&lock_path, action)
}

fn with_file_lock<T>(lock_path: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let _process_guard = CONFIG_WRITE_MUTEX
        .lock()
        .map_err(|_| anyhow!("配置写锁已损坏"))?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock_path)
        .with_context(|| format!("打开配置写锁失败: {}", lock_path.display()))?;
    if !lock
        .metadata()
        .with_context(|| format!("读取配置写锁元数据失败: {}", lock_path.display()))?
        .file_type()
        .is_file()
    {
        bail!("配置写锁不是普通文件: {}", lock_path.display());
    }
    lock.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("设置配置写锁权限失败: {}", lock_path.display()))?;
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("获取配置写锁失败: {}", lock_path.display()));
    }
    action()
}

pub(crate) fn write_atomic(output: &Path, content: &[u8]) -> Result<()> {
    let parent = output
        .parent()
        .with_context(|| format!("输出路径缺少父目录: {}", output.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("创建配置目录失败: {}", parent.display()))?;

    let file_name = output
        .file_name()
        .with_context(|| format!("输出路径缺少文件名: {}", output.display()))?;
    let (tmp, mut file) = (0..64)
        .find_map(|_| {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let candidate = output.with_file_name(format!(
                ".{}.{}.{}.tmp",
                file_name.to_string_lossy(),
                std::process::id(),
                sequence
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&candidate)
            {
                Ok(file) => Some(Ok((candidate, file))),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => None,
                Err(err) => Some(Err(err).with_context(|| {
                    format!("创建临时配置失败: {}", candidate.display())
                })),
            }
        })
        .transpose()?
        .context("连续 64 个临时配置文件名冲突")?;

    let result = (|| -> Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("设置临时配置权限失败: {}", tmp.display()))?;
        file.write_all(content)
            .with_context(|| format!("写入临时配置失败: {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("同步临时配置失败: {}", tmp.display()))?;
        drop(file);
        fs::rename(&tmp, output).with_context(|| {
            format!(
                "替换配置文件失败: {} -> {}",
                tmp.display(),
                output.display()
            )
        })?;
        fs::File::open(parent)
            .with_context(|| format!("打开配置目录失败: {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("同步配置目录失败: {}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_config_preserves_proxies_and_overrides_f50_required_fields() -> Result<()> {
        let rendered = render_config(
            r#"
mixed-port: 9999
external-controller: 0.0.0.0:9090
proxies:
  - name: HK-1
    type: ss
    server: 127.0.0.1
    port: 8388
proxy-groups:
  - name: Proxy
    type: select
    proxies: [HK-1]
rules:
  - MATCH,Proxy
dns:
  enable: false
  nameserver:
    - https://example.com/dns-query#Proxies
  nameserver-policy:
    cc.0x99.org:
      - 223.5.5.5
    geosite:cn:
      - 119.29.29.29
  fake-ip-filter:
    - existing.local
sniffer:
  enable: false
  sniff:
    HTTP:
      override-destination: false
"#,
        )?;
        let config: Value = serde_yml::from_str(&rendered)?;
        let root = config.as_mapping().context("渲染结果顶层不是 mapping")?;
        let dns = root
            .get(key("dns"))
            .and_then(Value::as_mapping)
            .context("缺少 dns mapping")?;

        assert_eq!(
            root.get(key("mixed-port")),
            Some(&serde_yml::to_value(14190_u16)?)
        );
        assert_eq!(
            root.get(key("port")),
            Some(&serde_yml::to_value(14191_u16)?)
        );
        assert_eq!(
            root.get(key("socks-port")),
            Some(&serde_yml::to_value(14192_u16)?)
        );
        assert_eq!(
            root.get(key("redir-port")),
            Some(&serde_yml::to_value(14194_u16)?)
        );
        assert_eq!(
            root.get(key("tproxy-port")),
            Some(&serde_yml::to_value(14198_u16)?)
        );
        assert_eq!(
            root.get(key("external-controller")),
            Some(&serde_yml::to_value("192.168.0.1:14193")?)
        );
        assert_eq!(
            root.get(key("bind-address")),
            Some(&serde_yml::to_value("192.168.0.1")?)
        );
        assert!(root.contains_key(key("proxies")));
        assert_eq!(dns.get(key("enable")), Some(&serde_yml::to_value(true)?));
        assert_eq!(
            dns.get(key("listen")),
            Some(&serde_yml::to_value("192.168.0.1:14153")?)
        );
        let fake_ip_filter = dns
            .get(key("fake-ip-filter"))
            .and_then(Value::as_sequence)
            .context("缺少 fake-ip-filter")?;
        assert!(fake_ip_filter.contains(&serde_yml::to_value("existing.local")?));
        assert!(fake_ip_filter.contains(&serde_yml::to_value("*.lan")?));

        assert_eq!(
            dns.get(key("default-nameserver")),
            Some(&serde_yml::to_value(["43.239.172.1", "43.239.172.2"])?)
        );
        assert_eq!(
            dns.get(key("proxy-server-nameserver")),
            Some(&serde_yml::to_value(["43.239.172.1", "43.239.172.2"])?)
        );

        let policy = dns
            .get(key("nameserver-policy"))
            .and_then(Value::as_mapping)
            .context("缺少 nameserver-policy")?;
        assert_eq!(
            policy.get(key("geosite:cn")),
            Some(&serde_yml::to_value(["43.239.172.1", "43.239.172.2"])?)
        );
        assert_eq!(
            policy.get(key("cc.0x99.org")),
            Some(&serde_yml::to_value(["43.239.172.1", "43.239.172.2"])?)
        );
        let sniffer = root
            .get(key("sniffer"))
            .and_then(Value::as_mapping)
            .context("缺少 sniffer mapping")?;
        assert_eq!(
            sniffer.get(key("enable")),
            Some(&serde_yml::to_value(true)?)
        );
        assert_eq!(
            sniffer.get(key("force-dns-mapping")),
            Some(&serde_yml::to_value(true)?)
        );
        assert_eq!(
            sniffer.get(key("parse-pure-ip")),
            Some(&serde_yml::to_value(true)?)
        );
        assert_eq!(
            sniffer.get(key("override-destination")),
            Some(&serde_yml::to_value(true)?)
        );
        let http = sniffer
            .get(key("sniff"))
            .and_then(Value::as_mapping)
            .and_then(|sniff| sniff.get(key("HTTP")))
            .and_then(Value::as_mapping)
            .context("缺少 HTTP sniffer mapping")?;
        assert_eq!(
            http.get(key("override-destination")),
            Some(&serde_yml::to_value(true)?)
        );
        Ok(())
    }

    #[test]
    fn production_render_injects_management_secret_into_mihomo_controller() -> Result<()> {
        let rendered = render_config_with_controller_secret(
            "proxies: []\nproxy-groups: []\nrules: []\n",
            "test-management-secret",
        )?;
        let config: Value = serde_yml::from_str(&rendered)?;
        let root = config.as_mapping().context("渲染结果顶层不是 mapping")?;

        assert_eq!(
            root.get(key("secret")),
            Some(&serde_yml::to_value("test-management-secret")?)
        );
        Ok(())
    }

    #[test]
    fn render_config_caps_log_level_to_bound_disk_usage() -> Result<()> {
        // 契约：强制 log-level=warning。mihomo 默认 info 逐连接刷日志，
        // 落盘 run/mihomo.log 后单次运行期间无法轮转，必须从源头限量。
        let rendered = render_config("proxies: []\nrules: []\nlog-level: debug\n")?;
        let config: Value = serde_yml::from_str(&rendered)?;
        let root = config.as_mapping().context("顶层不是 mapping")?;
        assert_eq!(
            root.get(key("log-level")),
            Some(&serde_yml::to_value("warning")?)
        );
        Ok(())
    }

    #[test]
    fn robustness_enforce_runtime_defaults_also_strips_tun() -> Result<()> {
        // 确保 enforce_runtime_defaults（每次 mihomo 启动跑）也走 sanitize 路径
        // 之前 sanitize 只挂在 render_config 上，导致旧 config.yaml 里的 tun 段不会被清
        let dir = std::env::temp_dir().join(format!("f50mgr-tun-test-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let path = dir.join("config.yaml");
        fs::write(
            &path,
            "tun:\n  enable: true\n  stack: system\nproxies: []\nrules: []\n",
        )?;
        enforce_runtime_defaults_with_secret(&path, "test-management-secret")?;
        let after = fs::read_to_string(&path)?;
        let cfg: Value = serde_yml::from_str(&after)?;
        assert!(
            cfg.as_mapping().unwrap().get(key("tun")).is_none(),
            "enforce_runtime_defaults 必须移除 tun 段，实际:\n{after}"
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn atomic_config_replace_uses_unique_private_temp_file() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("f50mgr-atomic-test-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let output = dir.join("config.yaml");
        let tmp = output.with_extension("yaml.tmp");
        fs::write(&tmp, b"stale")?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o666))?;

        write_atomic(&output, b"proxies: []\n")?;

        assert_eq!(fs::read(&output)?, b"proxies: []\n");
        assert_eq!(
            fs::metadata(&output)?.permissions().mode() & 0o777,
            0o600,
            "代理配置可能包含凭据，原子替换后必须保持私有权限"
        );
        assert_eq!(
            fs::read(&tmp)?,
            b"stale",
            "不得复用或改写其他请求遗留的固定临时文件"
        );
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn config_file_lock_rejects_symbolic_link() -> Result<()> {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("f50mgr-lock-link-test-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let target = dir.join("target");
        let lock_path = dir.join("config.lock");
        fs::write(&target, b"do-not-touch")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))?;
        symlink(&target, &lock_path)?;

        let result = with_file_lock(&lock_path, || Ok(()));

        assert!(result.is_err(), "配置写锁不得跟随符号链接");
        assert_eq!(
            fs::metadata(&target)?.permissions().mode() & 0o777,
            0o644,
            "拒绝符号链接时不得修改其目标权限"
        );
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn config_file_lock_serializes_across_processes() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("f50mgr-lock-test-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let lock_path = dir.join("config.lock");
        let start_path = dir.join("start");
        let trace_path = dir.join("trace");
        let executable = std::env::current_exe()?;
        let mut children = Vec::new();
        let mut ready_paths = Vec::new();

        for index in 0..2 {
            let ready_path = dir.join(format!("ready-{index}"));
            let child = std::process::Command::new(&executable)
                .args([
                    "--exact",
                    "subscription::tests::config_file_lock_child_process",
                    "--nocapture",
                ])
                .env("F50MGR_TEST_LOCK_PATH", &lock_path)
                .env("F50MGR_TEST_START_PATH", &start_path)
                .env("F50MGR_TEST_TRACE_PATH", &trace_path)
                .env("F50MGR_TEST_READY_PATH", &ready_path)
                .spawn()?;
            children.push(child);
            ready_paths.push(ready_path);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while ready_paths.iter().any(|path| !path.exists()) {
            if std::time::Instant::now() >= deadline {
                bail!("等待跨进程锁测试子进程就绪超时");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        fs::write(&start_path, b"go")?;
        for mut child in children {
            assert!(child.wait()?.success(), "跨进程锁测试子进程失败");
        }

        assert_eq!(fs::read(&trace_path)?, b"EXEX", "跨进程临界区不得重叠");
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn config_file_lock_child_process() -> Result<()> {
        let Some(lock_path) = std::env::var_os("F50MGR_TEST_LOCK_PATH") else {
            return Ok(());
        };
        let start_path =
            PathBuf::from(std::env::var_os("F50MGR_TEST_START_PATH").context("缺少 start path")?);
        let trace_path =
            PathBuf::from(std::env::var_os("F50MGR_TEST_TRACE_PATH").context("缺少 trace path")?);
        let ready_path =
            PathBuf::from(std::env::var_os("F50MGR_TEST_READY_PATH").context("缺少 ready path")?);
        fs::write(&ready_path, b"ready")?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !start_path.exists() {
            if std::time::Instant::now() >= deadline {
                bail!("等待跨进程锁测试开始信号超时");
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        with_file_lock(Path::new(&lock_path), || {
            let mut trace = fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&trace_path)?;
            trace.write_all(b"E")?;
            trace.sync_all()?;
            std::thread::sleep(Duration::from_millis(150));
            trace.write_all(b"X")?;
            trace.sync_all()?;
            Ok(())
        })
    }

    #[test]
    fn robustness_strips_tun_section_to_avoid_tproxy_conflict() -> Result<()> {
        let rendered = render_config("tun:\n  enable: true\n  stack: system\nproxies: []\nrules: []\n")?;
        let cfg: Value = serde_yml::from_str(&rendered)?;
        assert!(
            cfg.as_mapping().unwrap().get(key("tun")).is_none(),
            "tun 段必须被移除，避免与 F50 TPROXY 冲突"
        );
        Ok(())
    }

    #[test]
    fn robustness_decodes_base64_subscription() -> Result<()> {
        // 模拟某些机场返回的 base64 编码订阅（编码后只剩 ASCII 字母数字 + base64 字符）
        let yaml = "proxies: []\nrules: []\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(yaml);
        // 内部加换行模拟机场常见格式
        let multi = encoded
            .as_bytes()
            .chunks(40)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let rendered = render_config(&multi)?;
        let cfg: Value = serde_yml::from_str(&rendered)?;
        assert!(cfg.as_mapping().unwrap().contains_key(key("proxies")));
        Ok(())
    }

    #[test]
    fn robustness_passthrough_when_input_is_not_base64() -> Result<()> {
        // 含 ":" 的明显是 YAML，不应误判为 base64
        let yaml = "mixed-port: 7890\nproxies: []\nrules: []\n";
        let rendered = render_config(yaml)?;
        let cfg: Value = serde_yml::from_str(&rendered)?;
        assert_eq!(
            cfg.as_mapping().unwrap().get(key("mixed-port")),
            Some(&serde_yml::to_value(14190_u16)?)
        );
        Ok(())
    }

    #[test]
    fn robustness_handles_empty_proxies_and_rules() -> Result<()> {
        // 几乎空订阅：仍能渲染，至少有 mihomo 必需字段
        let rendered = render_config("proxies: []\nrules: []\n")?;
        let cfg: Value = serde_yml::from_str(&rendered)?;
        let root = cfg.as_mapping().unwrap();
        assert!(root.contains_key(key("mixed-port")));
        assert!(root.contains_key(key("dns")));
        Ok(())
    }

    #[test]
    fn robustness_proxy_providers_does_not_block_render() -> Result<()> {
        // 含 proxy-providers 时仅警告（log），不应失败
        let yaml = r#"
proxy-providers:
  remote-1:
    type: http
    url: https://example.com/sub
proxies: []
rules: []
"#;
        let rendered = render_config(yaml)?;
        let cfg: Value = serde_yml::from_str(&rendered)?;
        assert!(cfg.as_mapping().unwrap().contains_key(key("proxy-providers")));
        Ok(())
    }

    #[test]
    fn robustness_rejects_non_mapping_top_level() {
        // YAML 是个 sequence 而非 mapping —— 必须明确报错
        let err = render_config("- item1\n- item2\n").unwrap_err();
        assert!(format!("{err}").contains("顶层必须是 mapping"), "实际错误: {err}");
    }

    #[test]
    fn robustness_rejects_invalid_yaml() {
        // 字符串含 \t\n 等控制字符 + 错位 YAML 引号 → YAML 解析必败
        let err = render_config("\"unclosed: 'mixed quotes\nbroken: [line").unwrap_err();
        assert!(format!("{err}").contains("解析订阅 YAML 失败"), "实际错误: {err}");
    }

    #[test]
    fn robustness_dns_wrong_type_replaced_silently() -> Result<()> {
        // dns 字段被错配成字符串/序列时不应崩溃，而是直接覆盖为标准 mapping（宽容策略）
        for bad_dns in [
            "dns: enable\nproxies: []\nrules: []\n",
            "dns: [a, b]\nproxies: []\nrules: []\n",
            "dns: 12345\nproxies: []\nrules: []\n",
        ] {
            let rendered = render_config(bad_dns)?;
            let cfg: Value = serde_yml::from_str(&rendered)?;
            let dns = cfg
                .as_mapping()
                .unwrap()
                .get(key("dns"))
                .and_then(Value::as_mapping)
                .expect("dns 应被替换为 mapping");
            assert_eq!(dns.get(key("enable")), Some(&serde_yml::to_value(true)?));
            assert_eq!(
                dns.get(key("listen")),
                Some(&serde_yml::to_value("192.168.0.1:14153")?)
            );
        }
        Ok(())
    }

    #[test]
    fn robustness_fake_ip_filter_wrong_type_replaced() -> Result<()> {
        // 用户写错 fake-ip-filter 为字符串/对象时也覆盖为新 sequence，不报错
        let bad = "dns:\n  fake-ip-filter: a string\nproxies: []\nrules: []\n";
        let rendered = render_config(bad)?;
        let cfg: Value = serde_yml::from_str(&rendered)?;
        let filter = cfg
            .as_mapping()
            .unwrap()
            .get(key("dns"))
            .and_then(Value::as_mapping)
            .and_then(|d| d.get(key("fake-ip-filter")))
            .and_then(Value::as_sequence)
            .expect("fake-ip-filter 应是 sequence");
        assert!(filter.contains(&serde_yml::to_value("*.lan")?));
        Ok(())
    }

    #[test]
    fn robustness_top_level_string_rejected() {
        // 顶层是字符串（既不是 sequence 也不是 mapping）
        let err = render_config("just a string\n").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("顶层必须是 mapping") || msg.contains("解析订阅 YAML 失败"),
            "应有清晰错误信息，实际: {msg}"
        );
    }

    #[test]
    fn replace_section_preserves_other_sections_when_subscription_overwritten() {
        // 关键回归：订阅 URL 导入不能再清掉 [easytier] 段
        let original = "[subscription]\nurl = \"https://old\"\n\n[easytier]\nnetwork_name = \"team\"\nnetwork_secret = \"s\"\nipv4 = \"10.0.5.3\"\npeers = [\n  \"tcp://1.2.3.4:14020/\",\n]\n";
        let new_sub = "[subscription]\nurl = \"https://new\"\n";
        let merged = replace_or_append_section(original, "subscription", new_sub);
        assert!(merged.contains("url = \"https://new\""));
        assert!(!merged.contains("url = \"https://old\""));
        // [easytier] 段必须保留
        assert!(merged.contains("[easytier]"));
        assert!(merged.contains("network_name = \"team\""));
        assert!(merged.contains("network_secret = \"s\""));
        assert!(merged.contains("ipv4 = \"10.0.5.3\""));
        assert!(merged.contains("\"tcp://1.2.3.4:14020/\""));
    }

    #[test]
    fn replace_section_appends_subscription_when_only_easytier_present() {
        let original = "[easytier]\nnetwork_name = \"x\"\n";
        let new_sub = "[subscription]\nurl = \"https://y\"\n";
        let merged = replace_or_append_section(original, "subscription", new_sub);
        assert!(merged.contains("[easytier]"));
        assert!(merged.contains("[subscription]"));
        assert!(merged.contains("url = \"https://y\""));
    }

    #[test]
    fn escape_toml_string_escapes_secret_url() {
        assert_eq!(
            escape_toml_string(r#"https://example.com/a?x="1"\n"#),
            r#"https://example.com/a?x=\"1\"\\n"#
        );
    }
}
