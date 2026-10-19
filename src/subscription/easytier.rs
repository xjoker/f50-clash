use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    path::Path,
};

use anyhow::{bail, Context, Result};

const SECRETS_FILE: &str = "/data/adb/f50mgr/config/secrets.toml";
const F50MGR_CONFIG_FILE: &str = "/data/adb/f50mgr/config/f50mgr.toml";
const HOSTNAME_PREFIX: &str = "F50";
const RPC_PORTAL: &str = "127.0.0.1:15888";
/// 固定 EasyTier TUN 接口名，便于 iptables NAT 规则匹配（tun_et 长度 6，符合 IFNAMSIZ=15）。
pub(crate) const TUN_DEV_NAME: &str = "tun_et";
/// 本机 listeners：让 mesh peer 能反向连接打洞，从 RELAY 升级为 P2P。
/// 端口 14010 与公司中转节点端口一致，方便上游路由器统一开 NAT 端口转发。
const LISTENERS: [&str; 4] = [
    "tcp://0.0.0.0:14010",
    "tcp://[::]:14010",
    "udp://0.0.0.0:14010",
    "udp://[::]:14010",
];

#[derive(Debug, Clone)]
struct EasyTierSecrets {
    network_name: String,
    network_secret: String,
    ipv4: String,
    instance_id: Option<String>,
    instance_name: Option<String>,
    hostname: Option<String>,
    peers: Vec<String>,
}

/// 渲染 EasyTier 配置到 `output`。
/// 强制要求：内核 TUN（use_smoltcp=false, no_tun=false），rpc_portal 仅本地。
pub fn render_default(output: &Path) -> Result<()> {
    super::with_config_write_lock(output, || {
        let secrets = read_secrets(SECRETS_FILE)?;
        let device_id =
            crate::device::device_id().context("读取设备标识失败，无法生成 EasyTier hostname")?;
        let content = render(&secrets, &device_id)?;
        super::write_atomic(output, content.as_bytes())
    })
}

fn render(secrets: &EasyTierSecrets, device_id: &str) -> Result<String> {
    if secrets.network_name.is_empty() {
        bail!("secrets.toml [easytier] 缺少 network_name");
    }
    if secrets.network_secret.is_empty() {
        bail!("secrets.toml [easytier] 缺少 network_secret");
    }
    if secrets.ipv4.is_empty() {
        bail!("secrets.toml [easytier] 缺少 ipv4（每台 F50 必须静态分配）");
    }

    let hostname = secrets
        .hostname
        .clone()
        .unwrap_or_else(|| format!("{HOSTNAME_PREFIX}-{device_id}"));
    let instance_name = secrets
        .instance_name
        .clone()
        .unwrap_or_else(|| hostname.clone());
    let instance_id = secrets
        .instance_id
        .clone()
        .unwrap_or_else(generate_uuid_v4);

    let mut buf = String::new();
    buf.push_str(&format!("hostname = {}\n", toml_string(&hostname)));
    buf.push_str(&format!("instance_name = {}\n", toml_string(&instance_name)));
    buf.push_str(&format!("instance_id = {}\n", toml_string(&instance_id)));
    buf.push_str(&format!("ipv4 = {}\n", toml_string(&secrets.ipv4)));
    buf.push_str(&format!("rpc_portal = {}\n", toml_string(RPC_PORTAL)));
    buf.push('\n');

    buf.push_str("listeners = [\n");
    for uri in LISTENERS {
        buf.push_str(&format!("  {},\n", toml_string(uri)));
    }
    buf.push_str("]\n\n");

    buf.push_str("[network_identity]\n");
    buf.push_str(&format!("network_name = {}\n", toml_string(&secrets.network_name)));
    buf.push_str(&format!(
        "network_secret = {}\n",
        toml_string(&secrets.network_secret)
    ));
    buf.push('\n');

    // 强制内核 TUN：use_smoltcp=false, no_tun=false，避免用户态网络栈性能损失。
    // dev_name 固定为 tun_et，便于 iptables NAT 规则匹配（让 LAN 客户端经 mesh 出向）。
    buf.push_str("[flags]\n");
    buf.push_str(&format!("dev_name = {}\n", toml_string(TUN_DEV_NAME)));
    buf.push_str("private_mode = true\n");
    buf.push_str("latency_first = true\n");
    buf.push_str("use_smoltcp = false\n");
    buf.push_str("no_tun = false\n");
    buf.push_str("enable_encryption = true\n");
    buf.push_str("mtu = 1380\n");
    // 日志级别不走 config（[console_logger] 段实测被 easytier 忽略），
    // 由 spawn 时的 ET_CONSOLE_LOG_LEVEL 环境变量控制（见 process/easytier.rs）

    for uri in &secrets.peers {
        buf.push('\n');
        buf.push_str("[[peer]]\n");
        buf.push_str(&format!("uri = {}\n", toml_string(uri)));
    }

    Ok(buf)
}

fn read_secrets(path: &str) -> Result<EasyTierSecrets> {
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            bail!("EasyTier 缺少 secrets.toml：{path}")
        }
        Err(err) => return Err(err).with_context(|| format!("读取 secrets 失败: {path}")),
    };
    parse_secrets(&content)
}

fn parse_secrets(content: &str) -> Result<EasyTierSecrets> {
    let mut in_section = false;
    let mut scalars: BTreeMap<&str, String> = BTreeMap::new();
    let mut peers: Vec<String> = Vec::new();
    let mut peers_collecting = false;
    let mut peers_buf = String::new();

    for raw in content.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            // 段落切换前结算 peers 数组。
            if peers_collecting {
                bail!("secrets.toml [easytier].peers 数组未闭合");
            }
            in_section = line == "[easytier]";
            continue;
        }
        if !in_section {
            continue;
        }

        if peers_collecting {
            peers_buf.push_str(line);
            // 只认引号外的 `]`：IPv6 字面量 peer（tcp://[2001:db8::1]:11010）里也有 `]`
            if find_unquoted(line, ']').is_some() {
                peers.extend(parse_inline_string_array(&peers_buf)?);
                peers_buf.clear();
                peers_collecting = false;
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if key == "peers" {
            if value.starts_with('[') {
                if find_unquoted(value, ']').is_some() {
                    peers.extend(parse_inline_string_array(value)?);
                } else {
                    peers_collecting = true;
                    peers_buf.clear();
                    peers_buf.push_str(value);
                }
            } else {
                bail!("peers 必须是字符串数组");
            }
            continue;
        }

        let parsed = parse_toml_string(value)
            .with_context(|| format!("secrets [easytier].{key} 无法解析为字符串"))?;
        match key {
            "network_name" | "network_secret" | "ipv4" | "instance_id" | "instance_name"
            | "hostname" => {
                scalars.insert(key, parsed);
            }
            _ => {} // 未知字段忽略，保持向前兼容
        }
    }

    if peers_collecting {
        bail!("secrets.toml [easytier].peers 数组未闭合");
    }

    Ok(EasyTierSecrets {
        network_name: scalars.remove("network_name").unwrap_or_default(),
        network_secret: scalars.remove("network_secret").unwrap_or_default(),
        ipv4: scalars.remove("ipv4").unwrap_or_default(),
        instance_id: scalars.remove("instance_id"),
        instance_name: scalars.remove("instance_name"),
        hostname: scalars.remove("hostname"),
        peers,
    })
}

fn parse_inline_string_array(text: &str) -> Result<Vec<String>> {
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .context("数组语法错误，缺少 [ 或 ]")?;
    let mut out = Vec::new();
    for raw in split_unquoted(body, ',') {
        let item = strip_comment(raw).trim();
        if item.is_empty() {
            continue;
        }
        out.push(parse_toml_string(item)?);
    }
    Ok(out)
}

/// 仅支持基础双引号字符串（够用于 URL / network_name），不解析多行字符串。
fn parse_toml_string(value: &str) -> Result<String> {
    let v = value.trim();
    if let Some(stripped) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        let mut out = String::with_capacity(stripped.len());
        let mut chars = stripped.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            let next = chars.next().context("字符串以反斜杠结尾，未闭合转义")?;
            match next {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                other => bail!("不支持的转义序列: \\{other}"),
            }
        }
        Ok(out)
    } else if let Some(stripped) = v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        Ok(stripped.to_owned())
    } else {
        bail!("字符串必须用引号包裹：{value}")
    }
}

/// 去掉行尾注释；引号内的 `#` 属于值本身（例如 network_secret = "abc#def"）。
fn strip_comment(line: &str) -> &str {
    find_unquoted(line, '#').map_or(line, |idx| &line[..idx])
}

/// 返回第一个位于引号外的 `target` 的字节下标。
/// 认识 parse_toml_string 支持的两种字符串：基础字符串 "..."（含反斜杠转义）和字面量 '...'。
fn find_unquoted(text: &str, target: char) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, c) in text.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == target => return Some(idx),
            None if c == '"' || c == '\'' => quote = Some(c),
            None => {}
        }
    }
    None
}

/// 按引号外的 `sep` 切分。
fn split_unquoted(text: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = text;
    while let Some(idx) = find_unquoted(rest, sep) {
        parts.push(&rest[..idx]);
        rest = &rest[idx + sep.len_utf8()..];
    }
    parts.push(rest);
    parts
}

fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// 极简 v4 UUID 生成（无外部依赖）。来源：/proc/sys/kernel/random/uuid，兜底 SystemTime + pid 哈希。
fn generate_uuid_v4() -> String {
    if let Ok(s) = fs::read_to_string("/proc/sys/kernel/random/uuid") {
        let trimmed = s.trim();
        if trimmed.len() == 36 {
            return trimmed.to_owned();
        }
    }
    // 兜底：当前秒 + pid 拼出伪随机串，仍符合 UUID 格式但熵低（仅设备唯一性即可）。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let mix = now ^ (pid.wrapping_mul(0x9E3779B97F4A7C15));
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        (mix >> 32) as u32,
        (mix >> 16) as u16,
        (mix & 0xFFF) as u16,
        ((mix >> 4) & 0xFFF) as u16,
        mix & 0xFFFF_FFFF_FFFF
    )
}

/// CLI 调用（root shell）：读取 secrets 并打印生成的配置（不落盘）。
pub fn preview() -> Result<String> {
    let secrets = read_secrets(SECRETS_FILE)?;
    let device_id = crate::device::device_id()?;
    render(&secrets, &device_id)
}

/// Web 预览占位符。
const REDACTED_SECRET: &str = "<已隐藏>";

/// Web `GET /api/easytier/preview`：同 preview()，但脱敏 network_secret——
/// 14180 面板对 LAN 无认证开放，不得把 mesh 密钥回显给任意热点客户端。
pub fn preview_redacted() -> Result<String> {
    let mut secrets = read_secrets(SECRETS_FILE)?;
    redact_network_secret(&mut secrets);
    let device_id = crate::device::device_id()?;
    render(&secrets, &device_id)
}

fn redact_network_secret(secrets: &mut EasyTierSecrets) {
    if !secrets.network_secret.is_empty() {
        secrets.network_secret = REDACTED_SECRET.to_owned();
    }
}

/// Web `GET /api/easytier/secrets`：返回隐去 secret 后的 [easytier] 段视图。
/// 当 secrets.toml 不存在或无 [easytier] 段时返回 `Ok(None)`，便于前端判空。
pub fn read_secrets_safe() -> Result<Option<SecretsSafeView>> {
    let content = match fs::read_to_string(SECRETS_FILE) {
        Ok(s) => s,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("读取 secrets 失败: {SECRETS_FILE}"))
        }
    };
    if !has_easytier_section(&content) {
        return Ok(None);
    }
    let parsed = parse_secrets(&content)?;
    Ok(Some(SecretsSafeView {
        network_name: parsed.network_name,
        ipv4: parsed.ipv4,
        instance_id: parsed.instance_id,
        instance_name: parsed.instance_name,
        hostname: parsed.hostname,
        peers: parsed.peers,
        has_secret: !parsed.network_secret.is_empty(),
    }))
}

/// Web `POST /api/easytier/secrets`：合并写入 [easytier] 段，保留其他段。
/// `payload.network_secret` 为 None / 空串时保留旧值（防止 GET 不回显导致的误覆盖）。
pub fn write_secrets(payload: SecretsInput) -> Result<()> {
    super::with_config_write_lock(Path::new(SECRETS_FILE), || {
        let original = match fs::read_to_string(SECRETS_FILE) {
            Ok(s) => s,
            Err(err) if err.kind() == ErrorKind::NotFound => String::new(),
            Err(err) => {
                return Err(err).with_context(|| format!("读取 secrets 失败: {SECRETS_FILE}"))
            }
        };

        // 保留旧 secret（如果存在且 payload 里没新值）
        let preserved_secret = resolve_network_secret(&original, payload.network_secret)?;

        let new_section = render_easytier_section(&SecretsSection {
            network_name: payload.network_name,
            network_secret: preserved_secret,
            ipv4: payload.ipv4,
            instance_id: payload.instance_id,
            instance_name: payload.instance_name,
            hostname: payload.hostname,
            peers: payload.peers,
        });
        let merged = replace_or_append_easytier_section(&original, &new_section);
        super::write_atomic(Path::new(SECRETS_FILE), merged.as_bytes())
    })
}

/// payload 没带新 secret 时沿用 `original` 里的旧值。
/// 旧段解析失败时直接报错：不能把「读不出来」当成「没有旧值」，否则会把 network_secret 写空。
fn resolve_network_secret(original: &str, new_secret: Option<String>) -> Result<String> {
    if new_secret.as_deref().unwrap_or("").is_empty() && has_easytier_section(original) {
        let previous = parse_secrets(original)
            .context("现有 secrets.toml [easytier] 段无法解析，为避免清空 network_secret 已拒绝保存；请重新填写 network_secret")?;
        Ok(previous.network_secret)
    } else {
        Ok(new_secret.unwrap_or_default())
    }
}

#[derive(Debug, serde::Serialize)]
pub struct SecretsSafeView {
    pub network_name: String,
    pub ipv4: String,
    pub instance_id: Option<String>,
    pub instance_name: Option<String>,
    pub hostname: Option<String>,
    pub peers: Vec<String>,
    pub has_secret: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct SecretsInput {
    #[serde(default)]
    pub network_name: String,
    #[serde(default)]
    pub network_secret: Option<String>,
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub instance_id: Option<String>,
    #[serde(default)]
    pub instance_name: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub peers: Vec<String>,
}

struct SecretsSection {
    network_name: String,
    network_secret: String,
    ipv4: String,
    instance_id: Option<String>,
    instance_name: Option<String>,
    hostname: Option<String>,
    peers: Vec<String>,
}

fn has_easytier_section(content: &str) -> bool {
    content
        .lines()
        .map(|l| strip_comment(l).trim())
        .any(|l| l == "[easytier]")
}

fn render_easytier_section(s: &SecretsSection) -> String {
    let mut buf = String::from("[easytier]\n");
    buf.push_str(&format!("network_name = {}\n", toml_string(&s.network_name)));
    buf.push_str(&format!("network_secret = {}\n", toml_string(&s.network_secret)));
    buf.push_str(&format!("ipv4 = {}\n", toml_string(&s.ipv4)));
    if let Some(v) = &s.instance_id {
        buf.push_str(&format!("instance_id = {}\n", toml_string(v)));
    }
    if let Some(v) = &s.instance_name {
        buf.push_str(&format!("instance_name = {}\n", toml_string(v)));
    }
    if let Some(v) = &s.hostname {
        buf.push_str(&format!("hostname = {}\n", toml_string(v)));
    }
    buf.push_str("peers = [\n");
    for p in &s.peers {
        buf.push_str(&format!("  {},\n", toml_string(p)));
    }
    buf.push_str("]\n");
    buf
}

/// 替换 [easytier] 段为 `new_section`，保留其它段；若无该段则追加。
fn replace_or_append_easytier_section(original: &str, new_section: &str) -> String {
    let lines: Vec<&str> = original.lines().collect();
    let mut start: Option<usize> = None;
    let mut end: usize = lines.len();

    for (i, raw) in lines.iter().enumerate() {
        let line = strip_comment(raw).trim();
        if start.is_none() {
            if line == "[easytier]" {
                start = Some(i);
            }
        } else if line.starts_with('[') && line.ends_with(']') && line != "[easytier]" {
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
        // 去除替换段前的多余空行（避免每次保存都多一行空白）
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

#[allow(dead_code)]
const _: &str = F50MGR_CONFIG_FILE; // 预留：后续 8b 阶段读取 [easytier] 顶层覆写

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secrets() -> EasyTierSecrets {
        EasyTierSecrets {
            network_name: "team-a".into(),
            network_secret: "s3cret".into(),
            ipv4: "10.0.5.3".into(),
            instance_id: Some("11111111-2222-4333-8444-555555555555".into()),
            instance_name: None,
            hostname: None,
            peers: vec![
                "tcp://1.2.3.4:14020/".into(),
                "udp://1.2.3.4:14020/".into(),
            ],
        }
    }

    #[test]
    fn web_preview_redaction_never_leaks_real_secret() -> Result<()> {
        // 14180 面板无认证：预览输出里绝不能出现真实 network_secret
        let mut secrets = sample_secrets();
        redact_network_secret(&mut secrets);
        let cfg = render(&secrets, "x")?;
        assert!(!cfg.contains("s3cret"), "预览输出泄漏了真实密钥");
        assert!(cfg.contains(REDACTED_SECRET));
        Ok(())
    }

    #[test]
    fn render_uses_device_id_for_hostname() -> Result<()> {
        let cfg = render(&sample_secrets(), "356938035643809")?;
        assert!(cfg.contains("hostname = \"F50-356938035643809\""));
        assert!(cfg.contains("instance_name = \"F50-356938035643809\""));
        assert!(cfg.contains("ipv4 = \"10.0.5.3\""));
        assert!(cfg.contains("rpc_portal = \"127.0.0.1:15888\""));
        Ok(())
    }

    #[test]
    fn render_pins_dev_name_to_tun_et() -> Result<()> {
        let cfg = render(&sample_secrets(), "x")?;
        assert!(cfg.contains("dev_name = \"tun_et\""));
        assert_eq!(TUN_DEV_NAME, "tun_et");
        Ok(())
    }

    #[test]
    fn render_emits_listeners_for_p2p_punch() -> Result<()> {
        let cfg = render(&sample_secrets(), "x")?;
        assert!(cfg.contains("listeners = ["));
        assert!(cfg.contains("\"tcp://0.0.0.0:14010\""));
        assert!(cfg.contains("\"tcp://[::]:14010\""));
        assert!(cfg.contains("\"udp://0.0.0.0:14010\""));
        assert!(cfg.contains("\"udp://[::]:14010\""));
        Ok(())
    }

    #[test]
    fn render_enforces_kernel_tun_flags() -> Result<()> {
        let cfg = render(&sample_secrets(), "x")?;
        assert!(cfg.contains("use_smoltcp = false"));
        assert!(cfg.contains("no_tun = false"));
        assert!(cfg.contains("private_mode = true"));
        assert!(cfg.contains("latency_first = true"));
        Ok(())
    }

    #[test]
    fn render_emits_peers_in_order() -> Result<()> {
        let cfg = render(&sample_secrets(), "x")?;
        let tcp = cfg.find("uri = \"tcp://1.2.3.4:14020/\"").expect("tcp peer");
        let udp = cfg.find("uri = \"udp://1.2.3.4:14020/\"").expect("udp peer");
        assert!(tcp < udp);
        assert_eq!(cfg.matches("[[peer]]").count(), 2);
        Ok(())
    }

    #[test]
    fn render_rejects_missing_network_name() {
        let mut s = sample_secrets();
        s.network_name = String::new();
        assert!(render(&s, "x").is_err());
    }

    #[test]
    fn render_rejects_missing_ipv4() {
        let mut s = sample_secrets();
        s.ipv4 = String::new();
        assert!(render(&s, "x").is_err());
    }

    #[test]
    fn parse_secrets_parses_inline_array() -> Result<()> {
        let raw = r#"
[easytier]
network_name = "team-a"
network_secret = "s3cret"
ipv4 = "10.0.5.3"
peers = ["tcp://1.1.1.1:11010/", "udp://1.1.1.1:11010/"]
"#;
        let s = parse_secrets(raw)?;
        assert_eq!(s.peers.len(), 2);
        assert_eq!(s.peers[0], "tcp://1.1.1.1:11010/");
        Ok(())
    }

    #[test]
    fn parse_secrets_parses_multiline_array() -> Result<()> {
        let raw = r#"
[easytier]
network_name = "team-a"
network_secret = "s3cret"
ipv4 = "10.0.5.3"
peers = [
  "tcp://1.1.1.1:11010/",
  "udp://2.2.2.2:11010/",
]
"#;
        let s = parse_secrets(raw)?;
        assert_eq!(s.peers, vec![
            "tcp://1.1.1.1:11010/",
            "udp://2.2.2.2:11010/",
        ]);
        Ok(())
    }

    #[test]
    fn parse_secrets_ignores_other_sections() -> Result<()> {
        let raw = r#"
[mihomo]
secret = "abc"

[easytier]
network_name = "team-a"
network_secret = "s3cret"
ipv4 = "10.0.5.3"
peers = []
"#;
        let s = parse_secrets(raw)?;
        assert_eq!(s.network_name, "team-a");
        assert!(s.peers.is_empty());
        Ok(())
    }

    #[test]
    fn render_uses_explicit_hostname_override() -> Result<()> {
        let mut s = sample_secrets();
        s.hostname = Some("custom-name".into());
        let cfg = render(&s, "ignored")?;
        assert!(cfg.contains("hostname = \"custom-name\""));
        assert!(cfg.contains("instance_name = \"custom-name\""));
        Ok(())
    }

    #[test]
    fn toml_string_escapes_quotes_and_backslash() {
        assert_eq!(toml_string("a\"b\\c"), r#""a\"b\\c""#);
    }

    #[test]
    fn replace_easytier_section_preserves_other_sections() {
        let original = "[subscription]\nurl = \"https://x\"\n\n[easytier]\nnetwork_name = \"old\"\nnetwork_secret = \"old-secret\"\nipv4 = \"10.0.0.1\"\npeers = []\n\n[other]\nfoo = 1\n";
        let new_sec = "[easytier]\nnetwork_name = \"new\"\nnetwork_secret = \"old-secret\"\nipv4 = \"10.0.0.2\"\npeers = [\n  \"tcp://1.1.1.1:11010/\",\n]\n";
        let merged = replace_or_append_easytier_section(original, new_sec);
        assert!(merged.contains("[subscription]"));
        assert!(merged.contains("url = \"https://x\""));
        assert!(merged.contains("[other]"));
        assert!(merged.contains("foo = 1"));
        assert!(merged.contains("network_name = \"new\""));
        assert!(merged.contains("ipv4 = \"10.0.0.2\""));
        assert!(!merged.contains("network_name = \"old\""));
        assert!(!merged.contains("ipv4 = \"10.0.0.1\""));
        // 旧 secret 必须保留（合并由调用方完成，这里只确保 render 出的段被原样写入）
        assert!(merged.contains("network_secret = \"old-secret\""));
    }

    #[test]
    fn replace_easytier_appends_when_absent() {
        let original = "[subscription]\nurl = \"\"\n";
        let new_sec = "[easytier]\nnetwork_name = \"a\"\nnetwork_secret = \"b\"\nipv4 = \"10.0.0.3\"\npeers = []\n";
        let merged = replace_or_append_easytier_section(original, new_sec);
        assert!(merged.contains("[subscription]"));
        assert!(merged.contains("[easytier]"));
        assert!(merged.contains("network_name = \"a\""));
    }

    #[test]
    fn replace_easytier_handles_empty_input() {
        let new_sec = "[easytier]\nnetwork_name = \"a\"\nnetwork_secret = \"b\"\nipv4 = \"10.0.0.3\"\npeers = []\n";
        let merged = replace_or_append_easytier_section("", new_sec);
        assert!(merged.starts_with("[easytier]"));
    }

    #[test]
    fn render_easytier_section_emits_required_fields() {
        let sec = SecretsSection {
            network_name: "team".into(),
            network_secret: "s".into(),
            ipv4: "10.0.5.7".into(),
            instance_id: None,
            instance_name: None,
            hostname: None,
            peers: vec!["tcp://1.1.1.1:11010/".into()],
        };
        let out = render_easytier_section(&sec);
        assert!(out.contains("network_name = \"team\""));
        assert!(out.contains("network_secret = \"s\""));
        assert!(out.contains("ipv4 = \"10.0.5.7\""));
        assert!(out.contains("\"tcp://1.1.1.1:11010/\""));
        assert!(!out.contains("instance_id"));
    }

    #[test]
    fn has_easytier_section_detects_presence() {
        assert!(has_easytier_section("[easytier]\n"));
        assert!(has_easytier_section("[other]\nfoo=1\n[easytier]\nx=1\n"));
        assert!(!has_easytier_section("[other]\nfoo=1\n"));
        assert!(!has_easytier_section("# [easytier] in comment\n"));
    }

    fn section_with(network_secret: &str, peers: &[&str]) -> SecretsSection {
        SecretsSection {
            network_name: "team#1".into(),
            network_secret: network_secret.into(),
            ipv4: "10.0.5.7".into(),
            instance_id: None,
            instance_name: None,
            hostname: Some("f50#lab".into()),
            peers: peers.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    #[test]
    fn parse_secrets_roundtrips_ipv6_literal_peers() -> Result<()> {
        // #16：多行 peers 里 IPv6 字面量的 `]` 不能被当成数组结束
        let peers = [
            "tcp://[2001:db8::1]:11010",
            "udp://[2001:db8::2]:11010/",
            "tcp://1.2.3.4:11010/",
        ];
        let mut section = section_with("s3cret", &peers);
        section.network_name = "team".into();
        section.hostname = None;
        let parsed = parse_secrets(&render_easytier_section(&section))?;
        assert_eq!(parsed.peers, peers);
        assert_eq!(parsed.network_secret, "s3cret");
        Ok(())
    }

    #[test]
    fn parse_secrets_roundtrips_hash_inside_quoted_values() -> Result<()> {
        // #10：引号内的 `#` 不是注释
        let rendered = render_easytier_section(&section_with("abc#def", &["tcp://h.example:1/#x"]));
        let parsed = parse_secrets(&rendered)?;
        assert_eq!(parsed.network_secret, "abc#def");
        assert_eq!(parsed.network_name, "team#1");
        assert_eq!(parsed.hostname.as_deref(), Some("f50#lab"));
        assert_eq!(parsed.peers, vec!["tcp://h.example:1/#x"]);
        Ok(())
    }

    #[test]
    fn parse_secrets_still_strips_trailing_comments() -> Result<()> {
        let raw = "[easytier] # mesh\nnetwork_name = \"team\" # 名称\nnetwork_secret = 'a#b' # 字面量\nipv4 = \"10.0.5.3\"\npeers = [ # 列表\n  \"tcp://[::1]:11010\", # v6\n  \"tcp://a,b:1\",\n] # end\n";
        let parsed = parse_secrets(raw)?;
        assert_eq!(parsed.network_name, "team");
        assert_eq!(parsed.network_secret, "a#b");
        assert_eq!(parsed.peers, vec!["tcp://[::1]:11010", "tcp://a,b:1"]);
        Ok(())
    }

    #[test]
    fn resave_without_secret_keeps_secret_with_ipv6_peer_and_hash() -> Result<()> {
        // #10 / #16：只改 peers 再保存（payload 不带 secret）时，旧 secret 不能被写空
        let original = format!(
            "[subscription]\nurl = \"https://x\"\n\n{}",
            render_easytier_section(&section_with("abc#def", &["tcp://[2001:db8::1]:11010"]))
        );
        assert_eq!(resolve_network_secret(&original, None)?, "abc#def");
        assert_eq!(
            resolve_network_secret(&original, Some(String::new()))?,
            "abc#def"
        );
        assert_eq!(
            resolve_network_secret(&original, Some("new".into()))?,
            "new"
        );
        Ok(())
    }

    #[test]
    fn resave_without_secret_refuses_to_blank_unparseable_secret() {
        // 旧段无法解析时必须报错，而不是把 network_secret 当成空串写回
        let original = "[easytier]\nnetwork_name = \"team\"\nnetwork_secret = \"keep\"\nipv4 = \"10.0.5.3\"\npeers = [\n";
        assert!(resolve_network_secret(original, None).is_err());
        assert_eq!(
            resolve_network_secret(original, Some("new".into())).unwrap(),
            "new"
        );
    }

    #[test]
    fn generate_uuid_v4_has_correct_format() {
        let u = generate_uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[8], b'-');
        assert_eq!(u.as_bytes()[13], b'-');
        assert_eq!(u.as_bytes()[14], b'4'); // version 4
        assert_eq!(u.as_bytes()[18], b'-');
        assert_eq!(u.as_bytes()[23], b'-');
    }
}
