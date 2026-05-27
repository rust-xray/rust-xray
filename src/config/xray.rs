use std::collections::BTreeMap;
use std::path::Path;

use crate::vless::{validate_fallback_configs, FallbackConfig};
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;

const REALITY_DEFAULT_DEST_PORT: u16 = 443;

#[derive(Debug, Clone, Deserialize)]
pub struct XrayConfig {
    #[serde(default)]
    pub inbounds: Vec<InboundObject>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum InboundPortValue {
    Number(u16),
    String(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboundObject {
    pub tag: Option<String>,
    pub listen: Option<String>,
    pub port: Option<InboundPortValue>,
    pub protocol: Option<String>,
    pub settings: Option<Value>,
    #[serde(rename = "streamSettings")]
    pub stream_settings: Option<StreamSettingsObject>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VlessInboundSettings {
    #[serde(default)]
    pub clients: Vec<VlessClientObject>,

    pub decryption: Option<String>,

    #[serde(default)]
    pub fallbacks: Vec<FallbackConfig>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VlessClientObject {
    pub id: String,
    pub email: Option<String>,
    pub flow: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StreamSettingsObject {
    pub network: Option<String>,
    pub security: Option<String>,
    #[serde(rename = "realitySettings")]
    pub reality_settings: Option<RealitySettingsObject>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RealitySettingsObject {
    #[serde(default)]
    pub show: bool,

    pub dest: Option<Value>,
    pub target: Option<Value>,

    #[serde(rename = "type")]
    pub transport_type: Option<String>,

    #[serde(default)]
    pub xver: u64,

    #[serde(rename = "serverNames", default)]
    pub server_names: Vec<String>,

    #[serde(rename = "privateKey")]
    pub private_key: Option<String>,

    #[serde(rename = "minClientVer")]
    pub min_client_ver: Option<String>,

    #[serde(rename = "maxClientVer")]
    pub max_client_ver: Option<String>,

    #[serde(rename = "maxTimeDiff", default)]
    pub max_time_diff: u64,

    #[serde(rename = "shortIds", default)]
    pub short_ids: Vec<String>,

    #[serde(rename = "mldsa65Seed")]
    pub mldsa65_seed: Option<String>,

    #[serde(rename = "limitFallbackUpload")]
    pub limit_fallback_upload: Option<Value>,

    #[serde(rename = "limitFallbackDownload")]
    pub limit_fallback_download: Option<Value>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct RealityInboundRuntime {
    pub tag: Option<String>,
    pub protocol: Option<String>,
    pub listen_addr: String,
    pub dest_addr: String,
    pub private_key: String,
    pub server_names: Vec<String>,
    pub short_ids: Vec<Vec<u8>>,
    pub max_time_diff: u64,
    pub min_client_ver: Option<String>,
    pub max_client_ver: Option<String>,
    pub show: bool,
    pub vless_clients: Vec<VlessClientObject>,
    pub vless_decryption: String,
    pub vless_fallbacks: Vec<FallbackConfig>,
}

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn is_vless_protocol(protocol: Option<&str>) -> bool {
    protocol.is_some_and(|value| eq_ignore_ascii_case(value, "vless"))
}

fn is_reality_security(security: Option<&str>) -> bool {
    security.is_some_and(|value| eq_ignore_ascii_case(value, "reality"))
}

fn is_vless_reality_inbound(inbound: &InboundObject) -> bool {
    inbound.stream_settings.as_ref().is_some_and(|stream| {
        is_vless_protocol(inbound.protocol.as_deref())
            && is_reality_security(stream.security.as_deref())
            && stream.reality_settings.is_some()
    })
}

/// Validate REALITY inbound `streamSettings.network`.
///
/// `tcp` is the legacy alias for raw TCP transport; `raw` is the explicit form.
pub fn validate_reality_transport_network(network: Option<&str>) -> std::io::Result<()> {
    let normalized = network
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);

    match normalized.as_deref() {
        None | Some("tcp") | Some("raw") => Ok(()),
        Some("xhttp") => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "REALITY over XHTTP runtime is not implemented yet",
        )),
        Some("grpc") => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "REALITY over gRPC runtime is not implemented yet",
        )),
        Some("ws") | Some("websocket") => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY over WebSocket transport (network=ws) is not supported",
        )),
        Some("mkcp") | Some("kcp") => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
        )),
        Some("httpupgrade") => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY over HTTPUpgrade transport (network=httpupgrade) is not supported",
        )),
        Some("hysteria") => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY over Hysteria transport (network=hysteria) is not supported",
        )),
        Some(value) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported REALITY transport network: {value}"),
        )),
    }
}

/// Validate `streamSettings.network` when `streamSettings.security` is REALITY.
pub fn validate_reality_stream_settings(stream: &StreamSettingsObject) -> std::io::Result<()> {
    if !is_reality_security(stream.security.as_deref()) {
        return Ok(());
    }

    validate_reality_transport_network(stream.network.as_deref())
}

fn validate_vless_reality_inbound_stream(inbound: &InboundObject) -> std::io::Result<()> {
    let stream = inbound.stream_settings.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VLESS REALITY inbound is missing streamSettings",
        )
    })?;

    validate_reality_stream_settings(stream)
}

pub fn find_vless_reality_inbounds(config: &XrayConfig) -> Vec<&InboundObject> {
    config
        .inbounds
        .iter()
        .filter(|inbound| is_vless_reality_inbound(inbound))
        .collect()
}

pub fn parse_inbound_port(port: Option<&InboundPortValue>) -> std::io::Result<u16> {
    let port = port.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "inbound.port is required for REALITY inbound",
        )
    })?;

    match port {
        InboundPortValue::Number(value) => Ok(*value),
        InboundPortValue::String(value) => {
            if value.contains('-') {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("port ranges are not supported for REALITY inbound: {value}"),
                ));
            }
            value.parse::<u16>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid inbound port string: {value:?}"),
                )
            })
        }
    }
}

pub fn format_listen_host(listen: Option<&str>) -> std::io::Result<String> {
    let listen = listen
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("0.0.0.0");

    if listen == "::" {
        return Ok("[::]".to_string());
    }
    if listen == "::1" || listen == "[::1]" {
        return Ok("[::1]".to_string());
    }
    if listen.starts_with('[') {
        if !listen.contains(']') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IPv6 listen address: {listen:?}"),
            ));
        }
        return Ok(listen.to_string());
    }
    if listen.contains(':') {
        return Ok(format!("[{listen}]"));
    }

    Ok(listen.to_string())
}

fn validate_vless_decryption(decryption: Option<&str>) -> std::io::Result<String> {
    match decryption.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok("none".to_string()),
        Some(value) if eq_ignore_ascii_case(value, "none") => Ok("none".to_string()),
        Some(value) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("unsupported VLESS decryption: {value}; only 'none' is supported"),
        )),
    }
}

pub fn load_xray_config_from_file(path: impl AsRef<Path>) -> std::io::Result<XrayConfig> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("failed to read config file {}: {e}", path.display()),
        )
    })?;

    serde_json::from_str(&contents).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse config file {}: {e}", path.display()),
        )
    })
}

pub fn find_reality_inbounds(config: &XrayConfig) -> Vec<&InboundObject> {
    find_vless_reality_inbounds(config)
        .into_iter()
        .filter(|inbound| validate_vless_reality_inbound_stream(inbound).is_ok())
        .collect()
}

pub fn is_supported_reality_tcp_inbound(inbound: &InboundObject) -> bool {
    is_vless_reality_inbound(inbound) && validate_vless_reality_inbound_stream(inbound).is_ok()
}

pub fn get_inbound_reality_settings(inbound: &InboundObject) -> Option<&RealitySettingsObject> {
    inbound
        .stream_settings
        .as_ref()
        .and_then(|stream| stream.reality_settings.as_ref())
}

pub fn inbound_vless_settings(
    inbound: &InboundObject,
) -> std::io::Result<Option<VlessInboundSettings>> {
    if !is_vless_protocol(inbound.protocol.as_deref()) {
        return Ok(None);
    }

    let settings = inbound.settings.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vless inbound settings are required",
        )
    })?;

    let settings: VlessInboundSettings = serde_json::from_value(settings.clone()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse vless inbound settings: {e}"),
        )
    })?;

    validate_vless_decryption(settings.decryption.as_deref())?;
    validate_fallback_configs(&settings.fallbacks)?;

    Ok(Some(settings))
}

pub fn inbound_listen_addr(inbound: &InboundObject) -> std::io::Result<String> {
    let host = format_listen_host(inbound.listen.as_deref())?;
    let port = parse_inbound_port(inbound.port.as_ref())?;
    Ok(format!("{host}:{port}"))
}

fn normalize_dest_addr(addr: &str) -> std::io::Result<String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "dest/target must not be empty",
        ));
    }

    if addr.starts_with('[') {
        let closing = addr.find(']').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IPv6 dest/target address: {addr:?}"),
            )
        })?;
        let host = &addr[..=closing];
        let remainder = &addr[closing + 1..];
        if remainder.is_empty() {
            return Ok(format!("{host}:{REALITY_DEFAULT_DEST_PORT}"));
        }
        if remainder.starts_with(':')
            && remainder[1..].parse::<u16>().is_ok()
            && remainder[1..].parse::<u16>().unwrap() > 0
        {
            return Ok(addr.to_string());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid IPv6 dest/target address: {addr:?}"),
        ));
    }

    if let Some((host, port)) = addr.rsplit_once(':') {
        if !host.is_empty() && port.parse::<u16>().is_ok() {
            return Ok(addr.to_string());
        }
    }

    Ok(format!("{addr}:{REALITY_DEFAULT_DEST_PORT}"))
}

fn parse_dest_target_value(value: &Value, field: &str) -> std::io::Result<String> {
    match value {
        Value::String(addr) => normalize_dest_addr(addr),
        Value::Number(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("numeric realitySettings.{field} is not supported"),
        )),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("realitySettings.{field} must be a JSON string"),
        )),
    }
}

pub fn reality_dest_addr(settings: &RealitySettingsObject) -> std::io::Result<String> {
    match (&settings.dest, &settings.target) {
        (Some(_), Some(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.dest and realitySettings.target are mutually exclusive",
        )),
        (Some(dest), None) => parse_dest_target_value(dest, "dest"),
        (None, Some(target)) => parse_dest_target_value(target, "target"),
        (None, None) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.dest or realitySettings.target is required",
        )),
    }
}

pub fn reality_private_key(settings: &RealitySettingsObject) -> std::io::Result<&str> {
    match settings.private_key.as_deref() {
        Some(key) if !key.is_empty() => Ok(key),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.privateKey is required",
        )),
    }
}

pub fn reality_server_names(settings: &RealitySettingsObject) -> std::io::Result<Vec<String>> {
    if settings.server_names.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.serverNames must contain at least one server name",
        ));
    }

    for server_name in &settings.server_names {
        if server_name == "*" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "wildcard realitySettings.serverNames are not supported",
            ));
        }
    }

    Ok(settings.server_names.clone())
}

pub fn reality_short_ids(settings: &RealitySettingsObject) -> std::io::Result<Vec<Vec<u8>>> {
    settings
        .short_ids
        .iter()
        .map(|short_id| crate::reality::parse_short_id_hex(short_id))
        .collect()
}

pub fn first_reality_inbound_runtime(
    config: &XrayConfig,
) -> std::io::Result<RealityInboundRuntime> {
    let vless_reality_inbounds = find_vless_reality_inbounds(config);
    let inbounds = find_reality_inbounds(config);
    let inbound = inbounds.first().ok_or_else(|| {
        if let Some(inbound) = vless_reality_inbounds.first() {
            if let Err(err) = validate_vless_reality_inbound_stream(inbound) {
                return err;
            }
        }
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no supported VLESS TCP REALITY inbound found",
        )
    })?;

    if inbounds.len() > 1 {
        warn!(
            inbound_count = inbounds.len(),
            selected_tag = ?inbound.tag,
            "multiple supported VLESS TCP REALITY inbounds found; using the first match"
        );
    }

    let settings = get_inbound_reality_settings(inbound).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reality inbound is missing realitySettings",
        )
    })?;

    let vless_settings = inbound_vless_settings(inbound)?;
    let (vless_clients, vless_decryption, vless_fallbacks) = match vless_settings {
        Some(settings) => (
            settings.clients,
            settings
                .decryption
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| "none".to_string()),
            settings.fallbacks,
        ),
        None => (Vec::new(), "none".to_string(), Vec::new()),
    };

    let private_key = reality_private_key(settings)?.to_owned();
    crate::reality::validate_reality_private_key_b64(&private_key)?;
    crate::vless::validate_vless_client_flows(&vless_clients)?;
    crate::vless::build_vless_clients(&vless_clients).map(|_| ())?;

    Ok(RealityInboundRuntime {
        tag: inbound.tag.clone(),
        protocol: inbound.protocol.clone(),
        listen_addr: inbound_listen_addr(inbound)?,
        dest_addr: reality_dest_addr(settings)?,
        private_key,
        server_names: reality_server_names(settings)?,
        short_ids: reality_short_ids(settings)?,
        max_time_diff: settings.max_time_diff,
        min_client_ver: settings.min_client_ver.clone(),
        max_client_ver: settings.max_client_ver.clone(),
        show: settings.show,
        vless_clients,
        vless_decryption,
        vless_fallbacks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const TEST_REALITY_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";

    const MINIMAL_VLESS_REALITY: &str = r#"{
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.example.com:443",
                    "serverNames": ["www.example.com"],
                    "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                    "shortIds": ["", "0123456789abcdef"]
                },
                "sockopt": {"tcpFastOpen": true}
            },
            "sniffing": {"enabled": true}
        }],
        "outbounds": [{"protocol": "freedom"}],
        "unknownTopLevel": {"enabled": true}
    }"#;

    #[test]
    fn parse_config_without_inbounds_defaults_to_empty() {
        let json = r#"{"outbounds": [{"protocol": "freedom"}]}"#;

        let config: XrayConfig = serde_json::from_str(json).expect("parse config");

        assert!(config.inbounds.is_empty());
        assert!(find_reality_inbounds(&config).is_empty());

        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            "no supported VLESS TCP REALITY inbound found"
        );
    }

    #[test]
    fn parse_minimal_vless_reality_inbound() {
        let config: XrayConfig = serde_json::from_str(MINIMAL_VLESS_REALITY).expect("parse config");
        let inbounds = find_reality_inbounds(&config);

        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].protocol.as_deref(), Some("vless"));
        assert_eq!(inbound_listen_addr(inbounds[0]).unwrap(), "0.0.0.0:443");

        let settings = get_inbound_reality_settings(inbounds[0]).unwrap();
        assert_eq!(reality_dest_addr(settings).unwrap(), "www.example.com:443");
        assert_eq!(
            reality_private_key(settings).unwrap(),
            "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4"
        );
        assert_eq!(settings.server_names, vec!["www.example.com".to_string()]);
    }

    #[test]
    fn builds_first_reality_inbound_runtime() {
        let json = r#"{
            "inbounds": [{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "maxTimeDiff": 10000,
                        "shortIds": ["", "0123456789abcdef"]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();

        assert_eq!(runtime.tag.as_deref(), Some("reality-in"));
        assert_eq!(runtime.protocol.as_deref(), Some("vless"));
        assert_eq!(runtime.listen_addr, "127.0.0.1:443");
        assert_eq!(runtime.dest_addr, "www.example.com:443");
        assert_eq!(runtime.server_names, vec!["www.example.com".to_string()]);
        assert_eq!(
            runtime.short_ids,
            vec![
                Vec::<u8>::new(),
                vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
            ]
        );
        assert_eq!(runtime.max_time_diff, 10000);
        assert!(!runtime.show);
        assert_eq!(runtime.private_key, TEST_REALITY_PRIVATE_KEY);
        assert_eq!(runtime.vless_clients.len(), 1);
        assert_eq!(
            runtime.vless_clients[0].id,
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(runtime.vless_decryption, "none");
    }

    #[test]
    fn inbound_vless_settings_parses_fallback_dest_number() {
        let json = r#"{
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none",
                "fallbacks": [{"dest": 8080}]
            }
        }"#;

        let inbound: InboundObject = serde_json::from_str(json).unwrap();
        let settings = inbound_vless_settings(&inbound).unwrap().unwrap();

        assert_eq!(settings.fallbacks.len(), 1);
        assert_eq!(settings.fallbacks[0].dest.addr, "127.0.0.1:8080");
    }

    #[test]
    fn inbound_vless_settings_parses_clients_and_decryption() {
        let json = r#"{
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "email": "user@example.com",
                    "flow": "xtls-rprx-vision",
                    "level": 0
                }],
                "decryption": "none",
                "fallbacks": []
            }
        }"#;

        let inbound: InboundObject = serde_json::from_str(json).unwrap();
        let settings = inbound_vless_settings(&inbound).unwrap().unwrap();

        assert_eq!(settings.clients.len(), 1);
        assert_eq!(
            settings.clients[0].id,
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            settings.clients[0].email.as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            settings.clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );
        assert_eq!(settings.decryption.as_deref(), Some("none"));
        assert!(settings.fallbacks.is_empty());
        assert!(settings.clients[0].extra.contains_key("level"));
    }

    #[test]
    fn inbound_vless_settings_returns_none_for_non_vless_protocol() {
        let json = r#"{
            "protocol": "trojan",
            "settings": {"clients": []}
        }"#;

        let inbound: InboundObject = serde_json::from_str(json).unwrap();

        assert!(inbound_vless_settings(&inbound).unwrap().is_none());
    }

    #[test]
    fn inbound_vless_settings_requires_settings_for_vless() {
        let inbound = InboundObject {
            tag: None,
            listen: None,
            port: None,
            protocol: Some("vless".to_string()),
            settings: None,
            stream_settings: None,
            extra: BTreeMap::new(),
        };

        let err = inbound_vless_settings(&inbound).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn builds_first_reality_inbound_runtime_with_policy_fields() {
        let json = r#"{
            "inbounds": [{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "show": true,
                        "dest": "www.example.com:443",
                        "serverNames": ["Example.COM"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "minClientVer": "1.8.0",
                        "maxClientVer": "24.9.30",
                        "maxTimeDiff": 5000,
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();

        assert_eq!(runtime.tag.as_deref(), Some("reality-in"));
        assert_eq!(runtime.protocol.as_deref(), Some("vless"));
        assert_eq!(runtime.server_names, vec!["Example.COM".to_string()]);
        assert_eq!(runtime.min_client_ver.as_deref(), Some("1.8.0"));
        assert_eq!(runtime.max_client_ver.as_deref(), Some("24.9.30"));
        assert_eq!(runtime.max_time_diff, 5000);
        assert!(runtime.show);
    }

    #[test]
    fn parse_reality_settings_supports_target_alias() {
        let json = r#"{
            "inbounds": [{
                "port": 8443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "target": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
        assert_eq!(reality_dest_addr(settings).unwrap(), "example.com:443");
    }

    #[test]
    fn parse_reality_settings_rejects_dest_and_target_together() {
        let json = r#"{
            "inbounds": [{
                "port": 8443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "a.example.com:443",
                        "target": "b.example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
        let err = reality_dest_addr(settings).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn find_reality_inbounds_skips_non_reality_security() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "streamSettings": {
                    "security": "tls",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        assert!(find_reality_inbounds(&config).is_empty());
    }

    #[test]
    fn parse_preserves_unknown_fields_in_extra() {
        let config: XrayConfig = serde_json::from_str(MINIMAL_VLESS_REALITY).unwrap();

        assert!(config.extra.contains_key("unknownTopLevel"));
        assert!(config.inbounds[0].extra.contains_key("sniffing"));

        let stream = config.inbounds[0].stream_settings.as_ref().unwrap();
        assert!(stream.extra.contains_key("sockopt"));
        assert_eq!(
            stream.extra["sockopt"]["tcpFastOpen"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn parse_short_ids_empty_and_hex() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": ["", "0123456789abcdef"]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
        let short_ids = reality_short_ids(settings).unwrap();

        assert_eq!(short_ids.len(), 2);
        assert!(short_ids[0].is_empty());
        assert_eq!(
            short_ids[1],
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    const REALISTIC_XRAY_SERVER: &str =
        include_str!("../../scripts/live_reality_smoke/xray-compatible-server.fixture.json");

    #[test]
    fn parses_realistic_xray_vless_tcp_reality_server_config() {
        let config: XrayConfig =
            serde_json::from_str(REALISTIC_XRAY_SERVER).expect("parse realistic config");
        let runtime = first_reality_inbound_runtime(&config).expect("runtime");

        assert_eq!(runtime.listen_addr, "127.0.0.1:24443");
        assert_eq!(runtime.dest_addr, "www.microsoft.com:443");
        assert_eq!(runtime.vless_decryption, "none");
        assert!(config.extra.contains_key("log"));
        assert!(config.extra.contains_key("routing"));
        assert!(config.inbounds[0].extra.contains_key("sniffing"));
        assert!(config.inbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .extra
            .contains_key("sockopt"));
    }

    #[test]
    fn accepts_port_as_string() {
        let inbound: InboundObject =
            serde_json::from_str(r#"{"listen":"127.0.0.1","port":"443","protocol":"vless"}"#)
                .unwrap();
        assert_eq!(inbound_listen_addr(&inbound).unwrap(), "127.0.0.1:443");
    }

    #[test]
    fn rejects_port_range() {
        let inbound: InboundObject =
            serde_json::from_str(r#"{"listen":"127.0.0.1","port":"10000-20000"}"#).unwrap();
        let err = inbound_listen_addr(&inbound).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "port ranges are not supported for REALITY inbound: 10000-20000"
        );
    }

    #[test]
    fn formats_ipv6_listen_correctly() {
        assert_eq!(format_listen_host(Some("::")).unwrap(), "[::]");
        assert_eq!(format_listen_host(Some("::1")).unwrap(), "[::1]");
        assert_eq!(format_listen_host(Some("[::1]")).unwrap(), "[::1]");
        assert_eq!(
            inbound_listen_addr(&InboundObject {
                tag: None,
                listen: Some("::1".to_string()),
                port: Some(InboundPortValue::Number(24443)),
                protocol: None,
                settings: None,
                stream_settings: None,
                extra: BTreeMap::new(),
            })
            .unwrap(),
            "[::1]:24443"
        );
    }

    #[test]
    fn accepts_security_and_protocol_case_insensitively() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "protocol": "VLESS",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "security": "REALITY",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        assert_eq!(find_reality_inbounds(&config).len(), 1);
    }

    #[test]
    fn accepts_network_raw_as_tcp_compatible() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        assert_eq!(find_reality_inbounds(&config).len(), 1);
        assert!(validate_reality_transport_network(Some("raw")).is_ok());
        assert!(validate_reality_transport_network(Some("tcp")).is_ok());
        assert!(validate_reality_transport_network(None).is_ok());
    }

    fn vless_reality_inbound_json(network: &str) -> String {
        format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{"clients": [], "decryption": "none"}},
                "streamSettings": {{
                    "network": "{network}",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        )
    }

    #[test]
    fn validate_reality_transport_network_accepts_tcp_as_legacy_raw_alias() {
        assert!(validate_reality_transport_network(Some("tcp")).is_ok());
        assert!(validate_reality_transport_network(Some("TCP")).is_ok());
    }

    #[test]
    fn validate_reality_transport_network_accepts_raw() {
        assert!(validate_reality_transport_network(Some("raw")).is_ok());
        assert!(validate_reality_transport_network(Some("RAW")).is_ok());
    }

    #[test]
    fn validate_reality_transport_network_rejects_xhttp_as_unimplemented() {
        let err = validate_reality_transport_network(Some("xhttp")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "REALITY over XHTTP runtime is not implemented yet"
        );
    }

    #[test]
    fn validate_reality_transport_network_rejects_grpc_as_unimplemented() {
        let err = validate_reality_transport_network(Some("grpc")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "REALITY over gRPC runtime is not implemented yet"
        );
    }

    #[test]
    fn validate_reality_transport_network_rejects_websocket_variants() {
        for network in ["ws", "websocket", "WebSocket"] {
            let err = validate_reality_transport_network(Some(network)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("WebSocket"));
        }
    }

    #[test]
    fn validate_reality_transport_network_rejects_mkcp_httpupgrade_and_hysteria() {
        let cases = [
            (
                "mkcp",
                "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
            ),
            (
                "kcp",
                "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
            ),
            (
                "httpupgrade",
                "REALITY over HTTPUpgrade transport (network=httpupgrade) is not supported",
            ),
            (
                "hysteria",
                "REALITY over Hysteria transport (network=hysteria) is not supported",
            ),
        ];
        for (network, message) in cases {
            let err = validate_reality_transport_network(Some(network)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{network}");
            assert_eq!(err.to_string(), message, "{network}");
        }
    }

    #[test]
    fn validate_reality_stream_settings_skips_non_reality_security() {
        let stream = StreamSettingsObject {
            network: Some("ws".to_string()),
            security: Some("tls".to_string()),
            reality_settings: None,
            extra: BTreeMap::new(),
        };

        assert!(validate_reality_stream_settings(&stream).is_ok());
    }

    #[test]
    fn validate_reality_stream_settings_rejects_xhttp_with_reality_security() {
        let stream = StreamSettingsObject {
            network: Some("xhttp".to_string()),
            security: Some("reality".to_string()),
            reality_settings: None,
            extra: BTreeMap::new(),
        };

        let err = validate_reality_stream_settings(&stream).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "REALITY over XHTTP runtime is not implemented yet"
        );
    }

    #[test]
    fn validate_reality_stream_settings_accepts_raw_with_reality_security() {
        let stream = StreamSettingsObject {
            network: Some("raw".to_string()),
            security: Some("reality".to_string()),
            reality_settings: None,
            extra: BTreeMap::new(),
        };

        assert!(validate_reality_stream_settings(&stream).is_ok());
    }

    #[test]
    fn first_reality_inbound_runtime_rejects_xhttp_transport() {
        let config: XrayConfig =
            serde_json::from_str(&vless_reality_inbound_json("xhttp")).unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "REALITY over XHTTP runtime is not implemented yet"
        );
    }

    #[test]
    fn first_reality_inbound_runtime_rejects_grpc_transport() {
        let config: XrayConfig = serde_json::from_str(&vless_reality_inbound_json("grpc")).unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "REALITY over gRPC runtime is not implemented yet"
        );
    }

    #[test]
    fn first_reality_inbound_runtime_rejects_websocket_transport() {
        let config: XrayConfig = serde_json::from_str(&vless_reality_inbound_json("ws")).unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err
            .to_string()
            .contains("REALITY over WebSocket transport (network=ws) is not supported"));
    }

    #[test]
    fn skips_unsupported_ws_reality_inbound_and_selects_next_tcp() {
        let json = r#"{
            "inbounds": [
                {
                    "tag": "ws-reality",
                    "port": 8443,
                    "protocol": "vless",
                    "settings": {"clients": [], "decryption": "none"},
                    "streamSettings": {
                        "network": "ws",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "ws.example.com:443",
                            "serverNames": ["ws.example.com"],
                            "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                            "shortIds": [""]
                        }
                    }
                },
                {
                    "tag": "tcp-reality",
                    "port": 443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "tcp.example.com:443",
                            "serverNames": ["tcp.example.com"],
                            "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                            "shortIds": [""]
                        }
                    }
                }
            ]
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let inbounds = find_reality_inbounds(&config);
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].tag.as_deref(), Some("tcp-reality"));
        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert_eq!(runtime.dest_addr, "tcp.example.com:443");
    }

    #[test]
    fn dest_without_port_defaults_to_443() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        assert_eq!(reality_dest_addr(&settings).unwrap(), "example.com:443");
    }

    #[test]
    fn ipv6_dest_stays_bracketed() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "[2606:4700:4700::1111]:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        assert_eq!(
            reality_dest_addr(&settings).unwrap(),
            "[2606:4700:4700::1111]:443"
        );
    }

    #[test]
    fn rejects_wildcard_server_names() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["*"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        let err = reality_server_names(&settings).unwrap_err();
        assert!(err.to_string().contains("wildcard"));
    }

    #[test]
    fn rejects_empty_server_names_with_clear_error() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": [],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        let err = reality_server_names(&settings).unwrap_err();
        assert!(err
            .to_string()
            .contains("serverNames must contain at least one server name"));
    }

    #[test]
    fn accepts_uppercase_short_ids() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": ["0123456789ABCDEF"]
        }))
        .unwrap();
        assert_eq!(
            reality_short_ids(&settings).unwrap(),
            vec![vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]]
        );
    }

    #[test]
    fn rejects_odd_length_short_id() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": ["abc"]
        }))
        .unwrap();
        let err = reality_short_ids(&settings).unwrap_err();
        assert!(err.to_string().contains("abc"));
        assert!(err.to_string().contains("even"));
    }

    #[test]
    fn rejects_too_long_short_id() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": ["0123456789abcdef0"]
        }))
        .unwrap();
        let err = reality_short_ids(&settings).unwrap_err();
        assert!(err.to_string().contains("0123456789abcdef0"));
    }

    #[test]
    fn rejects_non_hex_short_id() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": ["012g"]
        }))
        .unwrap();
        let err = reality_short_ids(&settings).unwrap_err();
        assert!(err.to_string().contains("012g"));
    }

    #[test]
    fn defaults_missing_vless_decryption_to_none() {
        let inbound: InboundObject = serde_json::from_str(
            r#"{"protocol":"vless","settings":{"clients":[{"id":"00000000-0000-0000-0000-000000000001"}]}}"#,
        )
        .unwrap();
        let settings = inbound_vless_settings(&inbound).unwrap().unwrap();
        assert!(settings.decryption.is_none());

        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}]
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert_eq!(runtime.vless_decryption, "none");
    }

    #[test]
    fn rejects_decryption_other_than_none() {
        let inbound: InboundObject = serde_json::from_str(
            r#"{"protocol":"vless","settings":{"clients":[],"decryption":"auto"}}"#,
        )
        .unwrap();
        let err = inbound_vless_settings(&inbound).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn validates_client_uuid_at_runtime() {
        let invalid_id = "a".repeat(31);
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "{invalid_id}"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert!(err.to_string().contains("invalid VLESS client id"));
    }

    #[test]
    fn rejects_both_dest_and_target() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "a.example.com:443",
            "target": "b.example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        let err = reality_dest_addr(&settings).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            "realitySettings.dest and realitySettings.target are mutually exclusive"
        );
    }

    #[test]
    fn rejects_missing_dest_and_target() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        let err = reality_dest_addr(&settings).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            "realitySettings.dest or realitySettings.target is required"
        );
    }

    #[test]
    fn accepts_empty_short_id() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        assert_eq!(
            reality_short_ids(&settings).unwrap(),
            vec![Vec::<u8>::new()]
        );
    }

    #[test]
    fn preserves_client_flow_vision() {
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "flow": "xtls-rprx-vision"
                    }}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert_eq!(
            settings.clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );

        let runtime = first_reality_inbound_runtime(&config).expect("vision runtime");
        assert_eq!(
            runtime.vless_clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );
    }

    #[test]
    fn missing_flow_is_empty_or_none() {
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert!(settings.clients[0].flow.is_none());

        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert!(runtime.vless_clients[0].flow.is_none());
    }

    #[test]
    fn unknown_flow_returns_unsupported_at_runtime_validation() {
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "flow": "unknown-flow"
                    }}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert_eq!(settings.clients[0].flow.as_deref(), Some("unknown-flow"));

        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), "unsupported VLESS flow: unknown-flow");
    }

    #[test]
    fn vision_flow_runtime_accepts_when_implemented() {
        const VISION_FIXTURE: &str = include_str!(
            "../../scripts/live_reality_smoke/xray-compatible-server-vision.fixture.json"
        );
        let config: XrayConfig =
            serde_json::from_str(VISION_FIXTURE).expect("parse vision fixture");
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert_eq!(
            settings.clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );

        let runtime = first_reality_inbound_runtime(&config).expect("vision runtime");
        assert_eq!(
            runtime.vless_clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );
    }

    #[test]
    fn preserves_unknown_fields() {
        let json = r#"{
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "in",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "alterId": 0,
                        "customClientField": true
                    }],
                    "decryption": "none",
                    "fallbacks": [{"dest": 80}]
                },
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""],
                        "customRealityField": "keep"
                    },
                    "customStreamField": 1
                },
                "customInboundField": "keep"
            }],
            "routing": {"rules": []},
            "unknownTopLevel": true
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        assert!(config.extra.contains_key("log"));
        assert!(config.extra.contains_key("routing"));
        assert!(config.extra.contains_key("unknownTopLevel"));
        assert!(config.inbounds[0].extra.contains_key("customInboundField"));
        let stream = config.inbounds[0].stream_settings.as_ref().unwrap();
        assert!(stream.extra.contains_key("customStreamField"));
        let reality = stream.reality_settings.as_ref().unwrap();
        assert!(reality.extra.contains_key("customRealityField"));
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert_eq!(settings.fallbacks.len(), 1);
        assert_eq!(settings.fallbacks[0].dest.addr, "127.0.0.1:80");
        assert!(settings.clients[0].extra.contains_key("alterId"));
        assert!(settings.clients[0].extra.contains_key("customClientField"));
    }
}
