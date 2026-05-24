use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct XrayConfig {
    pub inbounds: Vec<InboundObject>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboundObject {
    pub tag: Option<String>,
    pub listen: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub settings: Option<Value>,
    #[serde(rename = "streamSettings")]
    pub stream_settings: Option<StreamSettingsObject>,

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
    config
        .inbounds
        .iter()
        .filter(|inbound| {
            inbound
                .stream_settings
                .as_ref()
                .is_some_and(|stream| stream.security.as_deref() == Some("reality"))
                && inbound
                    .stream_settings
                    .as_ref()
                    .and_then(|stream| stream.reality_settings.as_ref())
                    .is_some()
        })
        .collect()
}

pub fn get_inbound_reality_settings(inbound: &InboundObject) -> Option<&RealitySettingsObject> {
    inbound
        .stream_settings
        .as_ref()
        .and_then(|stream| stream.reality_settings.as_ref())
}

pub fn inbound_listen_addr(inbound: &InboundObject) -> std::io::Result<String> {
    let listen = inbound.listen.as_deref().unwrap_or("0.0.0.0");
    let port = inbound.port.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "inbound port is required")
    })?;

    Ok(format!("{listen}:{port}"))
}

fn parse_dest_target_value(value: &Value) -> std::io::Result<String> {
    match value {
        Value::String(addr) => Ok(addr.clone()),
        Value::Number(number) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "numeric dest/target ({number}) is not supported yet; use a string like \"example.com:443\""
            ),
        )),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "dest/target must be a JSON string",
        )),
    }
}

pub fn reality_dest_addr(settings: &RealitySettingsObject) -> std::io::Result<String> {
    match (&settings.dest, &settings.target) {
        (Some(_), Some(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings must not set both dest and target; target is an alias for dest",
        )),
        (Some(dest), None) => parse_dest_target_value(dest),
        (None, Some(target)) => parse_dest_target_value(target),
        (None, None) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings dest or target is required",
        )),
    }
}

pub fn reality_private_key(settings: &RealitySettingsObject) -> std::io::Result<&str> {
    match settings.private_key.as_deref() {
        Some(key) if !key.is_empty() => Ok(key),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings privateKey is required",
        )),
    }
}

pub fn reality_short_ids(settings: &RealitySettingsObject) -> std::io::Result<Vec<Vec<u8>>> {
    settings
        .short_ids
        .iter()
        .map(|short_id| crate::reality::parse_short_id_hex(short_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_VLESS_REALITY: &str = r#"{
        "inbounds": [{
            "tag": "reality-in",
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
}
