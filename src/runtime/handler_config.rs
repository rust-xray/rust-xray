//! Canonical HandlerService protobuf ↔ rust-xray runtime conversion.

use std::net::{Ipv4Addr, Ipv6Addr};

use base64::Engine;
use prost::Message;

use crate::api::proto::app::proxyman::{ReceiverConfig, SniffingConfig};
use crate::api::proto::common::net::{ip_or_domain, IpOrDomain, PortList, PortRange};
use crate::api::proto::common::protocol::User as ProtoUser;
use crate::api::proto::common::serial::TypedMessage;
use crate::api::proto::core::{InboundHandlerConfig, OutboundHandlerConfig};
use crate::api::proto::proxy::blackhole::Config as BlackholeConfig;
use crate::api::proto::proxy::freedom::Config as FreedomConfig;
use crate::api::proto::proxy::vless::inbound::Config as VlessInboundConfig;
use crate::api::proto::proxy::vless::Account;
use crate::api::proto::transport::internet::reality::Config as RealityConfig;
use crate::api::proto::transport::internet::splithttp::Config as SplitHttpConfig;
use crate::api::proto::transport::internet::StreamConfig;
use crate::config::xray::raw::{
    InboundObject, InboundPortValue, OutboundObject, RealitySettingsObject, StreamSettingsObject,
    VlessClientObject, VlessInboundSettings, XHttpSettings,
};
use crate::config::{normalize_vless_reality_inbound, VlessRealityInbound};
use crate::vless::user_manager::ManagedUser;

pub const RECEIVER_CONFIG_TYPE: &str = "xray.app.proxyman.ReceiverConfig";
#[allow(dead_code)]
pub const SENDER_CONFIG_TYPE: &str = "xray.app.proxyman.SenderConfig";
pub const VLESS_INBOUND_CONFIG_TYPE: &str = "xray.proxy.vless.inbound.Config";
pub const FREEDOM_CONFIG_TYPE: &str = "xray.proxy.freedom.Config";
pub const BLACKHOLE_CONFIG_TYPE: &str = "xray.proxy.blackhole.Config";
pub const REALITY_CONFIG_TYPE: &str = "xray.transport.internet.reality.Config";
pub const SPLITHHTTP_CONFIG_TYPE: &str = "xray.transport.internet.splithttp.Config";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerConfigError {
    InvalidArgument(String),
    Unsupported(String),
}

impl HandlerConfigError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }
}

impl std::fmt::Display for HandlerConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(message) | Self::Unsupported(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HandlerConfigError {}

fn decode_typed<T: Message + Default>(
    typed: &TypedMessage,
    expected: &str,
) -> Result<T, HandlerConfigError> {
    if typed.r#type.trim() != expected {
        return Err(HandlerConfigError::invalid(format!(
            "expected typed message {expected}, got {}",
            typed.r#type
        )));
    }
    T::decode(typed.value.as_slice())
        .map_err(|err| HandlerConfigError::invalid(format!("failed to decode {expected}: {err}")))
}

fn encode_typed<T: Message>(message: &T, type_name: &str) -> TypedMessage {
    TypedMessage {
        r#type: type_name.to_string(),
        value: message.encode_to_vec(),
    }
}

fn ip_or_domain_to_listen(value: &IpOrDomain) -> Result<String, HandlerConfigError> {
    match value.address.as_ref() {
        Some(ip_or_domain::Address::Ip(bytes)) if bytes.len() == 4 => {
            let octets: [u8; 4] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| HandlerConfigError::invalid("listen IPv4 address must be 4 bytes"))?;
            Ok(Ipv4Addr::from(octets).to_string())
        }
        Some(ip_or_domain::Address::Ip(bytes)) if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| HandlerConfigError::invalid("listen IPv6 address must be 16 bytes"))?;
            Ok(format!("[{}]", Ipv6Addr::from(octets)))
        }
        Some(ip_or_domain::Address::Domain(domain)) => Ok(domain.clone()),
        _ => Err(HandlerConfigError::invalid(
            "receiver listen address is required",
        )),
    }
}

fn listen_to_ip_or_domain(listen: &str) -> IpOrDomain {
    if let Ok(ip) = listen.parse::<std::net::IpAddr>() {
        IpOrDomain {
            address: Some(ip_or_domain::Address::Ip(match ip {
                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
            })),
        }
    } else {
        IpOrDomain {
            address: Some(ip_or_domain::Address::Domain(listen.to_string())),
        }
    }
}

fn port_from_list(port_list: &PortList) -> Result<u16, HandlerConfigError> {
    let range = port_list
        .range
        .first()
        .ok_or_else(|| HandlerConfigError::invalid("receiver port_list is required"))?;
    if range.from != range.to {
        return Err(HandlerConfigError::invalid(
            "rust-xray dynamic inbound requires a single port (From == To)",
        ));
    }
    u16::try_from(range.from)
        .map_err(|_| HandlerConfigError::invalid(format!("invalid inbound port: {}", range.from)))
}

fn port_list_from_port(port: u16) -> PortList {
    PortList {
        range: vec![PortRange {
            from: u32::from(port),
            to: u32::from(port),
        }],
    }
}

fn reality_private_key_b64(bytes: &[u8]) -> Result<String, HandlerConfigError> {
    if bytes.len() == 32 {
        return Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(HandlerConfigError::invalid(
        "REALITY private_key must be 32 raw bytes or base64url text",
    ))
}

fn reality_private_key_bytes(b64: &str) -> Result<Vec<u8>, HandlerConfigError> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|err| {
            HandlerConfigError::invalid(format!("invalid REALITY private_key: {err}"))
        })?;
    if decoded.len() != 32 {
        return Err(HandlerConfigError::invalid(format!(
            "invalid REALITY private_key length: expected 32 bytes, got {}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn version_bytes_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| Some(String::from_utf8_lossy(bytes).into_owned()))
}

fn version_string_to_bytes(value: Option<&str>) -> Vec<u8> {
    value.unwrap_or("").as_bytes().to_vec()
}

fn short_id_bytes_to_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn reality_settings_from_proto(
    config: &RealityConfig,
) -> Result<RealitySettingsObject, HandlerConfigError> {
    Ok(RealitySettingsObject {
        show: config.show,
        dest: Some(serde_json::Value::String(config.dest.clone())),
        target: None,
        transport_type: if config.r#type.is_empty() {
            None
        } else {
            Some(config.r#type.clone())
        },
        xver: config.xver,
        server_names: config.server_names.clone(),
        private_key: Some(reality_private_key_b64(&config.private_key)?),
        min_client_ver: version_bytes_to_string(&config.min_client_ver),
        max_client_ver: version_bytes_to_string(&config.max_client_ver),
        max_time_diff: config.max_time_diff,
        short_ids: config
            .short_ids
            .iter()
            .map(|bytes| short_id_bytes_to_hex(bytes))
            .collect(),
        mldsa65_seed: if config.mldsa65_seed.is_empty() {
            None
        } else {
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&config.mldsa65_seed))
        },
        limit_fallback_upload: config
            .limit_fallback_upload
            .as_ref()
            .map(|value| crate::config::LimitFallback {
                after_bytes: value.after_bytes,
                bytes_per_sec: value.bytes_per_sec,
                burst_bytes_per_sec: value.burst_bytes_per_sec,
            })
            .unwrap_or_default(),
        limit_fallback_download: config
            .limit_fallback_download
            .as_ref()
            .map(|value| crate::config::LimitFallback {
                after_bytes: value.after_bytes,
                bytes_per_sec: value.bytes_per_sec,
                burst_bytes_per_sec: value.burst_bytes_per_sec,
            })
            .unwrap_or_default(),
        extra: Default::default(),
    })
}

fn xhttp_settings_from_proto(config: &SplitHttpConfig) -> XHttpSettings {
    XHttpSettings {
        path: config.path.clone(),
        host: (!config.host.is_empty()).then_some(config.host.clone()),
        mode: if config.mode.is_empty() {
            None
        } else {
            Some(config.mode.clone())
        },
        ..XHttpSettings::default()
    }
}

fn stream_settings_from_proto(
    stream: &StreamConfig,
) -> Result<StreamSettingsObject, HandlerConfigError> {
    let security = stream.security_type.trim();
    let protocol = stream.protocol_name.to_ascii_lowercase();
    let network = match protocol.as_str() {
        "tcp" | "raw" => "raw".to_string(),
        "splithttp" | "xhttp" => "xhttp".to_string(),
        other => {
            return Err(HandlerConfigError::unsupported(format!(
                "unsupported inbound transport protocol: {other}"
            )));
        }
    };

    if security.is_empty() || security.eq_ignore_ascii_case("none") {
        if !stream.security_settings.is_empty() {
            return Err(HandlerConfigError::invalid(
                "plain vless inbound must not include security_settings",
            ));
        }
        let xhttp_settings = None;
        if network == "xhttp" {
            return Err(HandlerConfigError::unsupported(
                "plain vless inbound does not support xhttp transport",
            ));
        }
        return Ok(StreamSettingsObject {
            network: Some(network),
            security: None,
            reality_settings: None,
            xhttp_settings,
            splithttp_settings: None,
            extra: Default::default(),
        });
    }

    if security != REALITY_CONFIG_TYPE {
        return Err(HandlerConfigError::unsupported(format!(
            "unsupported stream security type: {security}"
        )));
    }

    let reality_typed = stream
        .security_settings
        .iter()
        .find(|typed| typed.r#type == REALITY_CONFIG_TYPE)
        .ok_or_else(|| {
            HandlerConfigError::invalid("REALITY security_settings entry is required")
        })?;
    let reality = decode_typed::<RealityConfig>(reality_typed, REALITY_CONFIG_TYPE)?;

    let mut xhttp_settings = None;
    if network == "xhttp" {
        let xhttp_typed = stream
            .transport_settings
            .iter()
            .find(|entry| {
                entry.protocol_name.eq_ignore_ascii_case("splithttp")
                    || entry.protocol_name.eq_ignore_ascii_case("xhttp")
            })
            .and_then(|entry| entry.settings.as_ref())
            .ok_or_else(|| {
                HandlerConfigError::invalid("XHTTP transport_settings entry is required")
            })?;
        let xhttp = decode_typed::<SplitHttpConfig>(xhttp_typed, SPLITHHTTP_CONFIG_TYPE)?;
        xhttp_settings = Some(xhttp_settings_from_proto(&xhttp));
    }

    Ok(StreamSettingsObject {
        network: Some(network),
        security: Some("reality".to_string()),
        reality_settings: Some(reality_settings_from_proto(&reality)?),
        xhttp_settings,
        splithttp_settings: None,
        extra: Default::default(),
    })
}

fn vless_client_from_proto(user: &ProtoUser) -> Result<VlessClientObject, HandlerConfigError> {
    let account = user
        .account
        .as_ref()
        .ok_or_else(|| HandlerConfigError::invalid("vless user account is required"))?;
    if account.r#type.trim() != "xray.proxy.vless.Account" {
        return Err(HandlerConfigError::unsupported(format!(
            "unsupported vless user account type: {}",
            account.r#type
        )));
    }
    let vless = Account::decode(account.value.as_slice()).map_err(|err| {
        HandlerConfigError::invalid(format!("failed to decode vless account: {err}"))
    })?;
    Ok(VlessClientObject {
        id: vless.id,
        email: if user.email.is_empty() {
            None
        } else {
            Some(user.email.clone())
        },
        flow: if vless.flow.is_empty() {
            None
        } else {
            Some(vless.flow)
        },
        level: if user.level == 0 {
            None
        } else {
            Some(user.level)
        },
        extra: Default::default(),
    })
}

fn inbound_object_from_handler_config(
    config: &InboundHandlerConfig,
) -> Result<InboundObject, HandlerConfigError> {
    if config.tag.trim().is_empty() {
        return Err(HandlerConfigError::invalid("inbound tag is required"));
    }

    let receiver = config
        .receiver_settings
        .as_ref()
        .ok_or_else(|| HandlerConfigError::invalid("receiver_settings is required"))?;
    let receiver = decode_typed::<ReceiverConfig>(receiver, RECEIVER_CONFIG_TYPE)?;

    let listen = receiver
        .listen
        .as_ref()
        .map(ip_or_domain_to_listen)
        .transpose()?
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let port_list = receiver
        .port_list
        .as_ref()
        .ok_or_else(|| HandlerConfigError::invalid("receiver port_list is required"))?;
    let port = port_from_list(port_list)?;

    let proxy = config
        .proxy_settings
        .as_ref()
        .ok_or_else(|| HandlerConfigError::invalid("proxy_settings is required"))?;
    let proxy = decode_typed::<VlessInboundConfig>(proxy, VLESS_INBOUND_CONFIG_TYPE)?;

    let stream = receiver
        .stream_settings
        .as_ref()
        .ok_or_else(|| HandlerConfigError::invalid("receiver stream_settings is required"))?;

    let clients = proxy
        .users
        .iter()
        .map(vless_client_from_proto)
        .collect::<Result<Vec<_>, _>>()?;

    let settings = VlessInboundSettings {
        clients: clients.clone(),
        flow: None,
        decryption: if proxy.decryption.is_empty() {
            None
        } else {
            Some(proxy.decryption)
        },
        fallbacks: proxy
            .fallbacks
            .iter()
            .map(|fallback| {
                Ok(crate::vless::FallbackConfig {
                    name: if fallback.name.is_empty() {
                        None
                    } else {
                        Some(fallback.name.clone())
                    },
                    alpn: if fallback.alpn.is_empty() {
                        None
                    } else {
                        Some(fallback.alpn.clone())
                    },
                    path: if fallback.path.is_empty() {
                        None
                    } else {
                        Some(fallback.path.clone())
                    },
                    dest: crate::vless::parse_fallback_dest(&serde_json::Value::String(
                        fallback.dest.clone(),
                    ))
                    .map_err(|err| {
                        HandlerConfigError::invalid(format!("invalid vless fallback dest: {err}"))
                    })?,
                    xver: u8::try_from(fallback.xver).unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        extra: Default::default(),
    };

    let fallbacks_json: Vec<serde_json::Value> = settings
        .fallbacks
        .iter()
        .map(|fallback| {
            serde_json::json!({
                "name": fallback.name,
                "alpn": fallback.alpn,
                "path": fallback.path,
                "dest": fallback.dest.addr,
                "xver": fallback.xver,
            })
        })
        .collect();

    Ok(InboundObject {
        tag: Some(config.tag.clone()),
        listen: Some(listen),
        port: Some(InboundPortValue::Number(port)),
        protocol: Some("vless".to_string()),
        settings: Some(serde_json::json!({
            "clients": clients.iter().map(|client| {
                serde_json::json!({
                    "id": client.id,
                    "email": client.email,
                    "flow": client.flow,
                    "level": client.level,
                })
            }).collect::<Vec<_>>(),
            "decryption": settings.decryption,
            "fallbacks": fallbacks_json,
        })),
        stream_settings: Some(stream_settings_from_proto(stream)?),
        extra: if receiver
            .sniffing_settings
            .as_ref()
            .is_some_and(|sniffing| sniffing.enabled)
        {
            std::collections::BTreeMap::from([(
                "sniffing".to_string(),
                serde_json::json!({"enabled": true}),
            )])
        } else {
            Default::default()
        },
    })
}

/// Decoded HandlerService inbound runtime model.
#[derive(Debug, Clone)]
pub struct DecodedInboundHandler {
    pub inbound: VlessRealityInbound,
    pub plain_vless: bool,
}

/// Decode canonical HandlerService inbound config into rust-xray runtime model.
pub fn decode_inbound_handler_config(
    config: &InboundHandlerConfig,
) -> Result<DecodedInboundHandler, HandlerConfigError> {
    let inbound = inbound_object_from_handler_config(config)?;
    let security = inbound
        .stream_settings
        .as_ref()
        .and_then(|stream| stream.security.as_deref())
        .unwrap_or("");
    if security.is_empty() || security.eq_ignore_ascii_case("none") {
        let inbound = crate::config::normalize_vless_plain_tcp_inbound(&inbound)
            .map_err(|err| HandlerConfigError::invalid(err.to_string()))?;
        return Ok(DecodedInboundHandler {
            inbound,
            plain_vless: true,
        });
    }
    let inbound = normalize_vless_reality_inbound(&inbound)
        .map_err(|err| HandlerConfigError::invalid(err.to_string()))?;
    Ok(DecodedInboundHandler {
        inbound,
        plain_vless: false,
    })
}

fn managed_user_to_proto(user: &ManagedUser) -> ProtoUser {
    let account = Account {
        id: user.id.to_string(),
        flow: user.flow.clone().unwrap_or_default(),
        encryption: "none".to_string(),
        ..Default::default()
    };
    ProtoUser {
        level: user.level.unwrap_or(0),
        email: user.email.clone(),
        account: Some(encode_typed(&account, "xray.proxy.vless.Account")),
    }
}

fn reality_config_from_runtime(
    inbound: &VlessRealityInbound,
) -> Result<RealityConfig, HandlerConfigError> {
    let private_key = reality_private_key_bytes(&inbound.reality.private_key)?;
    Ok(RealityConfig {
        show: inbound.reality.show,
        dest: inbound.reality.dest_addr.clone(),
        r#type: match inbound.reality.dest_transport {
            crate::reality::RealityDestTransport::Tcp => "tcp".to_string(),
            #[cfg(unix)]
            crate::reality::RealityDestTransport::Unix => "unix".to_string(),
        },
        xver: u64::from(inbound.reality.dest_xver),
        server_names: inbound.reality.server_names.clone(),
        private_key,
        min_client_ver: version_string_to_bytes(inbound.reality.min_client_ver.as_deref()),
        max_client_ver: version_string_to_bytes(inbound.reality.max_client_ver.as_deref()),
        max_time_diff: inbound.reality.max_time_diff,
        short_ids: inbound.reality.short_ids.clone(),
        mldsa65_seed: inbound
            .reality
            .mldsa65_seed
            .map(|seed| seed.to_vec())
            .unwrap_or_default(),
        limit_fallback_upload: Some(
            crate::api::proto::transport::internet::reality::LimitFallback {
                after_bytes: inbound.reality.limit_fallback_upload.after_bytes,
                bytes_per_sec: inbound.reality.limit_fallback_upload.bytes_per_sec,
                burst_bytes_per_sec: inbound.reality.limit_fallback_upload.burst_bytes_per_sec,
            },
        ),
        limit_fallback_download: Some(
            crate::api::proto::transport::internet::reality::LimitFallback {
                after_bytes: inbound.reality.limit_fallback_download.after_bytes,
                bytes_per_sec: inbound.reality.limit_fallback_download.bytes_per_sec,
                burst_bytes_per_sec: inbound.reality.limit_fallback_download.burst_bytes_per_sec,
            },
        ),
        ..Default::default()
    })
}

fn stream_config_from_runtime(
    inbound: &VlessRealityInbound,
) -> Result<StreamConfig, HandlerConfigError> {
    let reality = reality_config_from_runtime(inbound)?;
    let protocol_name = match &inbound.transport {
        crate::config::InboundTransportConfig::RawTcp => "tcp".to_string(),
        crate::config::InboundTransportConfig::XHttp(xhttp) => {
            let mut stream = StreamConfig {
                protocol_name: "splithttp".to_string(),
                security_type: REALITY_CONFIG_TYPE.to_string(),
                security_settings: vec![encode_typed(&reality, REALITY_CONFIG_TYPE)],
                ..Default::default()
            };
            let xhttp_cfg = SplitHttpConfig {
                path: xhttp.path.clone(),
                host: xhttp.host.clone().unwrap_or_default(),
                mode: xhttp.mode.clone(),
                ..Default::default()
            };
            stream.transport_settings.push(
                crate::api::proto::transport::internet::TransportConfig {
                    protocol_name: "splithttp".to_string(),
                    settings: Some(encode_typed(&xhttp_cfg, SPLITHHTTP_CONFIG_TYPE)),
                },
            );
            return Ok(stream);
        }
    };

    Ok(StreamConfig {
        protocol_name,
        security_type: REALITY_CONFIG_TYPE.to_string(),
        security_settings: vec![encode_typed(&reality, REALITY_CONFIG_TYPE)],
        ..Default::default()
    })
}

fn listen_port_from_runtime(
    inbound: &VlessRealityInbound,
) -> Result<(String, u16), HandlerConfigError> {
    let (host, port) = inbound
        .listen_addr
        .rsplit_once(':')
        .ok_or_else(|| HandlerConfigError::invalid("invalid listen_addr"))?;
    let port = port
        .parse()
        .map_err(|_| HandlerConfigError::invalid("invalid listen port"))?;
    Ok((host.to_string(), port))
}

pub fn encode_plain_vless_inbound_handler_config(
    inbound: &VlessRealityInbound,
    users: &[ManagedUser],
) -> Result<InboundHandlerConfig, HandlerConfigError> {
    let tag = inbound
        .tag
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "vless-in".to_string());
    let (listen, port) = listen_port_from_runtime(inbound)?;
    let stream = StreamConfig {
        protocol_name: "tcp".to_string(),
        ..Default::default()
    };

    let receiver = ReceiverConfig {
        port_list: Some(port_list_from_port(port)),
        listen: Some(listen_to_ip_or_domain(&listen)),
        stream_settings: Some(stream),
        sniffing_settings: Some(SniffingConfig {
            enabled: inbound.sniffing_enabled,
            ..Default::default()
        }),
        ..Default::default()
    };

    let vless = VlessInboundConfig {
        users: users.iter().map(managed_user_to_proto).collect(),
        decryption: inbound.reality.decryption.clone(),
        ..Default::default()
    };

    Ok(InboundHandlerConfig {
        tag,
        receiver_settings: Some(encode_typed(&receiver, RECEIVER_CONFIG_TYPE)),
        proxy_settings: Some(encode_typed(&vless, VLESS_INBOUND_CONFIG_TYPE)),
    })
}

/// Encode live inbound runtime state into canonical HandlerService config.
pub fn encode_inbound_handler_config(
    inbound: &VlessRealityInbound,
    users: &[ManagedUser],
) -> Result<InboundHandlerConfig, HandlerConfigError> {
    let tag = inbound
        .tag
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "reality-in".to_string());
    let (listen, port) = listen_port_from_runtime(inbound)?;
    let stream = stream_config_from_runtime(inbound)?;

    let receiver = ReceiverConfig {
        port_list: Some(port_list_from_port(port)),
        listen: Some(listen_to_ip_or_domain(&listen)),
        stream_settings: Some(stream),
        sniffing_settings: Some(SniffingConfig {
            enabled: inbound.sniffing_enabled,
            ..Default::default()
        }),
        ..Default::default()
    };

    let vless = VlessInboundConfig {
        users: users.iter().map(managed_user_to_proto).collect(),
        decryption: inbound.reality.decryption.clone(),
        ..Default::default()
    };

    Ok(InboundHandlerConfig {
        tag,
        receiver_settings: Some(encode_typed(&receiver, RECEIVER_CONFIG_TYPE)),
        proxy_settings: Some(encode_typed(&vless, VLESS_INBOUND_CONFIG_TYPE)),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundProtocol {
    Freedom,
    Blackhole,
    Commander,
}

impl OutboundProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Freedom => "freedom",
            Self::Blackhole => "blackhole",
            Self::Commander => "commander",
        }
    }
}

pub fn decode_outbound_handler_config(
    config: &OutboundHandlerConfig,
) -> Result<(OutboundProtocol, OutboundHandlerConfig), HandlerConfigError> {
    if config.tag.trim().is_empty() {
        return Err(HandlerConfigError::invalid("outbound tag is required"));
    }
    let proxy = config
        .proxy_settings
        .as_ref()
        .ok_or_else(|| HandlerConfigError::invalid("proxy_settings is required"))?;

    let protocol = match proxy.r#type.trim() {
        FREEDOM_CONFIG_TYPE => {
            let _ = decode_typed::<FreedomConfig>(proxy, FREEDOM_CONFIG_TYPE)?;
            OutboundProtocol::Freedom
        }
        BLACKHOLE_CONFIG_TYPE => {
            let _ = decode_typed::<BlackholeConfig>(proxy, BLACKHOLE_CONFIG_TYPE)?;
            OutboundProtocol::Blackhole
        }
        other => {
            return Err(HandlerConfigError::unsupported(format!(
                "unsupported outbound protocol: {other}"
            )));
        }
    };

    Ok((protocol, config.clone()))
}

pub fn encode_commander_outbound(tag: &str) -> OutboundHandlerConfig {
    OutboundHandlerConfig {
        tag: tag.trim().to_string(),
        ..Default::default()
    }
}

pub fn encode_outbound_handler_config(
    tag: &str,
    protocol: OutboundProtocol,
) -> OutboundHandlerConfig {
    if matches!(protocol, OutboundProtocol::Commander) {
        return encode_commander_outbound(tag);
    }
    let proxy = match protocol {
        OutboundProtocol::Freedom => encode_typed(&FreedomConfig::default(), FREEDOM_CONFIG_TYPE),
        OutboundProtocol::Blackhole => {
            encode_typed(&BlackholeConfig::default(), BLACKHOLE_CONFIG_TYPE)
        }
        OutboundProtocol::Commander => unreachable!("handled above"),
    };
    OutboundHandlerConfig {
        tag: tag.to_string(),
        sender_settings: None,
        proxy_settings: Some(proxy),
        ..Default::default()
    }
}

pub fn outbound_protocol_from_object(
    outbound: &OutboundObject,
) -> Result<OutboundProtocol, HandlerConfigError> {
    let protocol = outbound.protocol.as_deref().unwrap_or("").trim();
    if protocol.is_empty() {
        return Err(HandlerConfigError::invalid("outbound protocol is required"));
    }
    match protocol.to_ascii_lowercase().as_str() {
        "freedom" | "direct" => Ok(OutboundProtocol::Freedom),
        "blackhole" | "block" => Ok(OutboundProtocol::Blackhole),
        other => Err(HandlerConfigError::unsupported(format!(
            "unsupported outbound protocol: {other}"
        ))),
    }
}

pub fn encode_outbound_from_startup(
    outbound: &OutboundObject,
) -> Result<OutboundHandlerConfig, HandlerConfigError> {
    let tag = outbound
        .tag
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "direct".to_string());
    let protocol = outbound_protocol_from_object(outbound)?;
    Ok(encode_outbound_handler_config(&tag, protocol))
}

#[cfg(test)]
#[path = "../../tests/unit/runtime/handler_config.rs"]
mod tests;
