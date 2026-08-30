use serde_json::Value;

use super::api_listen::{
    api_listen_kind, is_internal_commander_listen, parse_api_tcp_listen_addr, ApiListenKind,
};

use super::raw::{InboundObject, RoutingRuleObject, XrayConfig};
use super::reality::inbound_listen_addr;
use super::validate::eq_ignore_ascii_case;

/// Known Xray API `services` entries (Remna panels typically enable Handler + Stats).
pub const KNOWN_API_SERVICES: &[&str] = &[
    "ReflectionService",
    "HandlerService",
    "LoggerService",
    "StatsService",
    "ObservatoryService",
    "RoutingService",
];

fn find_api_inbound<'a>(config: &'a XrayConfig, api_tag: &str) -> Option<&'a InboundObject> {
    find_api_inbound_with_source(config, api_tag)
        .ok()
        .map(|(inbound, _)| inbound)
}

fn is_api_routed_inbound_protocol(protocol: &str) -> bool {
    eq_ignore_ascii_case(protocol, "dokodemo-door") || eq_ignore_ascii_case(protocol, "tunnel")
}

fn validate_api_inbound_protocol(inbound: &InboundObject, api_tag: &str) -> std::io::Result<()> {
    if let Some(protocol) = inbound.protocol.as_deref() {
        if !is_api_routed_inbound_protocol(protocol) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "api inbound {:?} uses unsupported protocol {protocol}; expected dokodemo-door or tunnel",
                    api_tag
                ),
            ));
        }
    }

    Ok(())
}

/// Resolve listen address for routed API inbounds (`tunnel`, `dokodemo-door`).
///
/// Unix socket inbounds use `@abstract` or filesystem paths without `:port`.
pub fn api_inbound_listen_addr(inbound: &InboundObject) -> std::io::Result<String> {
    let listen = inbound
        .listen
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(listen) = listen {
        if listen.starts_with('@') {
            if listen.len() <= 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "abstract unix inbound listen must include a name after @",
                ));
            }
            return Ok(listen.to_string());
        }
        if listen.starts_with('/') {
            return Ok(listen.to_string());
        }
    }
    inbound_listen_addr(inbound)
}

fn api_rule_inbound_tags(rule: &RoutingRuleObject) -> Vec<&str> {
    match rule.inbound_tag.as_ref() {
        Some(Value::String(tag)) => vec![tag.as_str()],
        Some(Value::Array(tags)) => tags.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// How the API listen address was resolved (for startup logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiListenSource {
    ApiListenField,
    InboundTagMatchesApiTag,
    RoutingRule,
    InternalCommander,
}

impl ApiListenSource {
    pub fn as_log_label(self) -> &'static str {
        match self {
            Self::ApiListenField => "api.listen",
            Self::InboundTagMatchesApiTag => "inbound.tag==api.tag",
            Self::RoutingRule => "routing.outboundTag==api.tag",
            Self::InternalCommander => "internal-commander",
        }
    }
}

/// PEM material for Remnawave-style mTLS on the API dokodemo-door inbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTlsMaterial {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
    pub server_name: Option<String>,
}

fn pem_bytes_from_json_value(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(text) => {
            let pem = text.replace("\\n", "\n");
            if pem.trim().is_empty() {
                None
            } else {
                Some(pem.into_bytes())
            }
        }
        Value::Array(lines) => {
            let joined = lines
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n");
            if joined.trim().is_empty() {
                None
            } else {
                Some(joined.into_bytes())
            }
        }
        _ => None,
    }
}

fn parse_tls_settings_certificates(
    tls_settings: &Value,
) -> std::io::Result<Option<ApiTlsMaterial>> {
    let Some(entries) = tls_settings.get("certificates").and_then(Value::as_array) else {
        return Ok(None);
    };

    let mut cert_pem = None;
    let mut key_pem = None;
    let mut ca_pem = None;

    for entry in entries {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let usage = obj
            .get("usage")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let certificate = obj.get("certificate").and_then(pem_bytes_from_json_value);
        if usage.is_some_and(|value| eq_ignore_ascii_case(value, "verify")) {
            if let Some(ca) = certificate {
                ca_pem = Some(ca);
            }
            continue;
        }
        if let Some(cert) = certificate {
            cert_pem = Some(cert);
        }
        if let Some(key) = obj.get("key").and_then(pem_bytes_from_json_value) {
            key_pem = Some(key);
        }
    }

    let (cert_pem, key_pem, ca_pem) = match (cert_pem, key_pem, ca_pem) {
        (Some(cert_pem), Some(key_pem), Some(ca_pem)) => (cert_pem, key_pem, ca_pem),
        _ => return Ok(None),
    };

    let server_name = tls_settings
        .get("serverName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    Ok(Some(ApiTlsMaterial {
        cert_pem,
        key_pem,
        ca_pem,
        server_name,
    }))
}

/// Parse Remnawave/Xray API inbound `streamSettings.tlsSettings` PEM material.
pub fn extract_tls_material_from_inbound(
    inbound: &InboundObject,
) -> std::io::Result<Option<ApiTlsMaterial>> {
    let Some(stream) = inbound.stream_settings.as_ref() else {
        return Ok(None);
    };
    if !stream
        .security
        .as_deref()
        .is_some_and(|value| eq_ignore_ascii_case(value, "tls"))
    {
        return Ok(None);
    }
    let Some(tls_settings) = stream.extra.get("tlsSettings") else {
        return Ok(None);
    };
    parse_tls_settings_certificates(tls_settings)
}

/// Extract API TLS material from the routed dokodemo-door inbound (if present).
pub fn extract_api_inbound_tls_material(
    config: &XrayConfig,
) -> std::io::Result<Option<ApiTlsMaterial>> {
    let Some(api) = config.api.as_ref() else {
        return Ok(None);
    };
    let Some(inbound) = find_api_inbound(config, api.tag.as_str()) else {
        return Ok(None);
    };
    extract_tls_material_from_inbound(inbound)
}

/// True when the resolved API listen address is localhost-only (`127.0.0.1:*`).
pub fn is_localhost_api_listen(listen: &str) -> bool {
    listen.trim().starts_with("127.0.0.1:")
}

/// Resolved API listen address and optional dokodemo-door inbound tag (legacy routed inbound).
pub fn resolve_api_listen(
    config: &XrayConfig,
) -> std::io::Result<Option<(String, ApiListenSource, Option<String>)>> {
    let Some(api) = config.api.as_ref() else {
        return Ok(None);
    };

    if is_internal_commander_listen(api.listen.as_deref()) {
        return Ok(None);
    }

    if let Some(listen) = api
        .listen
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Ok(Some((
            listen.to_string(),
            ApiListenSource::ApiListenField,
            None,
        )));
    }

    let (inbound, source) = find_api_inbound_with_source(config, api.tag.as_str())?;
    validate_api_inbound_protocol(inbound, api.tag.as_str())?;
    let listen = inbound_listen_addr(inbound)?;
    Ok(Some((listen, source, inbound.tag.clone())))
}

/// Tag of the dokodemo-door inbound used for API (if any).
fn routed_dokodemo_inbound_tags_for_api_outbound(
    config: &XrayConfig,
    api_tag: &str,
) -> Vec<String> {
    let Some(routing) = config.routing.as_ref() else {
        return Vec::new();
    };
    let mut tags = Vec::new();
    for rule in &routing.rules {
        if rule.outbound_tag.as_deref() != Some(api_tag) {
            continue;
        }
        for tag in api_rule_inbound_tags(rule) {
            if config.inbounds.iter().any(|inbound| {
                inbound.tag.as_deref() == Some(tag)
                    && inbound
                        .protocol
                        .as_deref()
                        .is_some_and(is_api_routed_inbound_protocol)
            }) {
                tags.push(tag.to_string());
            }
        }
    }
    tags.sort();
    tags.dedup();
    tags
}

pub fn api_dokodemo_inbound_tag(config: &XrayConfig) -> Option<String> {
    let api = config.api.as_ref()?;
    if api.listen.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        return None;
    }
    if is_internal_commander_listen(api.listen.as_deref()) {
        let routed = routed_dokodemo_inbound_tags_for_api_outbound(config, api.tag.as_str());
        return match routed.len() {
            0 => None,
            1 => Some(routed[0].clone()),
            _ => None,
        };
    }
    find_api_inbound(config, api.tag.as_str()).and_then(|inbound| inbound.tag.clone())
}

pub fn api_listen_addr(config: &XrayConfig) -> std::io::Result<Option<String>> {
    Ok(resolve_api_listen(config)?.map(|(listen, _, _)| listen))
}

fn find_api_inbound_with_source<'a>(
    config: &'a XrayConfig,
    api_tag: &str,
) -> std::io::Result<(&'a InboundObject, ApiListenSource)> {
    if let Some(inbound) = config
        .inbounds
        .iter()
        .find(|inbound| inbound.tag.as_deref() == Some(api_tag))
    {
        return Ok((inbound, ApiListenSource::InboundTagMatchesApiTag));
    }

    let routing = config.routing.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "API services configured for tag {:?} but no api.listen and no routed dokodemo-door API inbound was found",
                api_tag
            ),
        )
    })?;

    let mut matched_inbounds = Vec::new();
    for rule in &routing.rules {
        if rule.outbound_tag.as_deref() != Some(api_tag) {
            continue;
        }
        for tag in api_rule_inbound_tags(rule) {
            if let Some(inbound) = config
                .inbounds
                .iter()
                .find(|inbound| inbound.tag.as_deref() == Some(tag))
            {
                matched_inbounds.push(inbound);
            }
        }
    }

    matched_inbounds.sort_by_key(|inbound| inbound.tag.as_deref().unwrap_or(""));
    matched_inbounds.dedup_by_key(|inbound| inbound.tag.as_deref().unwrap_or(""));

    match matched_inbounds.len() {
        0 => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "API services configured for tag {:?} but no api.listen and no routed dokodemo-door API inbound was found",
                api_tag
            ),
        )),
        1 => Ok((
            matched_inbounds[0],
            ApiListenSource::RoutingRule,
        )),
        _ => {
            let tags: Vec<_> = matched_inbounds
                .iter()
                .filter_map(|inbound| inbound.tag.as_deref())
                .collect();
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "ambiguous API inbound routing for tag {:?}: multiple inbounds matched ({tags:?})",
                    api_tag
                ),
            ))
        }
    }
}

pub(crate) fn validate_api_config(config: &XrayConfig) -> std::io::Result<()> {
    if let Some(api) = config.api.as_ref() {
        if api.tag.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "API tag can't be empty.",
            ));
        }
        if let Some(listen) = api
            .listen
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            match api_listen_kind(Some(listen)) {
                ApiListenKind::Tcp => {
                    parse_api_tcp_listen_addr(listen)?;
                }
                ApiListenKind::UnixPath => {
                    if listen.len() <= 1 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "unix api.listen path must not be empty",
                        ));
                    }
                }
                #[cfg(all(unix, target_os = "linux"))]
                ApiListenKind::UnixAbstract => {
                    if listen.len() <= 1 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "abstract unix api.listen must include a name after @",
                        ));
                    }
                }
                ApiListenKind::InternalCommander => {}
            }
        }
    }

    Ok(())
}
