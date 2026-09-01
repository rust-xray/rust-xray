use tracing::warn;

use super::raw::{InboundObject, InboundPortValue, RealitySettingsObject, StreamSettingsObject};
use super::transport::{validate_reality_transport_network, TransportNetwork};
use crate::reality::parse_reality_client_version;
use crate::vless::encryption::VlessDecryption;
use crate::vless::validate_inbound_decryption_with_fallbacks;
use crate::vless::FallbackConfig;

pub(crate) fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

pub(crate) fn is_vless_protocol(protocol: Option<&str>) -> bool {
    protocol.is_some_and(|value| eq_ignore_ascii_case(value, "vless"))
}

pub(crate) fn is_reality_security(security: Option<&str>) -> bool {
    security.is_some_and(|value| eq_ignore_ascii_case(value, "reality"))
}

pub fn is_vless_reality_inbound(inbound: &InboundObject) -> bool {
    inbound.stream_settings.as_ref().is_some_and(|stream| {
        is_vless_protocol(inbound.protocol.as_deref())
            && is_reality_security(stream.security.as_deref())
            && stream.reality_settings.is_some()
    })
}

/// Validate `streamSettings.network` when `streamSettings.security` is REALITY.
pub fn validate_reality_stream_settings(stream: &StreamSettingsObject) -> std::io::Result<()> {
    if !is_reality_security(stream.security.as_deref()) {
        return Ok(());
    }

    validate_reality_transport_network(stream.network.as_deref())
}

/// Client-outbound REALITY fields that panels may leak into inbound server `realitySettings`.
const REALITY_CLIENT_ONLY_INBOUND_FIELDS: &[&str] = &[
    "fingerprint",
    "serverName",
    "password",
    "publicKey",
    "shortId",
    "mldsa65Verify",
    "spiderX",
    "spiderY",
    "masterKeyLog",
];

/// `streamSettings` sub-objects that are not implemented for REALITY inbound (misconfiguration risk).
///
/// `sockopt` is intentionally allowed so Xray-compatible smoke fixtures keep validating.
const REALITY_UNSUPPORTED_STREAM_SUBOBJECTS: &[&str] = &[
    "tlsSettings",
    "rawSettings",
    "tcpSettings",
    "wsSettings",
    "grpcSettings",
    "kcpSettings",
    "httpupgradeSettings",
    "hysteriaSettings",
    "finalmask",
    "address",
    "port",
];

/// Validate parsed-but-unsupported REALITY inbound fields at startup.
pub fn validate_reality_inbound_config_policy(
    stream: &StreamSettingsObject,
    settings: &RealitySettingsObject,
) -> std::io::Result<()> {
    for field in REALITY_CLIENT_ONLY_INBOUND_FIELDS {
        if settings.extra.contains_key(*field) {
            warn!(
                field,
                "ignoring client-only realitySettings field on inbound REALITY server config"
            );
        }
    }

    for field in REALITY_UNSUPPORTED_STREAM_SUBOBJECTS {
        if stream.extra.contains_key(*field) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("streamSettings.{field} is not supported on REALITY inbound"),
            ));
        }
    }

    match TransportNetwork::parse(stream.network.as_deref())? {
        TransportNetwork::RawTcp => {
            if stream.xhttp_settings.is_some() || stream.splithttp_settings.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "streamSettings.xhttpSettings is only supported when network=xhttp/splithttp",
                ));
            }
        }
        TransportNetwork::XHttp => {
            let settings = stream
                .xhttp_settings
                .as_ref()
                .or(stream.splithttp_settings.as_ref());
            if let Some(settings) = settings {
                crate::transport::xhttp::configured_xhttp_mode(settings.mode.as_deref())?;
            }
        }
    }

    validate_reality_client_version_settings(settings)?;

    Ok(())
}

fn validate_reality_client_version_settings(
    settings: &RealitySettingsObject,
) -> std::io::Result<()> {
    if let Some(min) = settings
        .min_client_ver
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        parse_reality_client_version(min).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("realitySettings.minClientVer is invalid: {err}"),
            )
        })?;
    }

    if let Some(max) = settings
        .max_client_ver
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        parse_reality_client_version(max).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("realitySettings.maxClientVer is invalid: {err}"),
            )
        })?;
    }

    Ok(())
}

pub(crate) fn validate_vless_reality_inbound_stream(
    inbound: &InboundObject,
) -> std::io::Result<()> {
    let stream = inbound.stream_settings.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VLESS REALITY inbound is missing streamSettings",
        )
    })?;

    validate_reality_stream_settings(stream)?;

    if let Some(settings) = stream.reality_settings.as_ref() {
        validate_reality_inbound_config_policy(stream, settings)?;
    }

    Ok(())
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

pub(crate) fn validate_vless_decryption(
    decryption: Option<&str>,
    fallbacks: &[FallbackConfig],
) -> std::io::Result<VlessDecryption> {
    validate_inbound_decryption_with_fallbacks(decryption, !fallbacks.is_empty()).map_err(|err| {
        std::io::Error::new(
            if err.to_string().contains("unsupported") {
                std::io::ErrorKind::Unsupported
            } else {
                std::io::ErrorKind::InvalidInput
            },
            err.to_string(),
        )
    })
}
