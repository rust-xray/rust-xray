use std::net::SocketAddr;

use serde::Deserialize;
use serde_json::Value;

use crate::protocol::structs::ClientHelloPayload;
use crate::reality::extract_sni_hostname;

const FALLBACK_LOCALHOST: &str = "127.0.0.1";

/// Xray-compatible VLESS/Trojan fallback entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FallbackConfig {
    pub name: Option<String>,
    pub alpn: Option<String>,
    pub path: Option<String>,
    pub dest: FallbackDest,
    #[serde(default)]
    pub xver: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackDest {
    pub addr: String,
}

impl<'de> Deserialize<'de> for FallbackDest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        parse_fallback_dest(&value).map_err(serde::de::Error::custom)
    }
}

/// Parsed inputs for fallback selection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FallbackContext {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub http_path: Option<String>,
}

impl FallbackConfig {
    pub fn is_default(&self) -> bool {
        self.name.is_none() && self.alpn.is_none() && self.path.is_none()
    }
}

pub fn parse_fallback_dest(value: &Value) -> std::io::Result<FallbackDest> {
    match value {
        Value::Number(number) => {
            let port = number.as_u64().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "fallback dest port number must be unsigned integer",
                )
            })?;
            if port == 0 || port > u16::MAX as u64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("fallback dest port out of range: {port}"),
                ));
            }
            Ok(FallbackDest {
                addr: format!("{FALLBACK_LOCALHOST}:{port}"),
            })
        }
        Value::String(addr) => {
            let addr = addr.trim();
            if addr.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "fallback dest must not be empty",
                ));
            }
            if addr.starts_with('/') || addr.starts_with('@') {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("unix socket fallback dest is not supported: {addr:?}"),
                ));
            }
            Ok(FallbackDest {
                addr: normalize_host_port_dest(addr)?,
            })
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fallback dest must be a port number or host:port string",
        )),
    }
}

fn normalize_host_port_dest(addr: &str) -> std::io::Result<String> {
    if addr.starts_with('[') {
        let closing = addr.find(']').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IPv6 fallback dest: {addr:?}"),
            )
        })?;
        let _host = &addr[..=closing];
        let remainder = &addr[closing + 1..];
        if remainder.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("IPv6 fallback dest missing port: {addr:?}"),
            ));
        }
        if remainder.starts_with(':')
            && remainder[1..].parse::<u16>().is_ok()
            && remainder[1..].parse::<u16>().unwrap() > 0
        {
            return Ok(addr.to_string());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid IPv6 fallback dest: {addr:?}"),
        ));
    }

    if let Some((host, port)) = addr.rsplit_once(':') {
        if !host.is_empty() && port.parse::<u16>().is_ok() {
            return Ok(addr.to_string());
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid fallback dest address: {addr:?}"),
    ))
}

pub fn validate_fallback_configs(fallbacks: &[FallbackConfig]) -> std::io::Result<()> {
    for (index, fallback) in fallbacks.iter().enumerate() {
        validate_fallback_xver(fallback.xver).map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("fallbacks[{index}] xver invalid: {err}"),
            )
        })?;
        if fallback.dest.addr.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("fallbacks[{index}] dest must not be empty"),
            ));
        }
    }
    Ok(())
}

pub fn validate_fallback_xver(xver: u8) -> std::io::Result<()> {
    match xver {
        0 | 1 => Ok(()),
        2 => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "PROXY protocol v2 (xver=2) is not supported",
        )),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported fallback xver: {other}"),
        )),
    }
}

pub fn build_fallback_context(
    hello: Option<&ClientHelloPayload>,
    initial_bytes: &[u8],
) -> FallbackContext {
    let sni = hello.and_then(extract_sni_hostname);
    let alpn = hello.and_then(extract_client_alpn);
    let http_path = sniff_http_request_path(initial_bytes);
    FallbackContext {
        sni,
        alpn,
        http_path,
    }
}

pub fn extract_client_alpn(hello: &ClientHelloPayload) -> Option<String> {
    hello
        .alpn_extension()?
        .first()
        .and_then(|name| std::str::from_utf8(name.as_ref()).ok().map(str::to_string))
}

pub fn sniff_http_request_path(bytes: &[u8]) -> Option<String> {
    let line = extract_http_request_line(bytes)?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if !HTTP_METHODS.contains(&method) {
        return None;
    }
    let path = parts.next()?.to_string();
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    Some(path)
}

const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

fn extract_http_request_line(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == b'\n')?;
    let line = std::str::from_utf8(&bytes[..=end])
        .ok()?
        .trim_end_matches('\r');
    if line.is_empty() {
        return None;
    }
    Some(line)
}

pub fn looks_like_http_request(bytes: &[u8]) -> bool {
    sniff_http_request_path(bytes).is_some()
}

fn name_matches(fallback: &FallbackConfig, ctx: &FallbackContext) -> bool {
    match fallback.name.as_deref() {
        None => true,
        Some(expected) => ctx
            .sni
            .as_deref()
            .is_some_and(|sni| eq_ignore_ascii_case(sni, expected)),
    }
}

fn alpn_matches(fallback: &FallbackConfig, ctx: &FallbackContext) -> bool {
    match fallback.alpn.as_deref() {
        None => true,
        Some(expected) => ctx
            .alpn
            .as_deref()
            .is_some_and(|alpn| eq_ignore_ascii_case(alpn, expected)),
    }
}

fn path_matches(fallback: &FallbackConfig, ctx: &FallbackContext) -> bool {
    match fallback.path.as_deref() {
        None => true,
        Some(expected) => ctx
            .http_path
            .as_deref()
            .is_some_and(|path| path == expected || path.starts_with(expected)),
    }
}

fn matches_name_alpn(fallback: &FallbackConfig, ctx: &FallbackContext) -> bool {
    name_matches(fallback, ctx) && alpn_matches(fallback, ctx)
}

fn matches_with_path(fallback: &FallbackConfig, ctx: &FallbackContext) -> bool {
    fallback.path.is_some() && matches_name_alpn(fallback, ctx) && path_matches(fallback, ctx)
}

fn matches_without_path(fallback: &FallbackConfig, ctx: &FallbackContext) -> bool {
    fallback.path.is_none() && matches_name_alpn(fallback, ctx)
}

/// Select a configured fallback using Xray-style inheritance rules.
pub fn select_vless_fallback<'a>(
    fallbacks: &'a [FallbackConfig],
    ctx: &FallbackContext,
) -> Option<&'a FallbackConfig> {
    if fallbacks.is_empty() {
        return None;
    }

    if ctx.http_path.is_some() {
        for fallback in fallbacks {
            if fallback.path.is_some() && matches_with_path(fallback, ctx) {
                return Some(fallback);
            }
        }
    }

    for fallback in fallbacks {
        if !fallback.is_default() && matches_without_path(fallback, ctx) {
            return Some(fallback);
        }
    }

    fallbacks
        .iter()
        .find(|fallback| fallback.is_default())
        .or_else(|| fallbacks.first())
}

pub fn resolve_fallback_target(
    fallbacks: &[FallbackConfig],
    reality_dest: &str,
    ctx: &FallbackContext,
) -> std::io::Result<(String, u8)> {
    if let Some(fallback) = select_vless_fallback(fallbacks, ctx) {
        validate_fallback_xver(fallback.xver)?;
        return Ok((fallback.dest.addr.clone(), fallback.xver));
    }
    Ok((reality_dest.to_string(), 0))
}

pub fn build_proxy_protocol_v1(
    source: SocketAddr,
    destination: SocketAddr,
) -> std::io::Result<Vec<u8>> {
    let header = match (source, destination) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            src.ip(),
            dst.ip(),
            src.port(),
            dst.port()
        ),
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            src.ip(),
            dst.ip(),
            src.port(),
            dst.port()
        ),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "PROXY protocol v1 requires matching IP versions for source and destination",
            ))
        }
    };
    Ok(header.into_bytes())
}

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fallback(
        name: Option<&str>,
        alpn: Option<&str>,
        path: Option<&str>,
        dest: &str,
        xver: u8,
    ) -> FallbackConfig {
        FallbackConfig {
            name: name.map(str::to_string),
            alpn: alpn.map(str::to_string),
            path: path.map(str::to_string),
            dest: FallbackDest {
                addr: dest.to_string(),
            },
            xver,
        }
    }

    #[test]
    fn parse_fallback_dest_number_uses_localhost() {
        let dest = parse_fallback_dest(&json!(8080)).expect("parse numeric dest");
        assert_eq!(dest.addr, "127.0.0.1:8080");
    }

    #[test]
    fn parse_fallback_dest_host_port() {
        let dest = parse_fallback_dest(&json!("backend.example.com:9443")).expect("parse host");
        assert_eq!(dest.addr, "backend.example.com:9443");
    }

    #[test]
    fn parse_fallback_dest_rejects_unix_socket() {
        let err = parse_fallback_dest(&json!("/run/fallback.sock")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn select_default_fallback() {
        let fallbacks = vec![
            fallback(None, None, None, "127.0.0.1:8080", 0),
            fallback(Some("other.test"), None, None, "127.0.0.1:8081", 0),
        ];
        let ctx = FallbackContext::default();
        let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
        assert_eq!(selected.dest.addr, "127.0.0.1:8080");
    }

    #[test]
    fn select_by_name() {
        let fallbacks = vec![
            fallback(None, None, None, "127.0.0.1:8080", 0),
            fallback(Some("named.test"), None, None, "127.0.0.1:8081", 0),
        ];
        let ctx = FallbackContext {
            sni: Some("named.test".to_string()),
            ..FallbackContext::default()
        };
        let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
        assert_eq!(selected.dest.addr, "127.0.0.1:8081");
    }

    #[test]
    fn select_by_alpn() {
        let fallbacks = vec![
            fallback(None, None, None, "127.0.0.1:8080", 0),
            fallback(None, Some("h2"), None, "127.0.0.1:8082", 0),
        ];
        let ctx = FallbackContext {
            alpn: Some("h2".to_string()),
            ..FallbackContext::default()
        };
        let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
        assert_eq!(selected.dest.addr, "127.0.0.1:8082");
    }

    #[test]
    fn select_by_path_with_inheritance_when_path_missing() {
        let fallbacks = vec![
            fallback(None, None, None, "127.0.0.1:8080", 0),
            fallback(None, None, Some("/secret"), "127.0.0.1:8083", 0),
            fallback(Some("named.test"), None, None, "127.0.0.1:8084", 0),
        ];
        let ctx = FallbackContext {
            sni: Some("named.test".to_string()),
            http_path: Some("/other".to_string()),
            ..FallbackContext::default()
        };
        let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
        assert_eq!(selected.dest.addr, "127.0.0.1:8084");
    }

    #[test]
    fn select_by_path_when_http_request_matches() {
        let fallbacks = vec![
            fallback(None, None, None, "127.0.0.1:8080", 0),
            fallback(None, None, Some("/secret"), "127.0.0.1:8083", 0),
        ];
        let request = b"GET /secret/resource HTTP/1.1\r\nHost: x\r\n\r\n";
        let ctx = build_fallback_context(None, request);
        let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
        assert_eq!(selected.dest.addr, "127.0.0.1:8083");
    }

    #[test]
    fn xver_1_builds_valid_proxy_v1_header() {
        let header = build_proxy_protocol_v1(
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:24443".parse().unwrap(),
        )
        .expect("proxy header");
        assert_eq!(
            std::str::from_utf8(&header).unwrap(),
            "PROXY TCP4 127.0.0.1 127.0.0.1 12345 24443\r\n"
        );
    }

    #[test]
    fn xver_2_is_unsupported() {
        let err = validate_fallback_xver(2).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
