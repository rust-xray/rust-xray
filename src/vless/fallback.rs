use std::net::SocketAddr;

use serde::Deserialize;
use serde_json::Value;
use tracing::debug;

use crate::protocol::structs::ClientHelloPayload;
use crate::reality::extract_sni_hostname;

const FALLBACK_LOCALHOST: &str = "127.0.0.1";
const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const PROXY_V2_VERSION: u8 = 0x20;
const PROXY_V2_CMD_PROXY: u8 = 0x01;
const PROXY_V2_AF_INET: u8 = 0x10;
const PROXY_V2_AF_INET6: u8 = 0x20;
const PROXY_V2_TYPE_STREAM: u8 = 0x01;
const PROXY_V2_LOCAL_CMD: u8 = 0x00;

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
    pub alpn_offers: Vec<String>,
    pub http_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackMatchKind {
    Default,
    Name,
    Alpn,
    Path,
    Combined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedFallback<'a> {
    pub config: &'a FallbackConfig,
    pub kind: FallbackMatchKind,
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
        if let Some(path) = &fallback.path {
            if !path.starts_with('/') {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("fallbacks[{index}] path must start with '/': {path:?}"),
                ));
            }
        }
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
        0 | 1 | 2 => Ok(()),
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
    let alpn_offers = hello.map(extract_client_alpn_offers).unwrap_or_default();
    let alpn = alpn_offers.first().cloned();
    let http_path = sniff_http_request_path(initial_bytes);
    FallbackContext {
        sni,
        alpn,
        alpn_offers,
        http_path,
    }
}

pub fn extract_client_alpn_offers(hello: &ClientHelloPayload) -> Vec<String> {
    hello
        .alpn_extension()
        .map(|protocols| {
            protocols
                .iter()
                .filter_map(|name| std::str::from_utf8(name.as_ref()).ok().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub fn extract_client_alpn(hello: &ClientHelloPayload) -> Option<String> {
    extract_client_alpn_offers(hello).into_iter().next()
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
        Some(expected) => {
            ctx.alpn_offers
                .iter()
                .any(|offered| eq_ignore_ascii_case(offered, expected))
                || ctx
                    .alpn
                    .as_deref()
                    .is_some_and(|alpn| eq_ignore_ascii_case(alpn, expected))
        }
    }
}

fn fallback_match_kind(fallback: &FallbackConfig) -> FallbackMatchKind {
    let has_name = fallback.name.is_some();
    let has_alpn = fallback.alpn.is_some();
    let has_path = fallback.path.is_some();
    match (has_name, has_alpn, has_path) {
        (false, false, false) => FallbackMatchKind::Default,
        (false, false, true) => FallbackMatchKind::Path,
        (false, true, false) => FallbackMatchKind::Alpn,
        (true, false, false) => FallbackMatchKind::Name,
        _ => FallbackMatchKind::Combined,
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

fn fallback_specificity(fallback: &FallbackConfig) -> u32 {
    let mut score = 0;
    if fallback.name.is_some() {
        score += 1;
    }
    if fallback.alpn.is_some() {
        score += 1;
    }
    if fallback.path.is_some() {
        score += 2;
    }
    score
}

fn path_prefix_match_len(fallback: &FallbackConfig, ctx: &FallbackContext) -> usize {
    match (fallback.path.as_deref(), ctx.http_path.as_deref()) {
        (Some(expected), Some(path)) if path == expected || path.starts_with(expected) => {
            expected.len()
        }
        _ => 0,
    }
}

fn is_better_fallback_candidate(
    candidate: &FallbackConfig,
    candidate_index: usize,
    current_best: &FallbackConfig,
    current_index: usize,
    ctx: &FallbackContext,
) -> bool {
    let candidate_score = fallback_specificity(candidate);
    let best_score = fallback_specificity(current_best);
    if candidate_score != best_score {
        return candidate_score > best_score;
    }

    let candidate_path = path_prefix_match_len(candidate, ctx);
    let best_path = path_prefix_match_len(current_best, ctx);
    if candidate_path != best_path {
        return candidate_path > best_path;
    }

    // Xray-style config order: later duplicate keys win on equal specificity.
    candidate_index > current_index
}

fn pick_best_fallback<'a>(
    best: Option<(usize, &'a FallbackConfig)>,
    candidate_index: usize,
    candidate: &'a FallbackConfig,
    ctx: &FallbackContext,
) -> Option<(usize, &'a FallbackConfig)> {
    Some(match best {
        None => (candidate_index, candidate),
        Some((best_index, current))
            if is_better_fallback_candidate(
                candidate,
                candidate_index,
                current,
                best_index,
                ctx,
            ) =>
        {
            (candidate_index, candidate)
        }
        Some(current) => current,
    })
}

/// Select a configured fallback using Xray-style inheritance rules.
pub fn select_vless_fallback<'a>(
    fallbacks: &'a [FallbackConfig],
    ctx: &FallbackContext,
) -> Option<&'a FallbackConfig> {
    select_vless_fallback_with_kind(fallbacks, ctx).map(|selected| selected.config)
}

pub fn select_vless_fallback_with_kind<'a>(
    fallbacks: &'a [FallbackConfig],
    ctx: &FallbackContext,
) -> Option<SelectedFallback<'a>> {
    if fallbacks.is_empty() {
        return None;
    }

    if ctx.http_path.is_some() {
        let mut best: Option<(usize, &FallbackConfig)> = None;
        for (index, fallback) in fallbacks.iter().enumerate() {
            if fallback.path.is_some() && matches_with_path(fallback, ctx) {
                best = pick_best_fallback(best, index, fallback, ctx);
            }
        }
        if let Some((_, selected)) = best {
            return Some(SelectedFallback {
                config: selected,
                kind: fallback_match_kind(selected),
            });
        }
    }

    let mut best: Option<(usize, &FallbackConfig)> = None;
    for (index, fallback) in fallbacks.iter().enumerate() {
        if !fallback.is_default() && matches_without_path(fallback, ctx) {
            best = pick_best_fallback(best, index, fallback, ctx);
        }
    }
    if let Some((_, selected)) = best {
        return Some(SelectedFallback {
            config: selected,
            kind: fallback_match_kind(selected),
        });
    }

    fallbacks
        .iter()
        .find(|fallback| fallback.is_default())
        .or_else(|| fallbacks.first())
        .map(|selected| SelectedFallback {
            config: selected,
            kind: if selected.is_default() {
                FallbackMatchKind::Default
            } else {
                fallback_match_kind(selected)
            },
        })
}

pub fn fallback_match_kind_label(kind: FallbackMatchKind) -> &'static str {
    match kind {
        FallbackMatchKind::Default => "default",
        FallbackMatchKind::Name => "name",
        FallbackMatchKind::Alpn => "alpn",
        FallbackMatchKind::Path => "path",
        FallbackMatchKind::Combined => "combined",
    }
}

pub fn resolve_fallback_target(
    fallbacks: &[FallbackConfig],
    reality_dest: &str,
    ctx: &FallbackContext,
) -> std::io::Result<(String, u8)> {
    resolve_fallback_selection(fallbacks, reality_dest, ctx)
        .map(|selection| (selection.dest, selection.xver))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackSelection {
    pub dest: String,
    pub xver: u8,
    pub kind: FallbackMatchKind,
    pub used_configured_fallback: bool,
    pub matched_alpn: Option<String>,
}

pub fn matching_alpn_offer(fallback: &FallbackConfig, ctx: &FallbackContext) -> Option<String> {
    let expected = fallback.alpn.as_deref()?;
    ctx.alpn_offers
        .iter()
        .find(|offered| eq_ignore_ascii_case(offered, expected))
        .cloned()
        .or_else(|| {
            ctx.alpn
                .as_ref()
                .filter(|alpn| eq_ignore_ascii_case(alpn, expected))
                .cloned()
        })
}

pub fn resolve_fallback_selection(
    fallbacks: &[FallbackConfig],
    reality_dest: &str,
    ctx: &FallbackContext,
) -> std::io::Result<FallbackSelection> {
    if fallbacks.is_empty() {
        return Ok(FallbackSelection {
            dest: reality_dest.to_string(),
            xver: 0,
            kind: FallbackMatchKind::Default,
            used_configured_fallback: false,
            matched_alpn: None,
        });
    }

    let selected = select_vless_fallback_with_kind(fallbacks, ctx).or_else(|| {
        fallbacks
            .iter()
            .find(|fallback| fallback.is_default())
            .map(|config| SelectedFallback {
                config,
                kind: FallbackMatchKind::Default,
            })
            .or_else(|| {
                fallbacks.first().map(|config| SelectedFallback {
                    config,
                    kind: fallback_match_kind(config),
                })
            })
    });

    let selected = selected.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "configured fallbacks must not be empty",
        )
    })?;
    validate_fallback_xver(selected.config.xver)?;
    let selection = FallbackSelection {
        dest: selected.config.dest.addr.clone(),
        xver: selected.config.xver,
        kind: selected.kind,
        used_configured_fallback: true,
        matched_alpn: matching_alpn_offer(selected.config, ctx),
    };
    debug!(
        requested_sni = ?ctx.sni,
        detected_alpn = ?ctx.alpn,
        alpn_offers = ?ctx.alpn_offers,
        detected_http_path = ?ctx.http_path,
        selected_dest = %selection.dest,
        match_kind = fallback_match_kind_label(selection.kind),
        xver = selection.xver,
        matched_alpn = ?selection.matched_alpn,
        "VLESS fallback rule matched"
    );
    Ok(selection)
}

pub fn build_proxy_protocol_v2(
    source: SocketAddr,
    destination: SocketAddr,
) -> std::io::Result<Vec<u8>> {
    let mut header = Vec::with_capacity(52);
    header.extend_from_slice(&PROXY_V2_SIGNATURE);

    match (source, destination) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            header.push(PROXY_V2_VERSION | PROXY_V2_CMD_PROXY);
            header.push(PROXY_V2_AF_INET | PROXY_V2_TYPE_STREAM);
            header.extend_from_slice(&12u16.to_be_bytes());
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
            Ok(header)
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            header.push(PROXY_V2_VERSION | PROXY_V2_CMD_PROXY);
            header.push(PROXY_V2_AF_INET6 | PROXY_V2_TYPE_STREAM);
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
            Ok(header)
        }
        _ => {
            header.push(PROXY_V2_VERSION | PROXY_V2_LOCAL_CMD);
            header.push(0x00);
            header.extend_from_slice(&0u16.to_be_bytes());
            Ok(header)
        }
    }
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
        _ => "PROXY UNKNOWN\r\n".to_string(),
    };
    Ok(header.into_bytes())
}

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

#[cfg(test)]
#[path = "../../tests/unit/vless/fallback.rs"]
mod tests;
