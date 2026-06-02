use super::mode::TransportSecurity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpMatchRejectReason {
    PathMismatch,
    HostMismatch,
    MethodMismatch,
}

pub struct XHttpMatchSettings<'a> {
    pub path: &'a str,
    pub host: Option<&'a str>,
}

pub struct XHttpRequestDescriptor<'a> {
    pub method: &'a str,
    pub request_target: &'a str,
    pub host: Option<&'a str>,
}

/// Strips one trailing slash from non-root paths before equality compare.
///
/// Upstream Xray normalizes configured path to end with `/` and uses prefix
/// matching (`strings.HasPrefix`). MVP uses exact path equality after this
/// normalize so query/session params do not affect the compare while avoiding
/// overly broad prefix acceptance of arbitrary subpaths.
pub fn normalize_path_for_match(path: &str) -> &str {
    if path == "/" {
        return path;
    }
    path.strip_suffix('/').unwrap_or(path)
}

pub fn request_path_component(request_target: &str) -> &str {
    request_target
        .split_once('?')
        .map_or(request_target, |(path, _)| path)
}

pub fn path_matches(configured: &str, received_path: &str) -> bool {
    normalize_path_for_match(configured) == normalize_path_for_match(received_path)
}

pub fn query_keys(request_target: &str) -> Vec<String> {
    let Some((_, query)) = request_target.split_once('?') else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|part| {
            let key = part.split_once('=').map_or(part, |(key, _)| key).trim();
            if key.is_empty() {
                None
            } else {
                Some(key.to_string())
            }
        })
        .collect()
}

pub fn implied_default_host_port(security: TransportSecurity) -> Option<u16> {
    match security {
        TransportSecurity::Reality | TransportSecurity::Tls => Some(443),
        TransportSecurity::None => None,
    }
}

pub fn split_host_port(host: &str) -> Option<(&str, u16)> {
    let host = host.trim();
    if host.starts_with('[') {
        let closing = host.find(']')?;
        let inside = &host[1..closing];
        let rest = host.get(closing + 1..)?;
        if !rest.starts_with(':') {
            return None;
        }
        let port = rest[1..].parse().ok()?;
        return Some((inside, port));
    }
    let (name, port_str) = host.rsplit_once(':')?;
    if name.is_empty() {
        return None;
    }
    let port = port_str.parse().ok()?;
    Some((name, port))
}

pub fn host_matches(
    configured: Option<&str>,
    received: Option<&str>,
    security: TransportSecurity,
) -> bool {
    let Some(configured) = configured.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    let Some(received) = received.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };

    if configured.eq_ignore_ascii_case(received) {
        return true;
    }

    let default_port = implied_default_host_port(security);
    match (split_host_port(configured), split_host_port(received)) {
        (None, Some((received_host, received_port))) => {
            received_host.eq_ignore_ascii_case(configured)
                && default_port.is_some_and(|port| port == received_port)
        }
        (Some((configured_host, configured_port)), None) => {
            received.eq_ignore_ascii_case(configured_host)
                && default_port.is_some_and(|port| port == configured_port)
        }
        (Some((configured_host, configured_port)), Some((received_host, received_port))) => {
            configured_host.eq_ignore_ascii_case(received_host) && configured_port == received_port
        }
        (None, None) => false,
    }
}

pub fn method_matches_stream_one(method: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketUpPathMatch {
    pub session_id: String,
    pub seq: Option<u64>,
}

pub fn parse_packet_up_path(
    configured_base: &str,
    request_target: &str,
) -> Option<PacketUpPathMatch> {
    let path = request_path_component(request_target);
    let base = normalize_path_for_match(configured_base);
    let received = normalize_path_for_match(path);
    if received == base {
        return None;
    }
    let prefix = if base == "/" { "/" } else { base };
    if received == prefix {
        return None;
    }
    if !received.starts_with(prefix) {
        return None;
    }
    let suffix = received[prefix.len()..].trim_start_matches('/');
    if suffix.is_empty() {
        return None;
    }
    let mut parts = suffix.split('/');
    let session_id = parts.next()?.to_string();
    let seq = parts.next().and_then(|value| value.parse::<u64>().ok());
    if parts.next().is_some() {
        return None;
    }
    Some(PacketUpPathMatch { session_id, seq })
}

pub fn parse_packet_up_upload_seq_strict(
    configured_base: &str,
    request_target: &str,
) -> Result<Option<u64>, XHttpMatchRejectReason> {
    let path = request_path_component(request_target);
    let base = normalize_path_for_match(configured_base);
    let received = normalize_path_for_match(path);
    if received == base || received == base.trim_end_matches('/') {
        return Err(XHttpMatchRejectReason::PathMismatch);
    }
    let prefix = if base == "/" { "/" } else { base };
    if !received.starts_with(prefix) {
        return Err(XHttpMatchRejectReason::PathMismatch);
    }
    let suffix = received[prefix.len()..].trim_start_matches('/');
    let mut parts = suffix.split('/');
    let _session_id = parts.next().ok_or(XHttpMatchRejectReason::PathMismatch)?;
    match parts.next() {
        None => Ok(None),
        Some(raw) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|_| XHttpMatchRejectReason::PathMismatch),
    }
}

pub fn method_matches_packet_up_upload(method: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
}

pub fn method_matches_packet_up_download(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET")
}

pub fn parse_stream_up_path(configured_base: &str, request_target: &str) -> Option<String> {
    let parsed = parse_packet_up_path(configured_base, request_target)?;
    if parsed.seq.is_some() {
        return None;
    }
    Some(parsed.session_id)
}

pub fn stream_up_path_has_seq(configured_base: &str, request_target: &str) -> bool {
    parse_packet_up_path(configured_base, request_target).is_some_and(|parsed| parsed.seq.is_some())
}

pub fn validate_stream_up_request(
    settings: &XHttpMatchSettings<'_>,
    request: &XHttpRequestDescriptor<'_>,
    security: TransportSecurity,
) -> Result<String, XHttpMatchRejectReason> {
    if !host_matches(settings.host, request.host, security) {
        return Err(XHttpMatchRejectReason::HostMismatch);
    }
    if request.method.eq_ignore_ascii_case("POST")
        && stream_up_path_has_seq(settings.path, request.request_target)
    {
        return Err(XHttpMatchRejectReason::PathMismatch);
    }
    let session_id = parse_stream_up_path(settings.path, request.request_target)
        .ok_or(XHttpMatchRejectReason::PathMismatch)?;
    if !request.method.eq_ignore_ascii_case("GET") && !request.method.eq_ignore_ascii_case("POST") {
        return Err(XHttpMatchRejectReason::MethodMismatch);
    }
    Ok(session_id)
}

pub fn validate_packet_up_request(
    settings: &XHttpMatchSettings<'_>,
    request: &XHttpRequestDescriptor<'_>,
    security: TransportSecurity,
) -> Result<PacketUpPathMatch, XHttpMatchRejectReason> {
    if !host_matches(settings.host, request.host, security) {
        return Err(XHttpMatchRejectReason::HostMismatch);
    }
    let parsed = parse_packet_up_path(settings.path, request.request_target)
        .ok_or(XHttpMatchRejectReason::PathMismatch)?;
    if method_matches_packet_up_upload(request.method) {
        return Ok(parsed);
    }
    if method_matches_packet_up_download(request.method) {
        if parsed.seq.is_some() {
            return Err(XHttpMatchRejectReason::PathMismatch);
        }
        return Ok(parsed);
    }
    Err(XHttpMatchRejectReason::MethodMismatch)
}

pub fn validate_xhttp_stream_one_request(
    settings: &XHttpMatchSettings<'_>,
    request: &XHttpRequestDescriptor<'_>,
    security: TransportSecurity,
) -> Result<(), XHttpMatchRejectReason> {
    let received_path = request_path_component(request.request_target);
    if !path_matches(settings.path, received_path) {
        return Err(XHttpMatchRejectReason::PathMismatch);
    }
    if !host_matches(settings.host, request.host, security) {
        return Err(XHttpMatchRejectReason::HostMismatch);
    }
    if !method_matches_stream_one(request.method) {
        return Err(XHttpMatchRejectReason::MethodMismatch);
    }
    Ok(())
}

pub fn xhttp_match_reject_reason_label(reason: XHttpMatchRejectReason) -> &'static str {
    match reason {
        XHttpMatchRejectReason::PathMismatch => "path_mismatch",
        XHttpMatchRejectReason::HostMismatch => "host_mismatch",
        XHttpMatchRejectReason::MethodMismatch => "method_mismatch",
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/transport/xhttp/matching.rs"]
mod tests;
