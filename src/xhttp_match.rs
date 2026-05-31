use crate::xhttp_mode::TransportSecurity;

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
mod tests {
    use super::*;

    #[test]
    fn exact_path_matches() {
        assert!(path_matches("/xhttp", "/xhttp"));
    }

    #[test]
    fn trailing_slash_path_matches_configured_without_slash() {
        assert!(path_matches("/xhttp", "/xhttp/"));
        assert!(path_matches("/xhttp/", "/xhttp"));
    }

    #[test]
    fn query_path_matches_without_query_in_compare() {
        assert!(path_matches(
            "/xhttp",
            request_path_component("/xhttp?sid=abc")
        ));
        assert_eq!(
            query_keys("/xhttp?sessionId=abc&seqStr=1&flag"),
            vec![
                "sessionId".to_string(),
                "seqStr".to_string(),
                "flag".to_string()
            ]
        );
    }

    #[test]
    fn wrong_path_rejected() {
        assert!(!path_matches("/xhttp", "/wrong"));
    }

    #[test]
    fn host_absent_accepts_any() {
        assert!(host_matches(
            None,
            Some("anything.example"),
            TransportSecurity::Reality
        ));
        assert!(host_matches(None, None, TransportSecurity::Reality));
    }

    #[test]
    fn host_exact_match_case_insensitive() {
        assert!(host_matches(
            Some("Example.COM"),
            Some("example.com"),
            TransportSecurity::Reality
        ));
    }

    #[test]
    fn host_with_default_port_accepted_for_reality() {
        assert!(host_matches(
            Some("example.com"),
            Some("example.com:443"),
            TransportSecurity::Reality
        ));
        assert!(host_matches(
            Some("example.com"),
            Some("example.com:443"),
            TransportSecurity::Tls
        ));
    }

    #[test]
    fn host_with_non_default_port_rejected_for_bare_configured_host() {
        assert!(!host_matches(
            Some("example.com"),
            Some("example.com:8080"),
            TransportSecurity::Reality
        ));
    }

    #[test]
    fn wrong_host_rejected() {
        assert!(!host_matches(
            Some("example.com"),
            Some("other.example"),
            TransportSecurity::Reality
        ));
    }

    #[test]
    fn post_accepted_for_stream_one() {
        assert!(method_matches_stream_one("POST"));
        assert!(method_matches_stream_one("post"));
    }

    #[test]
    fn get_rejected_for_stream_one() {
        assert!(!method_matches_stream_one("GET"));
    }

    #[test]
    fn parse_packet_up_path_extracts_session_and_seq() {
        let parsed = parse_packet_up_path("/xhttp", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358")
            .expect("session");
        assert_eq!(parsed.session_id, "0897e374-2f32-4d61-aee9-b9c8523aa358");
        assert_eq!(parsed.seq, None);

        let parsed =
            parse_packet_up_path("/xhttp", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358/0")
                .expect("upload");
        assert_eq!(parsed.session_id, "0897e374-2f32-4d61-aee9-b9c8523aa358");
        assert_eq!(parsed.seq, Some(0));
    }

    #[test]
    fn validate_packet_up_upload_requires_seq_suffix() {
        let settings = XHttpMatchSettings {
            path: "/xhttp",
            host: None,
        };
        let request = XHttpRequestDescriptor {
            method: "POST",
            request_target: "/xhttp/session-a/0",
            host: Some("example.com"),
        };
        assert!(
            validate_packet_up_request(&settings, &request, TransportSecurity::Reality).is_ok()
        );
        let without_seq = XHttpRequestDescriptor {
            method: "POST",
            request_target: "/xhttp/session-a",
            host: Some("example.com"),
        };
        assert!(
            validate_packet_up_request(&settings, &without_seq, TransportSecurity::Reality).is_ok()
        );
    }

    #[test]
    fn validate_request_accepts_official_client_shape() {
        let settings = XHttpMatchSettings {
            path: "/xhttp",
            host: Some("example.com"),
        };
        let request = XHttpRequestDescriptor {
            method: "POST",
            request_target: "/xhttp?sessionId=abc&seq=1",
            host: Some("example.com:443"),
        };
        assert!(
            validate_xhttp_stream_one_request(&settings, &request, TransportSecurity::Reality)
                .is_ok()
        );
    }
}
