use http::Request;
use tracing::debug;

use super::matching::{
    method_matches_packet_up_upload, parse_packet_up_path, parse_packet_up_upload_seq_strict,
    query_keys, request_path_component, XHttpMatchRejectReason,
};
use super::mode::XHttpError;
use super::session::XHttpSessionManager;
use crate::config::XHttpSettings;

const UNSUPPORTED_QUERY_KEYS: &[&str] = &["sessionId", "session", "sid", "seq", "seqStr"];
const UNSUPPORTED_HEADER_NAMES: &[&str] = &["x-session-id", "session-id", "x-seq", "seq"];

pub fn request_target<B>(request: &Request<B>) -> String {
    request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string()
}

pub fn extract_xhttp_session_id<B>(
    request: &Request<B>,
    settings: &XHttpSettings,
) -> Result<String, XHttpError> {
    log_unsupported_session_sources(request);

    let request_target = request_target(request);
    let parsed = parse_packet_up_path(settings.effective_path(), &request_target)
        .ok_or(XHttpError::MissingSessionId)?;

    XHttpSessionManager::validate_session_id_as_xhttp_error(&parsed.session_id)?;
    Ok(parsed.session_id)
}

pub fn extract_xhttp_packet_seq<B>(request: &Request<B>) -> Option<u64> {
    if !method_matches_packet_up_upload(request.method().as_str()) {
        return None;
    }
    let target = request_target(request);
    let path = request_path_component(&target);
    let mut segments = path.split('/').filter(|part| !part.is_empty());
    let _ = segments.next()?;
    let _ = segments.next()?;
    segments.next()?.parse().ok()
}

pub fn extract_xhttp_packet_seq_for_settings<B>(
    request: &Request<B>,
    settings: &XHttpSettings,
) -> Result<Option<u64>, XHttpError> {
    if !method_matches_packet_up_upload(request.method().as_str()) {
        return Ok(None);
    }
    let request_target = request_target(request);
    match parse_packet_up_upload_seq_strict(settings.effective_path(), &request_target) {
        Ok(seq) => Ok(seq),
        Err(XHttpMatchRejectReason::PathMismatch) => Err(XHttpError::MalformedPacketRequest(
            "invalid packet seq path segment".to_string(),
        )),
        Err(XHttpMatchRejectReason::HostMismatch | XHttpMatchRejectReason::MethodMismatch) => Err(
            XHttpError::MalformedPacketRequest("invalid packet-up upload path".to_string()),
        ),
    }
}

fn log_unsupported_session_sources<B>(request: &Request<B>) {
    let request_target = request_target(request);
    for key in query_keys(&request_target) {
        if UNSUPPORTED_QUERY_KEYS
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
        {
            debug!(
                query_key = %key,
                source = "query",
                "xhttp packet-up session placement unsupported"
            );
        }
    }
    for name in UNSUPPORTED_HEADER_NAMES {
        if request.headers().contains_key(*name) {
            debug!(
                header = %name,
                source = "header",
                "xhttp packet-up session placement unsupported"
            );
        }
    }
}

pub fn packet_up_body_hint(content_length: Option<u64>, chunk_bytes: usize) -> String {
    match content_length {
        Some(len) => format!("content-length={len}"),
        None if chunk_bytes > 0 => format!("chunked_or_streaming first_chunk={chunk_bytes}"),
        None => "empty".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn request(method: &str, target: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(format!("https://example.com{target}"))
            .body(())
            .unwrap()
    }

    fn settings() -> XHttpSettings {
        XHttpSettings {
            path: "/xhttp".to_string(),
            ..XHttpSettings::default()
        }
    }

    #[test]
    fn session_id_extracted_from_observed_path_segment() {
        let req = request("GET", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358");
        let session_id = extract_xhttp_session_id(&req, &settings()).expect("session id");
        assert_eq!(session_id, "0897e374-2f32-4d61-aee9-b9c8523aa358");
    }

    #[test]
    fn invalid_session_id_rejected() {
        let req = request("GET", "/xhttp/../escape");
        let err = extract_xhttp_session_id(&req, &settings()).unwrap_err();
        assert!(matches!(err, XHttpError::InvalidSessionId(_)));

        let req = request("GET", "/xhttp/bad%2fid");
        let err = extract_xhttp_session_id(&req, &settings()).unwrap_err();
        assert!(matches!(err, XHttpError::InvalidSessionId(_)));
    }

    #[test]
    fn missing_session_id_is_clear_error() {
        let req = request("GET", "/xhttp");
        let err = extract_xhttp_session_id(&req, &settings()).unwrap_err();
        assert_eq!(err, XHttpError::MissingSessionId);
    }

    #[test]
    fn seq_extracted_from_upload_path_suffix() {
        let req = request("POST", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358/7");
        assert_eq!(
            extract_xhttp_packet_seq_for_settings(&req, &settings()).expect("seq"),
            Some(7)
        );
    }

    #[test]
    fn download_get_has_no_seq() {
        let req = request("GET", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358");
        assert_eq!(
            extract_xhttp_packet_seq_for_settings(&req, &settings()).expect("seq"),
            None
        );
    }

    #[test]
    fn malformed_seq_segment_is_rejected() {
        let req = request("POST", "/xhttp/session-a/not-a-number");
        let err = extract_xhttp_packet_seq_for_settings(&req, &settings()).unwrap_err();
        assert!(matches!(err, XHttpError::MalformedPacketRequest(_)));
    }

    #[test]
    fn extract_xhttp_packet_seq_without_settings() {
        let req = request("POST", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358/3");
        assert_eq!(extract_xhttp_packet_seq(&req), Some(3));
    }

    #[test]
    fn unsupported_query_session_source_is_not_used() {
        let req = request("GET", "/xhttp?sessionId=ignored");
        let err = extract_xhttp_session_id(&req, &settings()).unwrap_err();
        assert_eq!(err, XHttpError::MissingSessionId);
    }
}
