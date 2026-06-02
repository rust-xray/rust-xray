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
#[path = "../../../tests/unit/transport/xhttp/extract.rs"]
mod tests;
