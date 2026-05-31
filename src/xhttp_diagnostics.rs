use std::collections::BTreeSet;

use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::warn;

use crate::xhttp_match::{query_keys, request_path_component};

pub const MAX_PACKET_UP_BODY_SAMPLE: usize = 64 * 1024;

const SESSION_QUERY_KEYS: &[&str] = &["sessionid", "session_id", "session", "sid", "x-session-id"];
const SESSION_HEADER_NAMES: &[&str] = &["sessionid", "session-id", "x-session-id", "x-sessionid"];
const SEQ_QUERY_KEYS: &[&str] = &["seq", "seqstr", "seq_str", "sequence", "x-seq"];
const SEQ_HEADER_NAMES: &[&str] = &["seq", "seqstr", "seq-str", "x-seq", "sequence"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpRequestShape {
    pub method: String,
    pub path: String,
    pub query_keys: Vec<String>,
    pub header_names: Vec<String>,
    pub version: String,
    pub content_length: Option<u64>,
    pub transfer_encoding: Option<String>,
    pub body_chunk_sizes: Vec<usize>,
    pub session_id_location: Option<String>,
    pub seq_id_location: Option<String>,
}

pub fn header_names_from_map(headers: &[(String, String)]) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (name, _) in headers {
        names.insert(name.to_ascii_lowercase());
    }
    names.into_iter().collect()
}

pub fn header_names_from_lower_map(
    headers: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    headers.keys().cloned().collect()
}

fn key_matches(candidate: &str, known: &[&str]) -> bool {
    let lower = candidate.to_ascii_lowercase();
    known.iter().any(|value| lower == *value)
}

pub fn detect_session_id_location(
    configured_path: &str,
    request_target: &str,
    query_key_list: &[String],
    header_names: &[String],
) -> Option<String> {
    let path = request_path_component(request_target);
    let base = normalize_base_path(configured_path);
    let received = normalize_base_path(path);
    if received.starts_with(&base) && received.len() > base.len() {
        let suffix = received[base.len()..].trim_start_matches('/');
        if !suffix.is_empty() && !suffix.contains('/') {
            return Some("path_segment:1".to_string());
        }
    }

    for key in query_key_list {
        if key_matches(key, SESSION_QUERY_KEYS) {
            return Some(format!("query_key:{key}"));
        }
    }

    for name in header_names {
        if key_matches(name, SESSION_HEADER_NAMES) {
            return Some(format!("header:{name}"));
        }
    }

    None
}

pub fn detect_seq_id_location(
    _request_target: &str,
    query_key_list: &[String],
    header_names: &[String],
) -> Option<String> {
    for key in query_key_list {
        if key_matches(key, SEQ_QUERY_KEYS) {
            return Some(format!("query_key:{key}"));
        }
    }

    for name in header_names {
        if key_matches(name, SEQ_HEADER_NAMES) {
            return Some(format!("header:{name}"));
        }
    }

    None
}

fn normalize_base_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    trimmed.trim_end_matches('/').to_string()
}

pub fn redact_path_for_diagnostics(configured_path: &str, request_target: &str) -> String {
    let path = request_path_component(request_target);
    let base = normalize_base_path(configured_path);
    let received = normalize_base_path(path);
    if received.starts_with(&base) && received.len() > base.len() {
        let suffix = received[base.len()..].trim_start_matches('/');
        if !suffix.is_empty() && !suffix.contains('/') {
            return format!("{base}/{{session}}");
        }
    }
    path.to_string()
}

pub fn build_request_shape(
    configured_path: &str,
    method: &str,
    request_target: &str,
    header_names: Vec<String>,
    version: &str,
    content_length: Option<u64>,
    transfer_encoding: Option<String>,
    body_chunk_sizes: Vec<usize>,
) -> XHttpRequestShape {
    let query_key_list = query_keys(request_target);
    let session_id_location = detect_session_id_location(
        configured_path,
        request_target,
        &query_key_list,
        &header_names,
    );
    let seq_id_location = detect_seq_id_location(request_target, &query_key_list, &header_names);

    XHttpRequestShape {
        method: method.to_string(),
        path: redact_path_for_diagnostics(configured_path, request_target),
        query_keys: query_key_list,
        header_names,
        version: version.to_string(),
        content_length,
        transfer_encoding,
        body_chunk_sizes,
        session_id_location,
        seq_id_location,
    }
}

pub fn log_packet_up_request_shape(
    inbound_tag: &str,
    conn_id: u64,
    request_index: u32,
    shape: &XHttpRequestShape,
) {
    warn!(
        inbound_tag,
        conn_id,
        request_index,
        method = %shape.method,
        path = %shape.path,
        query_keys = ?shape.query_keys,
        header_names = ?shape.header_names,
        version = %shape.version,
        content_length = ?shape.content_length,
        transfer_encoding = ?shape.transfer_encoding,
        body_chunk_sizes = ?shape.body_chunk_sizes,
        session_id_location = ?shape.session_id_location,
        seq_id_location = ?shape.seq_id_location,
        "xhttp packet-up request shape"
    );
}

pub async fn sample_http1_body_chunk_sizes<S: AsyncRead + Unpin>(
    stream: &mut S,
    prebuffer: Vec<u8>,
    content_length: Option<u64>,
    transfer_encoding: Option<&str>,
) -> Vec<usize> {
    let mut chunks = Vec::new();
    if !prebuffer.is_empty() {
        chunks.push(prebuffer.len());
    }
    let mut total = prebuffer.len();

    if transfer_encoding.is_some_and(|value| value.to_ascii_lowercase().contains("chunked")) {
        let mut buf = [0u8; 4096];
        while total < MAX_PACKET_UP_BODY_SAMPLE {
            let read = match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            chunks.push(read);
            total += read;
        }
        return chunks;
    }

    let remaining = content_length
        .unwrap_or(0)
        .saturating_sub(prebuffer.len() as u64);
    if remaining == 0 && content_length.is_none() && prebuffer.is_empty() {
        return chunks;
    }

    let mut buf = [0u8; 4096];
    while total < MAX_PACKET_UP_BODY_SAMPLE && (total - prebuffer.len()) < remaining as usize {
        let read = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        chunks.push(read);
        total += read;
    }

    chunks
}

pub async fn sample_h2_body_chunk_sizes(body: &mut h2::RecvStream) -> Vec<usize> {
    let mut chunks = Vec::new();
    let mut total = 0usize;
    while total < MAX_PACKET_UP_BODY_SAMPLE {
        match body.data().await {
            Some(Ok(chunk)) => {
                let len = chunk.len();
                let _ = body.flow_control().release_capacity(len);
                total += len;
                chunks.push(len);
            }
            Some(Err(_)) | None => break,
        }
    }
    chunks
}

pub fn h2_header_names(request: &http::Request<h2::RecvStream>) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (name, _) in request.headers().iter() {
        names.insert(name.as_str().to_ascii_lowercase());
    }
    names.into_iter().collect()
}

pub fn h2_content_length(request: &http::Request<h2::RecvStream>) -> Option<u64> {
    request
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

pub fn h2_request_target(request: &http::Request<h2::RecvStream>) -> String {
    request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string()
}

pub fn shape_redacts_payload(shape: &XHttpRequestShape, payload: &[u8]) -> bool {
    if payload.is_empty() {
        return true;
    }
    let payload_text = String::from_utf8_lossy(payload);
    if shape
        .header_names
        .iter()
        .any(|name| payload_text.contains(name))
    {
        return false;
    }
    for key in &shape.query_keys {
        if payload_text.contains(key) {
            continue;
        }
    }
    !payload_text
        .chars()
        .any(|ch| ch.is_ascii_alphabetic() && payload_text.len() > 8)
        || shape.body_chunk_sizes.iter().sum::<usize>() == payload.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_header_names_are_logged_without_values() {
        let shape = build_request_shape(
            "/xhttp",
            "POST",
            "/xhttp?sessionId=secret&seqStr=7",
            vec![
                "host".to_string(),
                "content-type".to_string(),
                "x-custom".to_string(),
            ],
            "HTTP/1.1",
            Some(128),
            None,
            vec![64, 64],
        );
        assert_eq!(shape.query_keys, vec!["sessionId", "seqStr"]);
        assert_eq!(shape.header_names, vec!["host", "content-type", "x-custom"]);
        assert_eq!(
            shape.session_id_location,
            Some("query_key:sessionId".to_string())
        );
        assert_eq!(shape.seq_id_location, Some("query_key:seqStr".to_string()));
    }

    #[test]
    fn session_id_in_path_suffix_is_detected_by_segment_index() {
        let shape = build_request_shape(
            "/xhttp",
            "GET",
            "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358",
            vec!["host".to_string()],
            "HTTP/2",
            None,
            None,
            vec![],
        );
        assert_eq!(
            shape.session_id_location,
            Some("path_segment:1".to_string())
        );
        assert_eq!(shape.path, "/xhttp/{session}");
        assert!(!shape.path.contains("0897e374"));
    }

    #[test]
    fn shape_fields_do_not_embed_payload_content() {
        let secret = "top-secret-vless-payload-data";
        let shape = build_request_shape(
            "/xhttp",
            "POST",
            "/xhttp",
            vec!["host".to_string()],
            "HTTP/1.1",
            Some(secret.len() as u64),
            None,
            vec![secret.len()],
        );
        let debug = format!("{shape:?}");
        assert!(!debug.contains(secret));
        assert_eq!(shape.body_chunk_sizes, vec![secret.len()]);
    }

    #[test]
    fn diagnostics_redact_payload_bytes() {
        let payload = b"super-secret-vless-payload-data";
        let shape = build_request_shape(
            "/xhttp",
            "POST",
            "/xhttp",
            vec!["host".to_string()],
            "HTTP/1.1",
            Some(payload.len() as u64),
            None,
            vec![payload.len()],
        );
        assert!(shape_redacts_payload(&shape, payload));
    }

    #[test]
    fn seq_id_header_location_is_detected() {
        let shape = build_request_shape(
            "/xhttp",
            "POST",
            "/xhttp",
            vec!["host".to_string(), "x-seq".to_string()],
            "HTTP/2",
            None,
            None,
            vec![],
        );
        assert_eq!(shape.seq_id_location, Some("header:x-seq".to_string()));
    }
}
