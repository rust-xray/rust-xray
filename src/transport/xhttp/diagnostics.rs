use std::collections::BTreeSet;

use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::warn;

use super::matching::{
    method_matches_packet_up_download, method_matches_packet_up_upload, method_matches_stream_one,
    parse_packet_up_path, query_keys, request_path_component,
};
use super::mode::{effective_xhttp_mode_label, EffectiveXHttpMode};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpRequestLeg {
    Upload,
    Download,
    Duplex,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpBodyDirection {
    ClientToServer,
    ServerToClient,
    Both,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpDownloadRecon {
    pub method: String,
    pub path: String,
    pub query_keys: Vec<String>,
    pub header_names: Vec<String>,
    pub session_id_source: Option<String>,
    pub upload_download_relation: String,
    pub version: String,
    pub body_direction: String,
    pub requires_h2: String,
    pub effective_mode: String,
    pub content_length: Option<u64>,
    pub body_chunk_sizes: Vec<usize>,
}

pub fn classify_request_leg(
    method: &str,
    request_target: &str,
    configured_path: &str,
    effective_mode: EffectiveXHttpMode,
    session_id_location: Option<&str>,
) -> XHttpRequestLeg {
    if method_matches_stream_one(method) && matches!(effective_mode, EffectiveXHttpMode::StreamOne)
    {
        return XHttpRequestLeg::Duplex;
    }

    if method_matches_packet_up_upload(method) {
        return XHttpRequestLeg::Upload;
    }

    if method_matches_packet_up_download(method) {
        if parse_packet_up_path(configured_path, request_target)
            .is_some_and(|parsed| parsed.seq.is_none())
        {
            return XHttpRequestLeg::Download;
        }
        if session_id_location.is_some() {
            return XHttpRequestLeg::Download;
        }
    }

    match effective_mode {
        EffectiveXHttpMode::PacketDown | EffectiveXHttpMode::StreamUp => {
            if method_matches_packet_up_download(method) {
                return XHttpRequestLeg::Download;
            }
            if method_matches_packet_up_upload(method) {
                return XHttpRequestLeg::Upload;
            }
        }
        EffectiveXHttpMode::PacketUp => {
            if method_matches_packet_up_download(method) {
                return XHttpRequestLeg::Download;
            }
        }
        _ => {}
    }

    XHttpRequestLeg::Unknown
}

pub fn body_direction_for_leg(
    leg: XHttpRequestLeg,
    shape: &XHttpRequestShape,
) -> XHttpBodyDirection {
    match leg {
        XHttpRequestLeg::Download => XHttpBodyDirection::ServerToClient,
        XHttpRequestLeg::Upload => {
            if shape.body_chunk_sizes.is_empty() && shape.content_length.unwrap_or(0) == 0 {
                XHttpBodyDirection::None
            } else {
                XHttpBodyDirection::ClientToServer
            }
        }
        XHttpRequestLeg::Duplex => XHttpBodyDirection::Both,
        XHttpRequestLeg::Unknown => XHttpBodyDirection::None,
    }
}

pub fn upload_download_relation_label(
    leg: XHttpRequestLeg,
    effective_mode: EffectiveXHttpMode,
) -> &'static str {
    match (effective_mode, leg) {
        (EffectiveXHttpMode::PacketUp, XHttpRequestLeg::Download) => "packet-up:download_get",
        (EffectiveXHttpMode::PacketUp, XHttpRequestLeg::Upload) => "packet-up:upload_post",
        (EffectiveXHttpMode::StreamUp, XHttpRequestLeg::Download) => "stream-up:download_get",
        (EffectiveXHttpMode::StreamUp, XHttpRequestLeg::Upload) => "stream-up:upload_post",
        (EffectiveXHttpMode::PacketDown, XHttpRequestLeg::Download) => "packet-down:download_get",
        (EffectiveXHttpMode::PacketDown, XHttpRequestLeg::Upload) => "packet-down:upload_post",
        (EffectiveXHttpMode::StreamOne, XHttpRequestLeg::Duplex) => "stream-one:duplex_post",
        (_, XHttpRequestLeg::Download) => "download_get",
        (_, XHttpRequestLeg::Upload) => "upload_post",
        (_, XHttpRequestLeg::Duplex) => "duplex_post",
        _ => "unknown",
    }
}

pub fn requires_h2_label(version: &str) -> &'static str {
    if version.eq_ignore_ascii_case("HTTP/2") {
        "yes"
    } else if version.eq_ignore_ascii_case("HTTP/1.1") || version.starts_with("HTTP/1") {
        "no"
    } else {
        "unknown"
    }
}

fn body_direction_label(direction: XHttpBodyDirection) -> &'static str {
    match direction {
        XHttpBodyDirection::ClientToServer => "client_to_server",
        XHttpBodyDirection::ServerToClient => "server_to_client",
        XHttpBodyDirection::Both => "both",
        XHttpBodyDirection::None => "none",
    }
}

pub fn build_download_recon(
    shape: &XHttpRequestShape,
    leg: XHttpRequestLeg,
    effective_mode: EffectiveXHttpMode,
) -> Option<XHttpDownloadRecon> {
    if leg != XHttpRequestLeg::Download {
        return None;
    }
    let body_direction = body_direction_for_leg(leg, shape);
    Some(XHttpDownloadRecon {
        method: shape.method.clone(),
        path: shape.path.clone(),
        query_keys: shape.query_keys.clone(),
        header_names: shape.header_names.clone(),
        session_id_source: shape.session_id_location.clone(),
        upload_download_relation: upload_download_relation_label(leg, effective_mode).to_string(),
        version: shape.version.clone(),
        body_direction: body_direction_label(body_direction).to_string(),
        requires_h2: requires_h2_label(&shape.version).to_string(),
        effective_mode: effective_xhttp_mode_label(effective_mode).to_string(),
        content_length: shape.content_length,
        body_chunk_sizes: shape.body_chunk_sizes.clone(),
    })
}

pub fn log_xhttp_download_reconnaissance(
    inbound_tag: &str,
    conn_id: u64,
    request_index: u32,
    recon: &XHttpDownloadRecon,
) {
    warn!(
        inbound_tag,
        conn_id,
        request_index,
        method = %recon.method,
        path = %recon.path,
        query_keys = ?recon.query_keys,
        header_names = ?recon.header_names,
        session_id_source = recon.session_id_source.as_deref().unwrap_or("none"),
        upload_download_relation = %recon.upload_download_relation,
        version = %recon.version,
        body_direction = %recon.body_direction,
        requires_h2 = %recon.requires_h2,
        effective_mode = %recon.effective_mode,
        content_length = ?recon.content_length,
        body_chunk_sizes = ?recon.body_chunk_sizes,
        download_request_observed = "yes",
        "xhttp download reconnaissance"
    );
}

pub fn observe_download_reconnaissance(
    inbound_tag: &str,
    conn_id: u64,
    request_index: u32,
    shape: &XHttpRequestShape,
    request_target: &str,
    configured_path: &str,
    effective_mode: EffectiveXHttpMode,
) -> Option<XHttpDownloadRecon> {
    let leg = classify_request_leg(
        &shape.method,
        request_target,
        configured_path,
        effective_mode,
        shape.session_id_location.as_deref(),
    );
    let recon = build_download_recon(shape, leg, effective_mode)?;
    log_xhttp_download_reconnaissance(inbound_tag, conn_id, request_index, &recon);
    Some(recon)
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
#[path = "../../../tests/unit/transport/xhttp/diagnostics.rs"]
mod tests;
