use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

use crate::config::XHttpSettings;
use crate::stats::StatsState;
use crate::tls::PrefixedStream;
use crate::vless::VlessUserManager;

use super::bridge::{
    h2_send_chunk, run_h2_stream_one_bridge, run_http1_stream_one_bridge, write_http1_chunked_chunk,
};
use super::diagnostics::{
    build_request_shape, classify_request_leg, h2_content_length, h2_header_names,
    h2_request_target, header_names_from_lower_map, log_packet_up_request_shape,
    observe_download_reconnaissance, sample_h2_body_chunk_sizes, sample_http1_body_chunk_sizes,
    XHttpRequestLeg,
};
use super::extract::{
    extract_xhttp_packet_seq, extract_xhttp_packet_seq_for_settings, extract_xhttp_session_id,
    packet_up_body_hint,
};
use super::matching::{
    host_matches, method_matches_packet_up_download, method_matches_packet_up_upload,
    method_matches_stream_one, parse_packet_up_path, parse_packet_up_upload_seq_strict,
    path_matches, query_keys, request_path_component, xhttp_match_reject_reason_label,
    XHttpMatchRejectReason, XHttpMatchSettings, XHttpRequestDescriptor,
};
use super::mode::{
    configured_xhttp_mode, configured_xhttp_mode_label, effective_xhttp_mode_label,
    effective_xhttp_mode_unsupported_reason, resolve_xhttp_mode, transport_security_label,
    xhttp_download_side_ready, EffectiveXHttpMode, TransportSecurity, XHttpError,
};
use super::packet_up::{shared_packet_up_manager, spawn_packet_up_bridge, PacketUpLimits};
use super::session::XHttpSessionManager;

const MAX_HTTP_HEADER_SIZE: usize = 16 * 1024;
const HTTP1_UPLOAD_READ_BUFFER: usize = 16 * 1024;
const HTTP2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const PACKET_UP_DOWNLOAD_RECV_TIMEOUT: Duration = Duration::from_secs(30);
const PACKET_UP_DOWNLOAD_RESPONSE_HEADERS_HTTP1: &str = "HTTP/1.1 200 OK\r\nX-Accel-Buffering: no\r\nCache-Control: no-store\r\nContent-Type: text/event-stream\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

fn packet_up_download_h2_response() -> Result<Response<()>, http::Error> {
    Response::builder()
        .status(StatusCode::OK)
        .header("X-Accel-Buffering", "no")
        .header(http::header::CACHE_CONTROL, "no-store")
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST")
        .body(())
}

fn extract_session_id_from_request_target(
    settings: &XHttpSettings,
    request_target: &str,
) -> Result<String, XHttpError> {
    let parsed = parse_packet_up_path(settings.effective_path(), request_target)
        .ok_or(XHttpError::MissingSessionId)?;
    XHttpSessionManager::validate_session_id_as_xhttp_error(&parsed.session_id)?;
    Ok(parsed.session_id)
}

fn extract_packet_up_upload_seq(
    settings: &XHttpSettings,
    request_target: &str,
) -> Result<Option<u64>, XHttpError> {
    match parse_packet_up_upload_seq_strict(settings.effective_path(), request_target) {
        Ok(seq) => Ok(seq),
        Err(XHttpMatchRejectReason::PathMismatch) => Err(XHttpError::MalformedPacketRequest(
            "invalid packet seq path segment".to_string(),
        )),
        Err(XHttpMatchRejectReason::HostMismatch | XHttpMatchRejectReason::MethodMismatch) => Err(
            XHttpError::MalformedPacketRequest("invalid packet-up upload path".to_string()),
        ),
    }
}

static NEXT_XHTTP_CONN_ID: AtomicU64 = AtomicU64::new(1);

fn xhttp_has_download_settings(settings: &XHttpSettings) -> bool {
    settings.download_settings.is_some()
}

fn resolve_xhttp_mode_for_settings(
    settings: &XHttpSettings,
    security: TransportSecurity,
) -> Result<EffectiveXHttpMode, XHttpError> {
    let configured = configured_xhttp_mode(settings.mode.as_deref())?;
    let has_download_settings = xhttp_has_download_settings(settings);
    let effective = resolve_xhttp_mode(configured, has_download_settings, security)?;
    debug!(
        configured = configured_xhttp_mode_label(configured),
        effective = effective_xhttp_mode_label(effective),
        security = transport_security_label(security),
        has_download_settings,
        "xhttp mode resolved"
    );
    Ok(effective)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XHttpRequestHead {
    method: String,
    request_target: String,
    path: String,
    query_keys: Vec<String>,
    version: String,
    headers: BTreeMap<String, String>,
}

impl XHttpRequestHead {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

pub struct XHttpDuplexStream<S> {
    inner: S,
    prebuffer: Vec<u8>,
    prebuffer_pos: usize,
    remaining_request_body: Option<u64>,
    pending_write: Vec<u8>,
    pending_write_pos: usize,
    inbound_tag: Option<String>,
    conn_id: Option<u64>,
    request_eof_logged: bool,
    response_write_started: bool,
    response_finished: bool,
}

#[allow(dead_code)]
pub struct XHttpH2DuplexStream {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    current: Option<Bytes>,
    pending_write: Option<Bytes>,
    pending_write_pos: usize,
    inbound_tag: String,
    conn_id: u64,
    request_eof_logged: bool,
    response_write_started: bool,
    response_finished: bool,
}

#[allow(dead_code)]
impl XHttpH2DuplexStream {
    fn new(
        recv: h2::RecvStream,
        send: h2::SendStream<Bytes>,
        inbound_tag: &str,
        conn_id: u64,
    ) -> Self {
        Self {
            recv,
            send,
            current: None,
            pending_write: None,
            pending_write_pos: 0,
            inbound_tag: inbound_tag.to_string(),
            conn_id,
            request_eof_logged: false,
            response_write_started: false,
            response_finished: false,
        }
    }

    fn log_request_eof(&mut self) {
        if self.request_eof_logged {
            return;
        }
        self.request_eof_logged = true;
        debug!(
            inbound_tag = %self.inbound_tag,
            conn_id = self.conn_id,
            "xhttp request body eof"
        );
    }
}

impl<S> XHttpDuplexStream<S> {
    pub fn new(inner: S, prebuffer: Vec<u8>, content_length: Option<u64>) -> Self {
        Self::new_with_diagnostics(inner, prebuffer, content_length, None, None)
    }

    fn new_with_diagnostics(
        inner: S,
        prebuffer: Vec<u8>,
        content_length: Option<u64>,
        inbound_tag: Option<String>,
        conn_id: Option<u64>,
    ) -> Self {
        Self {
            inner,
            prebuffer,
            prebuffer_pos: 0,
            remaining_request_body: content_length,
            pending_write: Vec::new(),
            pending_write_pos: 0,
            inbound_tag,
            conn_id,
            request_eof_logged: false,
            response_write_started: false,
            response_finished: false,
        }
    }

    fn log_request_eof(&mut self) {
        if self.request_eof_logged {
            return;
        }
        self.request_eof_logged = true;
        debug!(
            inbound_tag = self.inbound_tag.as_deref().unwrap_or(""),
            conn_id = self.conn_id,
            "xhttp request body eof"
        );
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for XHttpDuplexStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(0) = self.remaining_request_body {
            return Poll::Ready(Ok(()));
        }

        if self.prebuffer_pos < self.prebuffer.len() {
            let available = self.prebuffer.len() - self.prebuffer_pos;
            let allowed = self
                .remaining_request_body
                .map(|remaining| remaining.min(available as u64) as usize)
                .unwrap_or(available);
            let to_copy = allowed.min(buf.remaining());
            let start = self.prebuffer_pos;
            let end = start + to_copy;
            buf.put_slice(&self.prebuffer[start..end]);
            self.prebuffer_pos = end;
            if let Some(remaining) = self.remaining_request_body.as_mut() {
                *remaining = remaining.saturating_sub(to_copy as u64);
                if *remaining == 0 {
                    self.log_request_eof();
                }
            }
            return Poll::Ready(Ok(()));
        }

        let before = buf.filled().len();
        match self.remaining_request_body {
            Some(remaining) => {
                if remaining == 0 {
                    return Poll::Ready(Ok(()));
                }
                let max = remaining.min(buf.remaining() as u64) as usize;
                if max == 0 {
                    return Poll::Ready(Ok(()));
                }
                let mut limited = ReadBuf::new(&mut buf.initialize_unfilled_to(max)[..max]);
                let result = Pin::new(&mut self.inner).poll_read(cx, &mut limited);
                if let Poll::Ready(Ok(())) = &result {
                    let read = limited.filled().len();
                    buf.advance(read);
                    if let Some(remaining) = self.remaining_request_body.as_mut() {
                        *remaining = remaining.saturating_sub(read as u64);
                        if *remaining == 0 {
                            self.log_request_eof();
                        }
                    }
                }
                result
            }
            None => {
                let result = Pin::new(&mut self.inner).poll_read(cx, buf);
                if let Poll::Ready(Ok(())) = &result {
                    if buf.filled().len() == before {
                        self.remaining_request_body = Some(0);
                        self.log_request_eof();
                    }
                }
                result
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for XHttpDuplexStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.response_write_started {
            self.response_write_started = true;
            debug!(
                inbound_tag = self.inbound_tag.as_deref().unwrap_or(""),
                conn_id = self.conn_id,
                first_chunk_len = buf.len(),
                "xhttp response body write started"
            );
        }
        if !self.pending_write.is_empty() {
            match self.as_mut().poll_flush_pending(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_write = Vec::with_capacity(buf.len() + 32);
        self.pending_write
            .extend_from_slice(format!("{:x}\r\n", buf.len()).as_bytes());
        self.pending_write.extend_from_slice(buf);
        self.pending_write.extend_from_slice(b"\r\n");
        self.pending_write_pos = 0;
        match self.as_mut().poll_flush_pending(cx)? {
            Poll::Ready(()) => Poll::Ready(Ok(buf.len())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.pending_write.is_empty() {
            match self.as_mut().poll_flush_pending(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        if !self.response_finished {
            self.pending_write.extend_from_slice(b"0\r\n\r\n");
            self.pending_write_pos = 0;
            match self.as_mut().poll_flush_pending(cx)? {
                Poll::Ready(()) => self.response_finished = true,
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncWrite + Unpin> XHttpDuplexStream<S> {
    fn poll_flush_pending(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::io::Result<Poll<()>> {
        while self.pending_write_pos < self.pending_write.len() {
            let pos = self.pending_write_pos;
            let chunk = self.pending_write[pos..].to_vec();
            match Pin::new(&mut self.inner).poll_write(cx, &chunk) {
                Poll::Ready(Ok(0)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write XHTTP response chunk",
                    ));
                }
                Poll::Ready(Ok(written)) => {
                    self.pending_write_pos += written;
                }
                Poll::Ready(Err(err)) => return Err(err),
                Poll::Pending => return Ok(Poll::Pending),
            }
        }
        self.pending_write.clear();
        self.pending_write_pos = 0;
        Ok(Poll::Ready(()))
    }
}

impl AsyncRead for XHttpH2DuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(current) = self.current.as_mut() {
            let to_copy = current.len().min(buf.remaining());
            buf.put_slice(&current[..to_copy]);
            current.advance(to_copy);
            if current.is_empty() {
                self.current = None;
            }
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.recv).poll_data(cx) {
            Poll::Ready(Some(Ok(mut chunk))) => {
                let len = chunk.len();
                let _ = self.recv.flow_control().release_capacity(len);
                let to_copy = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..to_copy]);
                chunk.advance(to_copy);
                if !chunk.is_empty() {
                    self.current = Some(chunk);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(err)))
                if matches!(
                    err.reason(),
                    Some(h2::Reason::NO_ERROR | h2::Reason::CANCEL)
                ) =>
            {
                self.log_request_eof();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("xhttp h2 request body error: {err}"),
            ))),
            Poll::Ready(None) => {
                self.log_request_eof();
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for XHttpH2DuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.response_write_started {
            self.response_write_started = true;
            debug!(
                inbound_tag = %self.inbound_tag,
                conn_id = self.conn_id,
                first_chunk_len = buf.len(),
                "xhttp response body write started"
            );
        }
        if self.pending_write.is_none() {
            self.pending_write = Some(Bytes::copy_from_slice(buf));
            self.pending_write_pos = 0;
        }
        let pending_len = self.pending_write.as_ref().map_or(0, Bytes::len);
        while self.pending_write_pos < pending_len {
            let remaining = pending_len - self.pending_write_pos;
            self.send.reserve_capacity(remaining);
            let capacity = match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => capacity,
                Poll::Ready(Some(Err(err))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("xhttp h2 response capacity error: {err}"),
                    )));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "xhttp h2 response stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            };
            if capacity == 0 {
                return Poll::Pending;
            }
            let to_send = capacity.min(pending_len - self.pending_write_pos);
            let end = self.pending_write_pos + to_send;
            let data = self
                .pending_write
                .as_ref()
                .expect("pending write")
                .slice(self.pending_write_pos..end);
            self.pending_write_pos = end;
            if let Err(err) = self.send.send_data(data, false) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("xhttp h2 response write error: {err}"),
                )));
            }
        }
        self.pending_write = None;
        self.pending_write_pos = 0;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.response_finished {
            if let Err(err) = self.send.send_data(Bytes::new(), true) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("xhttp h2 response finish error: {err}"),
                )));
            }
            self.response_finished = true;
        }
        Poll::Ready(Ok(()))
    }
}

async fn read_http_head<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<(XHttpRequestHead, Vec<u8>)> {
    let mut buffer = Vec::new();
    let header_end = loop {
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
        if buffer.len() >= MAX_HTTP_HEADER_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "XHTTP request header exceeds limit",
            ));
        }
        let mut byte = [0u8; 1];
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream closed before complete XHTTP request header",
            ));
        }
        buffer.push(byte[0]);
    };

    let head_bytes = &buffer[..header_end - 4];
    let head_text = std::str::from_utf8(head_bytes).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid XHTTP request header utf8: {err}"),
        )
    })?;
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing XHTTP request line",
        )
    })?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or("").to_string();
    let request_target = request_parts.next().unwrap_or("").to_string();
    let version = request_parts.next().unwrap_or("").to_string();
    let mut headers = BTreeMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    Ok((
        XHttpRequestHead {
            method,
            request_target: request_target.clone(),
            path: request_path_component(&request_target).to_string(),
            query_keys: query_keys(&request_target),
            version,
            headers,
        },
        buffer[header_end..].to_vec(),
    ))
}

fn request_content_length(head: &XHttpRequestHead) -> std::io::Result<Option<u64>> {
    match head.header("content-length") {
        Some(value) => value.parse::<u64>().map(Some).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid XHTTP content-length: {err}"),
            )
        }),
        None => Ok(None),
    }
}

fn xhttp_runtime_unsupported_reason(
    settings: &XHttpSettings,
    effective_mode: EffectiveXHttpMode,
) -> Option<&'static str> {
    if settings.xmux.is_some() {
        return Some("xmux_not_implemented");
    }
    effective_xhttp_mode_unsupported_reason(effective_mode)
}

fn log_xhttp_mode_unsupported(
    inbound_tag: &str,
    conn_id: u64,
    effective_mode: EffectiveXHttpMode,
    reason: &str,
) {
    warn!(
        inbound_tag,
        conn_id,
        mode = effective_xhttp_mode_label(effective_mode),
        reason,
        "xhttp mode unsupported"
    );
}

fn log_xhttp_download_side_unsupported(inbound_tag: &str, conn_id: u64) {
    warn!(
        inbound_tag,
        conn_id,
        reason = "download_side_not_implemented",
        "xhttp download side not implemented"
    );
}

fn is_download_side_request(
    method: &str,
    request_target: &str,
    settings: &XHttpSettings,
    effective_mode: EffectiveXHttpMode,
) -> bool {
    if xhttp_download_side_ready() {
        return false;
    }
    let header_names: Vec<String> = Vec::new();
    let pre_shape = build_request_shape(
        settings.effective_path(),
        method,
        request_target,
        header_names,
        "HTTP/2",
        None,
        None,
        Vec::new(),
    );
    let leg = classify_request_leg(
        method,
        request_target,
        settings.effective_path(),
        effective_mode,
        pre_shape.session_id_location.as_deref(),
    );
    leg == XHttpRequestLeg::Download
}

async fn reject_download_side_h2(
    request: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    settings: &XHttpSettings,
    inbound_tag: &str,
    conn_id: u64,
    request_index: u32,
    effective_mode: EffectiveXHttpMode,
) -> io::Result<()> {
    let method = request.method().as_str().to_string();
    let request_target = h2_request_target(&request);
    let header_names = h2_header_names(&request);
    let content_length = h2_content_length(&request);
    let mut body = request.into_body();
    let body_chunk_sizes = sample_h2_body_chunk_sizes(&mut body).await;
    let shape = build_request_shape(
        settings.effective_path(),
        &method,
        &request_target,
        header_names,
        "HTTP/2",
        content_length,
        None,
        body_chunk_sizes,
    );
    observe_download_reconnaissance(
        inbound_tag,
        conn_id,
        request_index,
        &shape,
        &request_target,
        settings.effective_path(),
        effective_mode,
    );
    log_xhttp_download_side_unsupported(inbound_tag, conn_id);
    send_h2_empty_response(respond, StatusCode::NOT_IMPLEMENTED).await
}

async fn reject_download_side_http1<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    settings: &XHttpSettings,
    head: &XHttpRequestHead,
    prebuffer: &[u8],
    inbound_tag: &str,
    conn_id: u64,
    effective_mode: EffectiveXHttpMode,
) -> io::Result<()> {
    let content_length = request_content_length(head).ok().flatten();
    let transfer_encoding = head.header("transfer-encoding").map(str::to_string);
    let body_chunk_sizes = sample_http1_body_chunk_sizes(
        stream,
        prebuffer.to_vec(),
        content_length,
        transfer_encoding.as_deref(),
    )
    .await;
    let shape = build_request_shape(
        settings.effective_path(),
        &head.method,
        &head.request_target,
        header_names_from_lower_map(&head.headers),
        &head.version,
        content_length,
        transfer_encoding,
        body_chunk_sizes,
    );
    observe_download_reconnaissance(
        inbound_tag,
        conn_id,
        0,
        &shape,
        &head.request_target,
        settings.effective_path(),
        effective_mode,
    );
    log_xhttp_download_side_unsupported(inbound_tag, conn_id);
    write_status(stream, "501 Not Implemented").await
}

async fn reject_unsupported_xhttp_h2_with_request(
    request: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    settings: &XHttpSettings,
    inbound_tag: &str,
    conn_id: u64,
    effective_mode: EffectiveXHttpMode,
    reason: &str,
) -> io::Result<()> {
    let method = request.method().as_str().to_string();
    let request_target = h2_request_target(&request);
    let header_names = h2_header_names(&request);
    let content_length = h2_content_length(&request);
    let mut body = request.into_body();
    let body_chunk_sizes = sample_h2_body_chunk_sizes(&mut body).await;
    let shape = build_request_shape(
        settings.effective_path(),
        &method,
        &request_target,
        header_names,
        "HTTP/2",
        content_length,
        None,
        body_chunk_sizes,
    );
    let _ = observe_download_reconnaissance(
        inbound_tag,
        conn_id,
        0,
        &shape,
        &request_target,
        settings.effective_path(),
        effective_mode,
    );
    if effective_mode == EffectiveXHttpMode::PacketUp && method_matches_packet_up_upload(&method) {
        log_packet_up_request_shape(inbound_tag, conn_id, 0, &shape);
    }
    reject_unsupported_xhttp_h2(respond, inbound_tag, conn_id, effective_mode, reason).await
}

async fn reject_unsupported_xhttp_http1<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    settings: &XHttpSettings,
    head: &XHttpRequestHead,
    prebuffer: Vec<u8>,
    inbound_tag: &str,
    conn_id: u64,
    effective_mode: EffectiveXHttpMode,
    reason: &str,
) -> io::Result<()> {
    let content_length = request_content_length(head).ok().flatten();
    let transfer_encoding = head.header("transfer-encoding").map(str::to_string);
    let body_chunk_sizes = sample_http1_body_chunk_sizes(
        stream,
        prebuffer,
        content_length,
        transfer_encoding.as_deref(),
    )
    .await;
    let shape = build_request_shape(
        settings.effective_path(),
        &head.method,
        &head.request_target,
        header_names_from_lower_map(&head.headers),
        &head.version,
        content_length,
        transfer_encoding,
        body_chunk_sizes,
    );
    let _ = observe_download_reconnaissance(
        inbound_tag,
        conn_id,
        0,
        &shape,
        &head.request_target,
        settings.effective_path(),
        effective_mode,
    );
    if effective_mode == EffectiveXHttpMode::PacketUp
        && method_matches_packet_up_upload(&head.method)
    {
        log_packet_up_request_shape(inbound_tag, conn_id, 0, &shape);
    }
    log_xhttp_mode_unsupported(inbound_tag, conn_id, effective_mode, reason);
    write_status(stream, "501 Not Implemented").await
}

async fn reject_unsupported_xhttp_h2(
    mut respond: h2::server::SendResponse<Bytes>,
    inbound_tag: &str,
    conn_id: u64,
    effective_mode: EffectiveXHttpMode,
    reason: &str,
) -> io::Result<()> {
    log_xhttp_mode_unsupported(inbound_tag, conn_id, effective_mode, reason);
    let response = Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .body(())
        .map_err(|err| io::Error::other(err.to_string()))?;
    let mut send = respond
        .send_response(response, false)
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
    let _ = send.send_data(Bytes::new(), true);
    Ok(())
}

async fn reject_unsupported_xhttp_h2_packet_up(
    request: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    settings: &XHttpSettings,
    inbound_tag: &str,
    conn_id: u64,
    reason: &str,
) -> io::Result<()> {
    let method = request.method().as_str().to_string();
    let request_target = h2_request_target(&request);
    let header_names = h2_header_names(&request);
    let content_length = h2_content_length(&request);
    let mut body = request.into_body();
    let body_chunk_sizes = sample_h2_body_chunk_sizes(&mut body).await;
    let shape = build_request_shape(
        settings.effective_path(),
        &method,
        &request_target,
        header_names,
        "HTTP/2",
        content_length,
        None,
        body_chunk_sizes,
    );
    let _ = observe_download_reconnaissance(
        inbound_tag,
        conn_id,
        0,
        &shape,
        &request_target,
        settings.effective_path(),
        EffectiveXHttpMode::PacketUp,
    );
    if method_matches_packet_up_upload(&method) {
        log_packet_up_request_shape(inbound_tag, conn_id, 0, &shape);
    }
    reject_unsupported_xhttp_h2(
        respond,
        inbound_tag,
        conn_id,
        EffectiveXHttpMode::PacketUp,
        reason,
    )
    .await
}

fn xhttp_match_settings(settings: &XHttpSettings) -> XHttpMatchSettings<'_> {
    XHttpMatchSettings {
        path: settings.effective_path(),
        host: settings.host.as_deref(),
    }
}

fn log_xhttp_request_received(
    inbound_tag: &str,
    conn_id: u64,
    method: &str,
    request_target: &str,
    host: Option<&str>,
    version: &str,
) {
    debug!(
        inbound_tag,
        conn_id,
        method,
        path = request_path_component(request_target),
        query_keys = ?query_keys(request_target),
        host = ?host,
        version,
        "xhttp request received"
    );
}

fn log_xhttp_path_result(
    inbound_tag: &str,
    conn_id: u64,
    settings: &XHttpMatchSettings<'_>,
    request_target: &str,
    accepted: bool,
    reason: Option<XHttpMatchRejectReason>,
) {
    if accepted {
        debug!(inbound_tag, conn_id, "xhttp path accepted");
    } else {
        debug!(
            inbound_tag,
            conn_id,
            configured_path = settings.path,
            request_path = request_path_component(request_target),
            reason = xhttp_match_reject_reason_label(reason.unwrap()),
            "xhttp path rejected"
        );
    }
}

fn log_xhttp_host_result(
    inbound_tag: &str,
    conn_id: u64,
    settings: &XHttpMatchSettings<'_>,
    host: Option<&str>,
    accepted: bool,
    reason: Option<XHttpMatchRejectReason>,
) {
    if accepted {
        debug!(inbound_tag, conn_id, "xhttp host accepted");
    } else {
        debug!(
            inbound_tag,
            conn_id,
            configured_host = ?settings.host,
            request_host = ?host,
            reason = xhttp_match_reject_reason_label(reason.unwrap()),
            "xhttp host rejected"
        );
    }
}

fn log_xhttp_method_result(
    inbound_tag: &str,
    conn_id: u64,
    method: &str,
    accepted: bool,
    reason: Option<XHttpMatchRejectReason>,
) {
    if accepted {
        debug!(inbound_tag, conn_id, method, "xhttp method accepted");
    } else {
        debug!(
            inbound_tag,
            conn_id,
            method,
            reason = xhttp_match_reject_reason_label(reason.unwrap()),
            "xhttp method rejected"
        );
    }
}

enum XHttpRequestRejectStatus {
    NotFound,
    MethodNotAllowed,
}

fn validate_stream_one_request_match(
    inbound_tag: &str,
    conn_id: u64,
    settings: &XHttpSettings,
    request: &XHttpRequestDescriptor<'_>,
) -> Result<(), XHttpRequestRejectStatus> {
    let match_settings = xhttp_match_settings(settings);
    let security = TransportSecurity::Reality;

    let received_path = request_path_component(request.request_target);
    if !path_matches(match_settings.path, received_path) {
        log_xhttp_path_result(
            inbound_tag,
            conn_id,
            &match_settings,
            request.request_target,
            false,
            Some(XHttpMatchRejectReason::PathMismatch),
        );
        return Err(XHttpRequestRejectStatus::NotFound);
    }
    log_xhttp_path_result(
        inbound_tag,
        conn_id,
        &match_settings,
        request.request_target,
        true,
        None,
    );

    if !host_matches(match_settings.host, request.host, security) {
        log_xhttp_host_result(
            inbound_tag,
            conn_id,
            &match_settings,
            request.host,
            false,
            Some(XHttpMatchRejectReason::HostMismatch),
        );
        return Err(XHttpRequestRejectStatus::NotFound);
    }
    log_xhttp_host_result(
        inbound_tag,
        conn_id,
        &match_settings,
        request.host,
        true,
        None,
    );

    if !method_matches_stream_one(request.method) {
        log_xhttp_method_result(
            inbound_tag,
            conn_id,
            request.method,
            false,
            Some(XHttpMatchRejectReason::MethodMismatch),
        );
        return Err(XHttpRequestRejectStatus::MethodNotAllowed);
    }
    log_xhttp_method_result(inbound_tag, conn_id, request.method, true, None);
    Ok(())
}

async fn send_h2_empty_response(
    mut respond: h2::server::SendResponse<Bytes>,
    status: StatusCode,
) -> io::Result<()> {
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|err| io::Error::other(err.to_string()))?;
    let mut send = respond
        .send_response(response, false)
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
    let _ = send.send_data(Bytes::new(), true);
    Ok(())
}

fn packet_up_error_status(err: &XHttpError) -> StatusCode {
    match err {
        XHttpError::MissingSessionId
        | XHttpError::InvalidSessionId(_)
        | XHttpError::MalformedPacketRequest(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_REQUEST,
    }
}

async fn handle_packet_up_h2_download(
    session_id: String,
    mut respond: h2::server::SendResponse<Bytes>,
    inbound_tag: &str,
    conn_id: u64,
) -> io::Result<()> {
    let manager = shared_packet_up_manager();
    let mut download_rx = match manager.bind_download_session(&session_id) {
        Ok(rx) => rx,
        Err(err) => {
            warn!(
                inbound_tag,
                conn_id,
                session_id = %session_id,
                error = %err,
                "xhttp packet-up download session rejected"
            );
            let status = if err == super::session::XHttpSessionError::DownloadAlreadyAttached {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            };
            return send_h2_empty_response(respond, status).await;
        }
    };

    let response =
        packet_up_download_h2_response().map_err(|err| io::Error::other(err.to_string()))?;
    let mut send = respond
        .send_response(response, false)
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;

    debug!(
        inbound_tag,
        conn_id,
        session_id = %session_id,
        "xhttp packet-up download stream opened"
    );

    loop {
        match tokio::time::timeout(PACKET_UP_DOWNLOAD_RECV_TIMEOUT, download_rx.recv()).await {
            Ok(Some(chunk)) => {
                if chunk.is_empty() {
                    continue;
                }
                if h2_send_chunk(&mut send, chunk).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                warn!(
                    inbound_tag,
                    conn_id,
                    session_id = %session_id,
                    timeout_secs = PACKET_UP_DOWNLOAD_RECV_TIMEOUT.as_secs(),
                    "xhttp packet-up download recv timed out"
                );
                break;
            }
        }
    }

    manager.detach_download_session(&session_id);
    let _ = send.send_data(Bytes::new(), true);
    Ok(())
}

async fn handle_packet_up_h2_upload(
    session_id: String,
    seq: Option<u64>,
    mut body: h2::RecvStream,
    respond: h2::server::SendResponse<Bytes>,
    inbound_tag: &str,
    conn_id: u64,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
    limits: PacketUpLimits,
) -> io::Result<()> {
    let manager = shared_packet_up_manager();
    let mut upload_handle = match manager.begin_upload_packet(&session_id, seq, limits) {
        Ok(handle) => handle,
        Err(err) => {
            warn!(
                inbound_tag,
                conn_id,
                session_id = %session_id,
                error = %err,
                "xhttp packet-up upload session rejected"
            );
            return send_h2_empty_response(respond, StatusCode::BAD_REQUEST).await;
        }
    };

    let mut upload_error: Option<String> = None;
    let mut total_bytes = 0usize;
    while let Some(data) = body.data().await {
        match data {
            Ok(chunk) => {
                let len = chunk.len();
                total_bytes += len;
                let _ = body.flow_control().release_capacity(len);
                match manager.append_upload_chunk(&mut upload_handle, chunk) {
                    Ok(Some(launch)) => {
                        spawn_packet_up_bridge(
                            launch,
                            Arc::clone(&users),
                            stats_state.clone(),
                            inbound_tag.to_string(),
                            conn_id,
                        );
                    }
                    Ok(None) => {}
                    Err(err) => {
                        upload_error = Some(err.to_string());
                        break;
                    }
                }
            }
            Err(err)
                if matches!(
                    err.reason(),
                    Some(h2::Reason::NO_ERROR | h2::Reason::CANCEL)
                ) =>
            {
                break;
            }
            Err(err) => {
                upload_error = Some(err.to_string());
                break;
            }
        }
    }

    let bridge_launch = if upload_error.is_none() {
        match manager.commit_upload_packet(&upload_handle) {
            Ok(outcome) => outcome.bridge_launch,
            Err(err) => {
                upload_error = Some(err.to_string());
                None
            }
        }
    } else {
        None
    };
    manager.finish_upload_packet(&session_id);

    if total_bytes > 0 {
        debug!(
            session_id = %session_id,
            seq = upload_handle.seq,
            bytes = total_bytes,
            "xhttp packet-up body appended"
        );
    }

    if let Some(launch) = bridge_launch {
        spawn_packet_up_bridge(launch, users, stats_state, inbound_tag.to_string(), conn_id);
    }

    if let Some(err) = upload_error {
        warn!(
            inbound_tag,
            conn_id,
            session_id = %session_id,
            seq = upload_handle.seq,
            error = %err,
            "xhttp packet-up upload failed"
        );
        let status = if err.contains("backpressure") {
            StatusCode::SERVICE_UNAVAILABLE
        } else if err.contains("scMaxEachPostBytes") || err.contains("PostTooLarge") {
            StatusCode::PAYLOAD_TOO_LARGE
        } else if err.contains("upload channel closed") || err.contains("session input closed") {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::BAD_REQUEST
        };
        return send_h2_empty_response(respond, status).await;
    }

    send_h2_empty_response(respond, StatusCode::OK).await
}

async fn handle_xhttp_h2_packet_up(
    request: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    settings: &XHttpSettings,
    inbound_tag: &str,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
    conn_id: u64,
) -> io::Result<()> {
    let method = request.method().as_str().to_string();
    let request_target = h2_request_target(&request);
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri().authority().map(|value| value.as_str()));

    log_xhttp_request_received(
        inbound_tag,
        conn_id,
        &method,
        &request_target,
        host,
        "HTTP/2",
    );

    let match_settings = xhttp_match_settings(settings);
    if !host_matches(match_settings.host, host, TransportSecurity::Reality) {
        log_xhttp_host_result(
            inbound_tag,
            conn_id,
            &match_settings,
            host,
            false,
            Some(XHttpMatchRejectReason::HostMismatch),
        );
        return send_h2_empty_response(respond, StatusCode::NOT_FOUND).await;
    }
    log_xhttp_host_result(inbound_tag, conn_id, &match_settings, host, true, None);

    let session_id = match extract_xhttp_session_id(&request, settings) {
        Ok(session_id) => session_id,
        Err(err) => {
            warn!(
                inbound_tag,
                conn_id,
                error = %err,
                "xhttp packet-up session extraction failed"
            );
            return send_h2_empty_response(respond, packet_up_error_status(&err)).await;
        }
    };

    if method_matches_packet_up_upload(&method) {
        let seq = match extract_xhttp_packet_seq_for_settings(&request, settings) {
            Ok(seq) => seq,
            Err(err) => {
                warn!(
                    inbound_tag,
                    conn_id,
                    session_id = %session_id,
                    error = %err,
                    "xhttp packet-up seq extraction failed"
                );
                return send_h2_empty_response(respond, packet_up_error_status(&err)).await;
            }
        };
        let body_hint = packet_up_body_hint(h2_content_length(&request), 0);
        debug!(
            inbound_tag,
            conn_id,
            session_id = %session_id,
            seq = ?seq,
            body_hint = %body_hint,
            "xhttp packet-up request received"
        );
        return handle_packet_up_h2_upload(
            session_id,
            seq,
            request.into_body(),
            respond,
            inbound_tag,
            conn_id,
            users,
            stats_state,
            PacketUpLimits::from_settings(settings),
        )
        .await;
    }

    if method_matches_packet_up_download(&method) {
        if extract_xhttp_packet_seq(&request).is_some() {
            return send_h2_empty_response(respond, StatusCode::BAD_REQUEST).await;
        }
        let body_hint = packet_up_body_hint(None, 0);
        debug!(
            inbound_tag,
            conn_id,
            session_id = %session_id,
            seq = None::<u64>,
            body_hint = %body_hint,
            "xhttp packet-up request received"
        );
        return handle_packet_up_h2_download(session_id, respond, inbound_tag, conn_id).await;
    }

    send_h2_empty_response(respond, StatusCode::METHOD_NOT_ALLOWED).await
}

async fn handle_packet_up_http1_download<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session_id: String,
    inbound_tag: &str,
    conn_id: u64,
) -> io::Result<()> {
    let manager = shared_packet_up_manager();
    let mut download_rx = match manager.bind_download_session(&session_id) {
        Ok(rx) => rx,
        Err(err) => {
            warn!(
                inbound_tag,
                conn_id,
                session_id = %session_id,
                error = %err,
                "xhttp packet-up download session rejected"
            );
            let status = if err == super::session::XHttpSessionError::DownloadAlreadyAttached {
                "409 Conflict"
            } else {
                "404 Not Found"
            };
            return write_status(stream, status).await;
        }
    };

    stream
        .write_all(PACKET_UP_DOWNLOAD_RESPONSE_HEADERS_HTTP1.as_bytes())
        .await?;
    debug!(
        inbound_tag,
        conn_id,
        session_id = %session_id,
        "xhttp packet-up download stream opened"
    );

    loop {
        match tokio::time::timeout(PACKET_UP_DOWNLOAD_RECV_TIMEOUT, download_rx.recv()).await {
            Ok(Some(chunk)) => {
                if chunk.is_empty() {
                    continue;
                }
                if write_http1_chunked_chunk(stream, &chunk).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                warn!(
                    inbound_tag,
                    conn_id,
                    session_id = %session_id,
                    timeout_secs = PACKET_UP_DOWNLOAD_RECV_TIMEOUT.as_secs(),
                    "xhttp packet-up download recv timed out"
                );
                break;
            }
        }
    }

    manager.detach_download_session(&session_id);
    write_http1_chunked_chunk(stream, &[]).await?;
    stream.shutdown().await
}

async fn read_http1_upload_bytes<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
) -> io::Result<usize> {
    let mut tmp = [0u8; HTTP1_UPLOAD_READ_BUFFER];
    let read = stream.read(&mut tmp).await?;
    if read > 0 {
        buffer.extend_from_slice(&tmp[..read]);
    }
    Ok(read)
}

fn chunked_size_line_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

fn parse_chunked_size_line(buffer: &[u8]) -> io::Result<usize> {
    let line_end = chunked_size_line_end(buffer).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed xhttp packet-up chunked upload: missing chunk size line",
        )
    })?;
    let size_line = std::str::from_utf8(&buffer[..line_end]).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed xhttp packet-up chunked upload: {err}"),
        )
    })?;
    let size_hex = size_line.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(size_hex, 16).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed xhttp packet-up chunked upload chunk size: {err}"),
        )
    })
}

async fn stream_http1_chunked_upload<S, F>(
    stream: &mut S,
    mut buffer: Vec<u8>,
    mut on_chunk: F,
) -> Result<(), String>
where
    S: AsyncRead + Unpin,
    F: FnMut(Bytes) -> Result<(), String>,
{
    loop {
        while chunked_size_line_end(&buffer).is_none() {
            if read_http1_upload_bytes(stream, &mut buffer)
                .await
                .map_err(|err| err.to_string())?
                == 0
            {
                return Err(
                    "truncated xhttp packet-up chunked upload before chunk size line".to_string(),
                );
            }
        }
        let size = parse_chunked_size_line(&buffer).map_err(|err| err.to_string())?;
        let line_end = chunked_size_line_end(&buffer).expect("size line present");
        buffer.drain(..line_end + 2);

        if size == 0 {
            while chunked_size_line_end(&buffer).is_none() {
                if read_http1_upload_bytes(stream, &mut buffer)
                    .await
                    .map_err(|err| err.to_string())?
                    == 0
                {
                    break;
                }
            }
            return Ok(());
        }

        while buffer.len() < size + 2 {
            if read_http1_upload_bytes(stream, &mut buffer)
                .await
                .map_err(|err| err.to_string())?
                == 0
            {
                return Err("truncated xhttp packet-up chunked upload body".to_string());
            }
        }
        if &buffer[size..size + 2] != b"\r\n" {
            return Err("malformed xhttp packet-up chunked upload chunk terminator".to_string());
        }
        let chunk = Bytes::copy_from_slice(&buffer[..size]);
        buffer.drain(..size + 2);
        on_chunk(chunk)?;
    }
}

async fn stream_http1_content_length_upload<S, F>(
    stream: &mut S,
    prebuffer: Vec<u8>,
    content_length: Option<u64>,
    mut on_chunk: F,
) -> Result<(), String>
where
    S: AsyncRead + Unpin,
    F: FnMut(Bytes) -> Result<(), String>,
{
    let expected = content_length.unwrap_or(0) as usize;
    let mut received = prebuffer.len();
    if !prebuffer.is_empty() {
        on_chunk(Bytes::from(prebuffer))?;
    }
    while received < expected {
        let to_read = (expected - received).min(HTTP1_UPLOAD_READ_BUFFER);
        let mut buf = vec![0u8; to_read];
        let read = stream.read(&mut buf).await.map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("truncated xhttp packet-up upload body".to_string());
        }
        received += read;
        on_chunk(Bytes::from(buf[..read].to_vec()))?;
    }
    Ok(())
}

async fn stream_http1_packet_up_upload_body<S, F>(
    stream: &mut S,
    prebuffer: Vec<u8>,
    content_length: Option<u64>,
    transfer_encoding: Option<&str>,
    on_chunk: F,
) -> Result<(), String>
where
    S: AsyncRead + Unpin,
    F: FnMut(Bytes) -> Result<(), String>,
{
    if transfer_encoding.is_some_and(|value| value.to_ascii_lowercase().contains("chunked")) {
        stream_http1_chunked_upload(stream, prebuffer, on_chunk).await
    } else {
        stream_http1_content_length_upload(stream, prebuffer, content_length, on_chunk).await
    }
}

fn packet_up_upload_error_status(err: &str) -> &'static str {
    if err.contains("backpressure") {
        "503 Service Unavailable"
    } else if err.contains("scMaxEachPostBytes") || err.contains("PostTooLarge") {
        "413 Payload Too Large"
    } else {
        "400 Bad Request"
    }
}

async fn handle_packet_up_http1_upload<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    head: &XHttpRequestHead,
    prebuffer: Vec<u8>,
    session_id: String,
    seq: Option<u64>,
    inbound_tag: &str,
    conn_id: u64,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
    limits: PacketUpLimits,
) -> io::Result<()> {
    let manager = shared_packet_up_manager();
    let mut upload_handle = match manager.begin_upload_packet(&session_id, seq, limits) {
        Ok(handle) => handle,
        Err(err) => {
            warn!(
                inbound_tag,
                conn_id,
                session_id = %session_id,
                error = %err,
                "xhttp packet-up upload session rejected"
            );
            return write_status(stream, "400 Bad Request").await;
        }
    };

    let content_length = request_content_length(head).ok().flatten();
    let transfer_encoding = head.header("transfer-encoding").map(str::to_string);
    let mut upload_error: Option<String> = None;
    let mut bridge_launch = None;
    let mut total_bytes = 0usize;
    match stream_http1_packet_up_upload_body(
        stream,
        prebuffer,
        content_length,
        transfer_encoding.as_deref(),
        |chunk| {
            if chunk.is_empty() {
                return Ok(());
            }
            total_bytes += chunk.len();
            match manager.append_upload_chunk(&mut upload_handle, chunk) {
                Ok(Some(launch)) => {
                    bridge_launch = Some(launch);
                    Ok(())
                }
                Ok(None) => Ok(()),
                Err(err) => Err(err.to_string()),
            }
        },
    )
    .await
    {
        Ok(()) => {}
        Err(err)
            if err.contains("malformed")
                || err.contains("truncated")
                || err.contains("chunk size") =>
        {
            warn!(
                inbound_tag,
                conn_id,
                session_id = %session_id,
                error = %err,
                "xhttp packet-up upload body read failed"
            );
            manager.finish_upload_packet(&session_id);
            return write_status(stream, "400 Bad Request").await;
        }
        Err(err) => upload_error = Some(err),
    }

    if upload_error.is_none() {
        match manager.commit_upload_packet(&upload_handle) {
            Ok(outcome) => {
                if bridge_launch.is_none() {
                    bridge_launch = outcome.bridge_launch;
                }
            }
            Err(err) => upload_error = Some(err.to_string()),
        }
    }
    manager.finish_upload_packet(&session_id);

    if total_bytes > 0 {
        debug!(
            session_id = %session_id,
            seq = upload_handle.seq,
            bytes = total_bytes,
            "xhttp packet-up body appended"
        );
    }

    if let Some(launch) = bridge_launch {
        spawn_packet_up_bridge(launch, users, stats_state, inbound_tag.to_string(), conn_id);
    }

    if let Some(err) = upload_error {
        warn!(
            inbound_tag,
            conn_id,
            session_id = %session_id,
            seq = upload_handle.seq,
            error = %err,
            "xhttp packet-up upload failed"
        );
        return write_status(stream, packet_up_upload_error_status(&err)).await;
    }

    write_status(stream, "200 OK").await
}

async fn handle_xhttp_http1_packet_up<S>(
    mut stream: S,
    settings: &XHttpSettings,
    head: &XHttpRequestHead,
    prebuffer: Vec<u8>,
    inbound_tag: &str,
    conn_id: u64,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let match_settings = xhttp_match_settings(settings);
    if !host_matches(
        match_settings.host,
        head.header("host"),
        TransportSecurity::Reality,
    ) {
        return write_status(&mut stream, "404 Not Found").await;
    }

    if method_matches_packet_up_upload(&head.method) {
        let session_id = match extract_session_id_from_request_target(
            settings,
            &head.request_target,
        ) {
            Ok(session_id) => session_id,
            Err(err) => {
                warn!(inbound_tag, conn_id, error = %err, "xhttp packet-up session extraction failed");
                return write_status(&mut stream, "400 Bad Request").await;
            }
        };
        let seq = match extract_packet_up_upload_seq(settings, &head.request_target) {
            Ok(seq) => seq,
            Err(err) => {
                warn!(inbound_tag, conn_id, error = %err, "xhttp packet-up seq extraction failed");
                return write_status(&mut stream, "400 Bad Request").await;
            }
        };
        return handle_packet_up_http1_upload(
            &mut stream,
            head,
            prebuffer,
            session_id,
            seq,
            inbound_tag,
            conn_id,
            users,
            stats_state,
            PacketUpLimits::from_settings(settings),
        )
        .await;
    }

    if method_matches_packet_up_download(&head.method) {
        let parsed = match parse_packet_up_path(settings.effective_path(), &head.request_target) {
            Some(parsed) => parsed,
            None => return write_status(&mut stream, "404 Not Found").await,
        };
        if parsed.seq.is_some() {
            return write_status(&mut stream, "400 Bad Request").await;
        }
        let session_id =
            match extract_session_id_from_request_target(settings, &head.request_target) {
                Ok(session_id) => session_id,
                Err(_) => return write_status(&mut stream, "400 Bad Request").await,
            };
        return handle_packet_up_http1_download(&mut stream, session_id, inbound_tag, conn_id)
            .await;
    }

    write_status(&mut stream, "405 Method Not Allowed").await
}

async fn write_status<S: AsyncWrite + Unpin>(stream: &mut S, status: &str) -> std::io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

pub async fn serve_xhttp_stream_one<S>(
    mut stream: S,
    settings: &XHttpSettings,
    users: Arc<VlessUserManager>,
    stats_state: Option<&StatsState>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let effective_mode = resolve_xhttp_mode_for_settings(settings, TransportSecurity::Reality)
        .map_err(|err| {
            warn!(inbound_tag = users.inbound_tag(), error = %err, "xhttp mode resolution failed");
            std::io::Error::from(err)
        })?;
    let inbound_tag = users.inbound_tag().to_string();

    let mut preface = Vec::with_capacity(HTTP2_PREFACE.len());
    while preface.len() < HTTP2_PREFACE.len() {
        let mut byte = [0u8; 1];
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream closed before XHTTP request preface",
            ));
        }
        preface.push(byte[0]);
    }
    let prefixed = PrefixedStream::new(stream, preface.clone());
    if preface.as_slice() == HTTP2_PREFACE {
        return serve_xhttp_h2_stream_one(
            prefixed,
            settings,
            &inbound_tag,
            users,
            stats_state.cloned(),
            effective_mode,
        )
        .await;
    }
    serve_xhttp_http1_stream_one(
        prefixed,
        settings,
        &inbound_tag,
        users,
        stats_state.cloned(),
        effective_mode,
    )
    .await
}

async fn serve_xhttp_http1_stream_one<S>(
    mut stream: S,
    settings: &XHttpSettings,
    inbound_tag: &str,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
    effective_mode: EffectiveXHttpMode,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn_id = NEXT_XHTTP_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let (head, prebuffer) = match read_http_head(&mut stream).await {
        Ok(value) => value,
        Err(err) => {
            warn!(inbound_tag, conn_id, error = %err, "xhttp request header parse failed");
            return Err(err);
        }
    };
    log_xhttp_request_received(
        inbound_tag,
        conn_id,
        &head.method,
        &head.request_target,
        head.header("host"),
        &head.version,
    );

    if is_download_side_request(&head.method, &head.request_target, settings, effective_mode) {
        return reject_download_side_http1(
            &mut stream,
            settings,
            &head,
            &prebuffer,
            inbound_tag,
            conn_id,
            effective_mode,
        )
        .await;
    }

    if let Some(reason) = xhttp_runtime_unsupported_reason(settings, effective_mode) {
        return reject_unsupported_xhttp_http1(
            &mut stream,
            settings,
            &head,
            prebuffer,
            inbound_tag,
            conn_id,
            effective_mode,
            reason,
        )
        .await;
    }

    if effective_mode == EffectiveXHttpMode::PacketUp {
        return handle_xhttp_http1_packet_up(
            stream,
            settings,
            &head,
            prebuffer,
            inbound_tag,
            conn_id,
            users,
            stats_state,
        )
        .await;
    }

    debug!(
        inbound_tag,
        conn_id,
        requested_mode = settings.effective_mode(),
        effective_mode = effective_xhttp_mode_label(effective_mode),
        "xhttp mode detected/requested"
    );

    let request = XHttpRequestDescriptor {
        method: &head.method,
        request_target: &head.request_target,
        host: head.header("host"),
    };
    if let Err(status) = validate_stream_one_request_match(inbound_tag, conn_id, settings, &request)
    {
        return match status {
            XHttpRequestRejectStatus::NotFound => {
                write_status(&mut stream, "404 Not Found").await?;
                Ok(())
            }
            XHttpRequestRejectStatus::MethodNotAllowed => {
                write_status(&mut stream, "405 Method Not Allowed").await?;
                Ok(())
            }
        };
    }

    if head
        .header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        warn!(
            inbound_tag,
            conn_id, "xhttp chunked request body is not implemented in MVP"
        );
        debug!(
            inbound_tag,
            conn_id,
            reason = "chunked_request_body",
            "xhttp request rejected"
        );
        write_status(&mut stream, "501 Not Implemented").await?;
        return Ok(());
    }

    let content_length = request_content_length(&head)?;
    run_http1_stream_one_bridge(
        stream,
        Bytes::from(prebuffer),
        content_length,
        inbound_tag,
        conn_id,
        started,
        users.as_ref(),
        stats_state.as_ref(),
    )
    .await
}

async fn serve_xhttp_h2_stream_one<S>(
    stream: S,
    settings: &XHttpSettings,
    inbound_tag: &str,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
    effective_mode: EffectiveXHttpMode,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn_id = NEXT_XHTTP_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let mut connection = h2::server::handshake(stream).await.map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("xhttp h2 handshake failed: {err}"),
        )
    })?;
    let Some(request) = connection.accept().await else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "xhttp h2 connection closed before request",
        ));
    };
    let (request, respond) = request.map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("xhttp h2 request failed: {err}"),
        )
    })?;
    let settings_for_driver = settings.clone();
    let packet_up = effective_mode == EffectiveXHttpMode::PacketUp
        && xhttp_runtime_unsupported_reason(&settings_for_driver, effective_mode).is_none();
    let inbound_tag_driver = inbound_tag.to_string();
    let users_driver = Arc::clone(&users);
    let stats_driver = stats_state.clone();
    let driver = tokio::spawn(async move {
        while let Some(request) = connection.accept().await {
            let Ok((request, mut respond)) = request else {
                continue;
            };
            if packet_up {
                let users = Arc::clone(&users_driver);
                let stats = stats_driver.clone();
                let inbound_tag = inbound_tag_driver.clone();
                let settings = settings_for_driver.clone();
                tokio::spawn(async move {
                    let _ = handle_xhttp_h2_packet_up(
                        request,
                        respond,
                        &settings,
                        &inbound_tag,
                        users,
                        stats,
                        conn_id,
                    )
                    .await;
                });
                continue;
            }
            let response = match Response::builder().status(StatusCode::NOT_FOUND).body(()) {
                Ok(response) => response,
                Err(_) => continue,
            };
            if let Ok(mut send) = respond.send_response(response, false) {
                let _ = send.send_data(Bytes::new(), true);
            }
        }
    });
    let result = handle_xhttp_h2_request(
        request,
        respond,
        settings,
        inbound_tag,
        users,
        stats_state,
        conn_id,
        started,
        effective_mode,
    )
    .await;
    driver.abort();
    result
}

async fn handle_xhttp_h2_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    settings: &XHttpSettings,
    inbound_tag: &str,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
    conn_id: u64,
    started: Instant,
    effective_mode: EffectiveXHttpMode,
) -> io::Result<()> {
    if is_download_side_request(
        request.method().as_str(),
        &h2_request_target(&request),
        settings,
        effective_mode,
    ) {
        return reject_download_side_h2(
            request,
            respond,
            settings,
            inbound_tag,
            conn_id,
            0,
            effective_mode,
        )
        .await;
    }

    let method = request.method().as_str().to_string();
    let request_target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri().authority().map(|value| value.as_str()));

    if let Some(reason) = xhttp_runtime_unsupported_reason(settings, effective_mode) {
        if effective_mode == EffectiveXHttpMode::PacketUp {
            return reject_unsupported_xhttp_h2_packet_up(
                request,
                respond,
                settings,
                inbound_tag,
                conn_id,
                reason,
            )
            .await;
        }
        return reject_unsupported_xhttp_h2_with_request(
            request,
            respond,
            settings,
            inbound_tag,
            conn_id,
            effective_mode,
            reason,
        )
        .await;
    }

    if effective_mode == EffectiveXHttpMode::PacketUp {
        return handle_xhttp_h2_packet_up(
            request,
            respond,
            settings,
            inbound_tag,
            users,
            stats_state,
            conn_id,
        )
        .await;
    }

    log_xhttp_request_received(
        inbound_tag,
        conn_id,
        &method,
        &request_target,
        host,
        "HTTP/2",
    );

    debug!(
        inbound_tag,
        conn_id,
        requested_mode = settings.effective_mode(),
        effective_mode = effective_xhttp_mode_label(effective_mode),
        "xhttp mode detected/requested"
    );

    let request_descriptor = XHttpRequestDescriptor {
        method: &method,
        request_target: &request_target,
        host,
    };
    if let Err(status) =
        validate_stream_one_request_match(inbound_tag, conn_id, settings, &request_descriptor)
    {
        let status_code = match status {
            XHttpRequestRejectStatus::NotFound => StatusCode::NOT_FOUND,
            XHttpRequestRejectStatus::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        };
        let response = Response::builder()
            .status(status_code)
            .body(())
            .map_err(|err| io::Error::other(err.to_string()))?;
        let mut send = respond
            .send_response(response, false)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        let _ = send.send_data(Bytes::new(), true);
        return Ok(());
    }

    run_h2_stream_one_bridge(
        request.into_body(),
        respond,
        inbound_tag,
        conn_id,
        started,
        users.as_ref(),
        stats_state.as_ref(),
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/unit/transport/xhttp/transport.rs"]
mod tests;
