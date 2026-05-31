use std::collections::BTreeMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

use crate::config::XHttpSettings;
use crate::stats::StatsState;
use crate::vless::{handle_vless_tcp_inbound, VlessUserManager};

const MAX_HTTP_HEADER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XHttpMode {
    StreamOne,
    Unsupported(String),
}

pub fn select_xhttp_mode(settings: &XHttpSettings) -> XHttpMode {
    match settings.effective_mode().to_ascii_lowercase().as_str() {
        "auto" | "stream-one" => XHttpMode::StreamOne,
        other => XHttpMode::Unsupported(other.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XHttpRequestHead {
    method: String,
    path: String,
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
    response_finished: bool,
}

impl<S> XHttpDuplexStream<S> {
    pub fn new(inner: S, prebuffer: Vec<u8>, content_length: Option<u64>) -> Self {
        Self {
            inner,
            prebuffer,
            prebuffer_pos: 0,
            remaining_request_body: content_length,
            pending_write: Vec::new(),
            pending_write_pos: 0,
            response_finished: false,
        }
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
                    }
                }
                result
            }
            None => {
                let result = Pin::new(&mut self.inner).poll_read(cx, buf);
                if let Poll::Ready(Ok(())) = &result {
                    if buf.filled().len() == before {
                        self.remaining_request_body = Some(0);
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
    let path = request_parts.next().unwrap_or("").to_string();
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
            path,
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

fn host_matches(configured: Option<&str>, received: Option<&str>) -> bool {
    let Some(configured) = configured.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    received.is_some_and(|host| host.eq_ignore_ascii_case(configured))
}

async fn write_status<S: AsyncWrite + Unpin>(stream: &mut S, status: &str) -> std::io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

pub async fn serve_xhttp_stream_one<S>(
    mut stream: S,
    settings: &XHttpSettings,
    inbound_tag: &str,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (head, prebuffer) = match read_http_head(&mut stream).await {
        Ok(value) => value,
        Err(err) => {
            warn!(inbound_tag, error = %err, "xhttp request header parse failed");
            return Err(err);
        }
    };
    debug!(
        inbound_tag,
        method = %head.method,
        path = %head.path,
        "xhttp request received"
    );

    match select_xhttp_mode(settings) {
        XHttpMode::StreamOne => {
            debug!(inbound_tag, mode = "stream-one", "xhttp mode selected");
        }
        XHttpMode::Unsupported(mode) => {
            warn!(inbound_tag, mode, "xhttp mode unsupported");
            write_status(&mut stream, "501 Not Implemented").await?;
            return Ok(());
        }
    }

    if head.path != settings.effective_path() {
        debug!(
            inbound_tag,
            configured_path = settings.effective_path(),
            request_path = %head.path,
            "xhttp path rejected"
        );
        write_status(&mut stream, "404 Not Found").await?;
        return Ok(());
    }
    debug!(inbound_tag, "xhttp path accepted");

    if !host_matches(settings.host.as_deref(), head.header("host")) {
        debug!(
            inbound_tag,
            configured_host = ?settings.host,
            request_host = ?head.header("host"),
            "xhttp host rejected"
        );
        write_status(&mut stream, "404 Not Found").await?;
        return Ok(());
    }

    if !head.method.eq_ignore_ascii_case("POST") {
        debug!(inbound_tag, method = %head.method, "xhttp method rejected");
        write_status(&mut stream, "405 Method Not Allowed").await?;
        return Ok(());
    }

    if head
        .header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        warn!(
            inbound_tag,
            "xhttp chunked request body is not implemented in MVP"
        );
        write_status(&mut stream, "501 Not Implemented").await?;
        return Ok(());
    }

    let content_length = request_content_length(&head)?;
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await?;
    stream.flush().await?;

    debug!(inbound_tag, "xhttp bridge started");
    let bridge = XHttpDuplexStream::new(stream, prebuffer, content_length);
    let result = handle_vless_tcp_inbound(bridge, users, stats_state).await;
    match &result {
        Ok(()) => debug!(inbound_tag, "xhttp bridge completed"),
        Err(err) => warn!(inbound_tag, error = %err, "xhttp bridge failed"),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::VlessUserManager;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn select_xhttp_mode_accepts_auto_and_stream_one() {
        let auto = XHttpSettings::default();
        assert_eq!(select_xhttp_mode(&auto), XHttpMode::StreamOne);
        let stream_one = XHttpSettings {
            mode: Some("stream-one".to_string()),
            ..XHttpSettings::default()
        };
        assert_eq!(select_xhttp_mode(&stream_one), XHttpMode::StreamOne);
    }

    #[test]
    fn select_xhttp_mode_rejects_packet_modes_for_mvp() {
        let packet = XHttpSettings {
            mode: Some("packet-up".to_string()),
            ..XHttpSettings::default()
        };
        assert_eq!(
            select_xhttp_mode(&packet),
            XHttpMode::Unsupported("packet-up".to_string())
        );
    }

    #[tokio::test]
    async fn xhttp_duplex_reads_prebuffer_then_body_limit() {
        let (mut client, server) = tokio::io::duplex(128);
        client.write_all(b"worldextra").await.unwrap();
        let mut xhttp = XHttpDuplexStream::new(server, b"hello".to_vec(), Some(10));
        let mut out = Vec::new();
        xhttp.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"helloworld");
    }

    #[tokio::test]
    async fn xhttp_duplex_writes_chunked_response() {
        let (client, server) = tokio::io::duplex(128);
        let mut xhttp = XHttpDuplexStream::new(server, Vec::new(), Some(0));
        xhttp.write_all(b"pong").await.unwrap();
        xhttp.shutdown().await.unwrap();
        let mut client = client;
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"4\r\npong\r\n0\r\n\r\n");
    }

    async fn run_request(settings: XHttpSettings, request: &'static [u8]) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(2048);
        let users = VlessUserManager::new("xhttp-test", Vec::new());
        let task = tokio::spawn(async move {
            serve_xhttp_stream_one(server, &settings, "xhttp-test", &users, None).await
        });
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let _ = task.await.unwrap();
        response
    }

    #[tokio::test]
    async fn wrong_path_is_rejected() {
        let settings = XHttpSettings {
            path: "/xhttp".to_string(),
            ..XHttpSettings::default()
        };
        let response = run_request(
            settings,
            b"POST /wrong HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn wrong_host_is_rejected_when_configured() {
        let settings = XHttpSettings {
            path: "/xhttp".to_string(),
            host: Some("example.com".to_string()),
            ..XHttpSettings::default()
        };
        let response = run_request(
            settings,
            b"POST /xhttp HTTP/1.1\r\nHost: other.example\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn get_is_rejected_for_stream_one() {
        let settings = XHttpSettings {
            path: "/xhttp".to_string(),
            ..XHttpSettings::default()
        };
        let response = run_request(
            settings,
            b"GET /xhttp HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 405 Method Not Allowed"));
    }

    #[tokio::test]
    async fn correct_path_starts_stream_one_response() {
        let settings = XHttpSettings {
            path: "/xhttp".to_string(),
            ..XHttpSettings::default()
        };
        let response = run_request(
            settings,
            b"POST /xhttp HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
    }
}
