use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use crate::stats::StatsState;
use crate::vless::{handle_vless_tcp_inbound_with_response_hook, VlessUserManager};

pub const XHTTP_BRIDGE_CHANNEL_CAPACITY: usize = 16;
pub const XHTTP_BRIDGE_READ_CHUNK: usize = 16 * 1024;
pub const XHTTP_BRIDGE_WRITE_TIMEOUT: Duration = Duration::from_secs(120);

const HTTP1_CHUNKED_RESPONSE_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

type ChunkResult = Result<Bytes, io::Error>;

pub struct XHttpBridgeStream {
    reader: BridgeRequestReader,
    writer: BridgeResponseWriter,
}

struct BridgeRequestReader {
    conn_id: u64,
    rx: mpsc::Receiver<ChunkResult>,
    current: Option<Bytes>,
    pos: usize,
    eof_logged: bool,
}

struct BridgeResponseWriter {
    #[allow(dead_code)]
    conn_id: u64,
    tx: mpsc::Sender<ChunkResult>,
    pending: Option<Bytes>,
}

struct BridgePumps {
    request_pump: tokio::task::JoinHandle<()>,
    response_pump: tokio::task::JoinHandle<()>,
}

pub async fn run_http1_stream_one_bridge<S>(
    stream: S,
    prebuffer: Bytes,
    content_length: Option<u64>,
    inbound_tag: &str,
    conn_id: u64,
    started: Instant,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!(inbound_tag, conn_id, "xhttp bridge started");

    let (read_half, write_half) = tokio::io::split(stream);
    let (req_tx, req_rx) = mpsc::channel(XHTTP_BRIDGE_CHANNEL_CAPACITY);
    let (resp_tx, resp_rx) = mpsc::channel(XHTTP_BRIDGE_CHANNEL_CAPACITY);

    let http_response_started = Arc::new(AtomicBool::new(false));
    let writer = Arc::new(Mutex::new(write_half));

    let request_pump = tokio::spawn(pump_http1_request_body(
        read_half,
        prebuffer,
        content_length,
        req_tx,
        conn_id,
    ));

    let response_started = Arc::clone(&http_response_started);
    let response_writer = Arc::clone(&writer);
    let response_pump = tokio::spawn(pump_http1_response_body(
        resp_rx,
        response_writer,
        response_started,
        conn_id,
    ));

    let bridge = XHttpBridgeStream {
        reader: BridgeRequestReader {
            conn_id,
            rx: req_rx,
            current: None,
            pos: 0,
            eof_logged: false,
        },
        writer: BridgeResponseWriter {
            conn_id,
            tx: resp_tx,
            pending: None,
        },
    };

    let hook_started = Arc::clone(&http_response_started);
    let hook_writer = Arc::clone(&writer);
    let result = handle_vless_tcp_inbound_with_response_hook(
        bridge,
        users,
        stats_state,
        move || async move {
            let mut writer = hook_writer.lock().await;
            writer
                .write_all(HTTP1_CHUNKED_RESPONSE_HEAD)
                .await
                .map_err(|err| {
                    io::Error::other(format!("xhttp response head write failed: {err}"))
                })?;
            writer.flush().await.map_err(|err| {
                io::Error::other(format!("xhttp response head flush failed: {err}"))
            })?;
            hook_started.store(true, Ordering::Release);
            Ok(())
        },
    )
    .await;

    finish_bridge_http1(
        inbound_tag,
        conn_id,
        started,
        BridgePumps {
            request_pump,
            response_pump,
        },
        writer,
        result,
    )
    .await
}

pub async fn run_h2_stream_one_bridge(
    recv: h2::RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
    inbound_tag: &str,
    conn_id: u64,
    started: Instant,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> io::Result<()> {
    debug!(inbound_tag, conn_id, "xhttp bridge started");

    let (req_tx, req_rx) = mpsc::channel(XHTTP_BRIDGE_CHANNEL_CAPACITY);
    let (resp_tx, resp_rx) = mpsc::channel(XHTTP_BRIDGE_CHANNEL_CAPACITY);
    let (send_tx, send_rx) = oneshot::channel();

    let http_response_started = Arc::new(AtomicBool::new(false));

    let request_pump = tokio::spawn(pump_h2_request_body(recv, req_tx, conn_id));

    let response_started = Arc::clone(&http_response_started);
    let response_pump = tokio::spawn(pump_h2_response_body(
        resp_rx,
        send_rx,
        response_started,
        conn_id,
    ));

    let bridge = XHttpBridgeStream {
        reader: BridgeRequestReader {
            conn_id,
            rx: req_rx,
            current: None,
            pos: 0,
            eof_logged: false,
        },
        writer: BridgeResponseWriter {
            conn_id,
            tx: resp_tx,
            pending: None,
        },
    };

    let hook_started = Arc::clone(&http_response_started);
    let result = handle_vless_tcp_inbound_with_response_hook(
        bridge,
        users,
        stats_state,
        move || async move {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/octet-stream")
                .body(())
                .map_err(|err| io::Error::other(err.to_string()))?;
            let send = respond
                .send_response(response, false)
                .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
            hook_started.store(true, Ordering::Release);
            send_tx.send(send).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "xhttp h2 send stream lost")
            })?;
            Ok(())
        },
    )
    .await;

    finish_bridge_common(
        inbound_tag,
        conn_id,
        started,
        BridgePumps {
            request_pump,
            response_pump,
        },
        result,
    )
    .await
}

async fn finish_bridge_common(
    inbound_tag: &str,
    conn_id: u64,
    started: Instant,
    pumps: BridgePumps,
    result: io::Result<()>,
) -> io::Result<()> {
    pumps.request_pump.abort();
    if !pumps.response_pump.is_finished() {
        pumps.response_pump.abort();
    }
    let _ = pumps.response_pump.await;

    match result {
        Ok(()) => {
            debug!(
                inbound_tag,
                conn_id,
                duration_ms = started.elapsed().as_millis(),
                "xhttp bridge completed"
            );
            Ok(())
        }
        Err(err) => {
            let reason = bridge_failure_reason(&err);
            debug!(
                inbound_tag,
                conn_id,
                reason,
                duration_ms = started.elapsed().as_millis(),
                "xhttp bridge failed"
            );
            warn!(inbound_tag, conn_id, reason, "xhttp bridge failed");
            Err(err)
        }
    }
}

async fn finish_bridge_http1<W>(
    inbound_tag: &str,
    conn_id: u64,
    started: Instant,
    pumps: BridgePumps,
    writer: Arc<Mutex<W>>,
    result: io::Result<()>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let result = finish_bridge_common(inbound_tag, conn_id, started, pumps, result).await;
    if let Ok(mut writer) = writer.try_lock() {
        let _ = writer.shutdown().await;
    }
    result
}

fn bridge_failure_reason(err: &io::Error) -> &'static str {
    match err.kind() {
        io::ErrorKind::PermissionDenied => "vless_auth_failed",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        io::ErrorKind::TimedOut => "write_timeout",
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => "client_disconnect",
        _ => "relay_error",
    }
}

async fn pump_http1_request_body<R>(
    mut reader: R,
    prebuffer: Bytes,
    content_length: Option<u64>,
    tx: mpsc::Sender<ChunkResult>,
    conn_id: u64,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut remaining = content_length;

    if !prebuffer.is_empty() {
        let chunk = match remaining {
            Some(rem) => prebuffer.slice(..rem.min(prebuffer.len() as u64) as usize),
            None => prebuffer,
        };
        if let Some(rem) = remaining.as_mut() {
            *rem = rem.saturating_sub(chunk.len() as u64);
        }
        if !send_request_chunk(&tx, conn_id, chunk).await {
            return;
        }
    }

    loop {
        if remaining == Some(0) {
            break;
        }
        let max_read = remaining
            .map(|rem| rem.min(XHTTP_BRIDGE_READ_CHUNK as u64) as usize)
            .unwrap_or(XHTTP_BRIDGE_READ_CHUNK);
        let mut buf = vec![0u8; max_read];
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if let Some(rem) = remaining.as_mut() {
                    *rem = rem.saturating_sub(n as u64);
                }
                if !send_request_chunk(&tx, conn_id, Bytes::copy_from_slice(&buf[..n])).await {
                    return;
                }
            }
            Err(err) => {
                tx.send(Err(err)).await.ok();
                return;
            }
        }
    }

    debug!(conn_id, "xhttp request body eof");
}

async fn send_request_chunk(tx: &mpsc::Sender<ChunkResult>, conn_id: u64, data: Bytes) -> bool {
    if data.is_empty() {
        return true;
    }
    trace!(conn_id, bytes = data.len(), "xhttp request body chunk");
    debug!(conn_id, bytes = data.len(), "xhttp request body chunk");
    tx.send(Ok(data)).await.is_ok()
}

async fn pump_http1_response_body<W>(
    mut resp_rx: mpsc::Receiver<ChunkResult>,
    writer: Arc<Mutex<W>>,
    http_response_started: Arc<AtomicBool>,
    conn_id: u64,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    while let Some(chunk) = resp_rx.recv().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                warn!(conn_id, error = %err, "xhttp response pump read error");
                break;
            }
        };
        if !http_response_started.load(Ordering::Acquire) {
            continue;
        }
        trace!(conn_id, bytes = chunk.len(), "xhttp response body chunk");
        debug!(conn_id, bytes = chunk.len(), "xhttp response body chunk");
        if let Err(err) = write_chunked_with_timeout(&writer, &chunk, conn_id).await {
            warn!(conn_id, error = %err, "xhttp response pump write failed");
            break;
        }
    }

    if http_response_started.load(Ordering::Acquire) {
        let _ = write_chunked_with_timeout(&writer, &[], conn_id).await;
        let mut writer = writer.lock().await;
        let _ = writer.flush().await;
    }
}

async fn pump_h2_request_body(
    mut recv: h2::RecvStream,
    tx: mpsc::Sender<ChunkResult>,
    conn_id: u64,
) {
    loop {
        match recv.data().await {
            Some(Ok(chunk)) => {
                let len = chunk.len();
                let _ = recv.flow_control().release_capacity(len);
                if !send_request_chunk(&tx, conn_id, chunk).await {
                    return;
                }
            }
            Some(Err(err))
                if matches!(
                    err.reason(),
                    Some(h2::Reason::NO_ERROR | h2::Reason::CANCEL)
                ) =>
            {
                break;
            }
            Some(Err(err)) => {
                tx.send(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!("xhttp h2 request body error: {err}"),
                )))
                .await
                .ok();
                return;
            }
            None => break,
        }
    }
    debug!(conn_id, "xhttp request body eof");
}

async fn pump_h2_response_body(
    mut resp_rx: mpsc::Receiver<ChunkResult>,
    send_rx: oneshot::Receiver<h2::SendStream<Bytes>>,
    http_response_started: Arc<AtomicBool>,
    conn_id: u64,
) {
    let Ok(mut send) = send_rx.await else {
        return;
    };

    while let Some(chunk) = resp_rx.recv().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                warn!(conn_id, error = %err, "xhttp response pump read error");
                break;
            }
        };
        if !http_response_started.load(Ordering::Acquire) {
            continue;
        }
        trace!(conn_id, bytes = chunk.len(), "xhttp response body chunk");
        debug!(conn_id, bytes = chunk.len(), "xhttp response body chunk");
        if chunk.is_empty() {
            continue;
        }
        if let Err(err) = h2_send_chunk(&mut send, chunk).await {
            warn!(conn_id, error = %err, "xhttp h2 response write failed");
            break;
        }
    }

    if http_response_started.load(Ordering::Acquire) {
        let _ = send.send_data(Bytes::new(), true);
    }
}

async fn h2_send_chunk(send: &mut h2::SendStream<Bytes>, chunk: Bytes) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < chunk.len() {
        send.reserve_capacity(chunk.len() - offset);
        let capacity = timeout(
            XHTTP_BRIDGE_WRITE_TIMEOUT,
            poll_fn(|cx| send.poll_capacity(cx)),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "xhttp h2 response capacity timed out after {XHTTP_BRIDGE_WRITE_TIMEOUT:?}"
                ),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "xhttp h2 response stream closed")
        })?
        .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        if capacity == 0 {
            continue;
        }
        let end = (offset + capacity).min(chunk.len());
        let data = chunk.slice(offset..end);
        offset = end;
        send.send_data(data, false)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
    }
    Ok(())
}

async fn write_chunked_with_timeout<W>(
    writer: &Arc<Mutex<W>>,
    chunk: &[u8],
    conn_id: u64,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let writer = Arc::clone(writer);
    let chunk = Bytes::copy_from_slice(chunk);
    timeout(XHTTP_BRIDGE_WRITE_TIMEOUT, async move {
        let mut writer = writer.lock().await;
        if chunk.is_empty() {
            writer.write_all(b"0\r\n\r\n").await?;
        } else {
            let header = format!("{:x}\r\n", chunk.len());
            writer.write_all(header.as_bytes()).await?;
            writer.write_all(&chunk).await?;
            writer.write_all(b"\r\n").await?;
        }
        writer.flush().await?;
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("xhttp response write timed out after {XHTTP_BRIDGE_WRITE_TIMEOUT:?}"),
        )
    })?
    .map_err(|err| {
        warn!(conn_id, error = %err, "xhttp chunked response write failed");
        err
    })
}

impl AsyncRead for BridgeRequestReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(current) = self.current.take() {
            let available = current.len().saturating_sub(self.pos);
            if available > 0 {
                let to_copy = available.min(buf.remaining());
                let end = self.pos + to_copy;
                buf.put_slice(&current[self.pos..end]);
                self.pos = end;
                if self.pos < current.len() {
                    self.current = Some(current);
                } else {
                    self.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            self.pos = 0;
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let to_copy = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..to_copy]);
                if to_copy < chunk.len() {
                    self.current = Some(chunk);
                    self.pos = to_copy;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(err)),
            Poll::Ready(None) => {
                if !self.eof_logged {
                    self.eof_logged = true;
                    debug!(conn_id = self.conn_id, "xhttp request body eof");
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for BridgeResponseWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending.is_none() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            self.pending = Some(Bytes::copy_from_slice(buf));
        }

        let pending = self.pending.as_ref().expect("pending chunk must exist");
        match self.tx.try_send(Ok(pending.clone())) {
            Ok(()) => {
                let len = pending.len();
                self.pending = None;
                Poll::Ready(Ok(len))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp response bridge closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for XHttpBridgeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XHttpBridgeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::config::VlessClient;
    use crate::vless::encode_vless_response_header;
    use crate::vless::VlessUserManager;
    use std::net::Ipv4Addr;

    const USER_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const UNKNOWN_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    fn test_clients() -> Vec<VlessClient> {
        vec![VlessClient {
            id: uuid::Uuid::from_bytes(USER_ID),
            email: Some("user@example.com".to_string()),
            flow: None,
            level: None,
        }]
    }

    fn build_vless_tcp_request(user_id: [u8; 16], port: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&user_id);
        out.push(0);
        out.push(0x01);
        out.extend_from_slice(&port.to_be_bytes());
        out.push(0x01);
        out.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
        out.extend_from_slice(payload);
        out
    }

    fn http1_post_request(path: &str, host: &str, body: &[u8]) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect()
    }

    fn split_http_request(request: &[u8]) -> (Vec<u8>, Bytes) {
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("headers")
            + 4;
        (
            request[..header_end].to_vec(),
            Bytes::copy_from_slice(&request[header_end..]),
        )
    }

    async fn run_http1_bridge_request(
        user_id: [u8; 16],
        clients: Vec<VlessClient>,
        body: Vec<u8>,
        duplex_capacity: usize,
    ) -> (Vec<u8>, io::Result<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound_port = listener.local_addr().unwrap().port();
        let drain_only = body.len() >= 1024 * 1024;
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) if drain_only => continue,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let mut vless_body = build_vless_tcp_request(user_id, outbound_port, &[]);
        vless_body.extend(body);
        let request = http1_post_request("/xhttp", "example.com", &vless_body);
        let (_, prebuffer) = split_http_request(&request);

        let (mut client, server) = tokio::io::duplex(duplex_capacity.max(512 * 1024));
        let bridge_result = async move {
            let users = VlessUserManager::new("xhttp-bridge-test", clients);
            run_http1_stream_one_bridge(
                server,
                prebuffer,
                Some(vless_body.len() as u64),
                "xhttp-bridge-test",
                1,
                Instant::now(),
                &users,
                None,
            )
            .await
        };
        let client_result = async move {
            for chunk in request.chunks(64 * 1024) {
                client.write_all(chunk).await?;
            }
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };

        let (result, response) = tokio::join!(bridge_result, client_result);
        (response.unwrap(), result)
    }

    fn response_body(response: &[u8]) -> &[u8] {
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("response headers")
            + 4;
        &response[header_end..]
    }

    use tokio::net::TcpListener;

    #[tokio::test]
    async fn small_request_response_roundtrip() {
        let (response, result) =
            run_http1_bridge_request(USER_ID, test_clients(), b"ping".to_vec(), 8192).await;
        result.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        let body = response_body(&response);
        assert!(body
            .windows(2)
            .any(|w| w == encode_vless_response_header(0, None)));
    }

    #[tokio::test]
    async fn ten_mb_request_pump_streams_without_full_buffer() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (tx, mut rx) = mpsc::channel(XHTTP_BRIDGE_CHANNEL_CAPACITY);
        let body = vec![0xABu8; 10 * 1024 * 1024];
        let pump = tokio::spawn(pump_http1_request_body(
            server,
            Bytes::new(),
            Some(body.len() as u64),
            tx,
            42,
        ));
        let write_task = tokio::spawn(async move {
            let mut client = client;
            for chunk in body.chunks(64 * 1024) {
                client.write_all(chunk).await?;
            }
            client.shutdown().await
        });

        let mut total = 0usize;
        while let Some(Ok(chunk)) = rx.recv().await {
            total += chunk.len();
        }
        write_task.await.unwrap().unwrap();
        pump.await.unwrap();
        assert_eq!(total, 10 * 1024 * 1024);
    }

    #[tokio::test]
    async fn large_transfer_roundtrip_through_bridge() {
        let payload = vec![0xCDu8; 256 * 1024];
        let (response, result) =
            run_http1_bridge_request(USER_ID, test_clients(), payload, 128 * 1024).await;
        result.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn eof_propagation_with_zero_length_body() {
        let (response, result) =
            run_http1_bridge_request(USER_ID, test_clients(), Vec::new(), 4096).await;
        result.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn vless_auth_failure_does_not_send_http_ok_or_leak_details() {
        let users = VlessUserManager::new("xhttp-bridge-test", Vec::new());
        let vless_body = build_vless_tcp_request(UNKNOWN_ID, 443, b"secret-payload");
        let request = http1_post_request("/xhttp", "example.com", &vless_body);
        let (_, prebuffer) = split_http_request(&request);

        let (mut client, server) = tokio::io::duplex(4096);
        let bridge_task = tokio::spawn(async move {
            run_http1_stream_one_bridge(
                server,
                prebuffer,
                Some(vless_body.len() as u64),
                "xhttp-bridge-test",
                2,
                Instant::now(),
                &users,
                None,
            )
            .await
        });

        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response).await;
        let result = bridge_task.await.unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let text = String::from_utf8_lossy(&response);
        assert!(!text.starts_with("HTTP/1.1 200 OK"));
        assert!(!text.to_ascii_lowercase().contains("permission"));
        assert!(!text.contains("secret-payload"));
    }

    #[tokio::test]
    async fn client_disconnect_aborts_bridge_cleanly() {
        let vless_body = build_vless_tcp_request(USER_ID, 443, b"abc");
        let request = http1_post_request("/xhttp", "example.com", &vless_body);
        let (_, prebuffer) = split_http_request(&request);

        let (client, server) = tokio::io::duplex(1024);
        let bridge_task = tokio::spawn(async move {
            let users = VlessUserManager::new("xhttp-bridge-test", test_clients());
            run_http1_stream_one_bridge(
                server,
                prebuffer,
                Some(vless_body.len() as u64),
                "xhttp-bridge-test",
                3,
                Instant::now(),
                &users,
                None,
            )
            .await
        });

        drop(client);
        let result = bridge_task.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bounded_backpressure_on_slow_reader() {
        let (req_tx, req_rx) = mpsc::channel(2);
        let mut reader = BridgeRequestReader {
            conn_id: 99,
            rx: req_rx,
            current: None,
            pos: 0,
            eof_logged: false,
        };

        req_tx.send(Ok(Bytes::from_static(b"a"))).await.unwrap();
        req_tx.send(Ok(Bytes::from_static(b"b"))).await.unwrap();
        assert!(req_tx.try_send(Ok(Bytes::from_static(b"c"))).is_err());

        let mut buf = [0u8; 1];
        assert_eq!(
            tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
                .await
                .unwrap(),
            1
        );
        assert_eq!(buf[0], b'a');
        assert_eq!(
            tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
                .await
                .unwrap(),
            1
        );
        assert_eq!(buf[0], b'b');
    }
}
