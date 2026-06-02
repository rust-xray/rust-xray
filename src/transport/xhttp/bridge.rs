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
use crate::vless::{
    handle_vless_tcp_inbound, handle_vless_tcp_inbound_with_response_hook, VlessUserManager,
};

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

struct PacketUpDownloadWriter {
    on_chunk: Box<dyn FnMut(Bytes) + Send>,
    pending: Option<Bytes>,
}

impl AsyncWrite for PacketUpDownloadWriter {
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

        let pending = self.pending.take().expect("pending chunk must exist");
        (self.on_chunk)(pending.clone());
        let len = pending.len();
        self.pending = None;
        cx.waker().wake_by_ref();
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct PacketUpBridgeStream<R> {
    reader: R,
    writer: PacketUpDownloadWriter,
}

impl<R> AsyncRead for PacketUpBridgeStream<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R> AsyncWrite for PacketUpBridgeStream<R>
where
    R: Unpin,
{
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

pub async fn run_packet_up_bridge<R, F>(
    upload: R,
    on_download: F,
    inbound_tag: &str,
    conn_id: u64,
    session_id: &str,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    F: FnMut(Bytes) + Send + 'static,
{
    debug!(
        inbound_tag,
        conn_id, session_id, "xhttp packet-up bridge started"
    );

    let started = Instant::now();
    let bridge = PacketUpBridgeStream {
        reader: upload,
        writer: PacketUpDownloadWriter {
            on_chunk: Box::new(on_download),
            pending: None,
        },
    };

    let result = handle_vless_tcp_inbound(bridge, users, stats_state).await;

    match result {
        Ok(()) => {
            debug!(
                inbound_tag,
                conn_id,
                session_id,
                duration_ms = started.elapsed().as_millis(),
                "xhttp packet-up bridge completed"
            );
            Ok(())
        }
        Err(err) => {
            let reason = bridge_failure_reason(&err);
            debug!(
                inbound_tag,
                conn_id,
                session_id,
                reason,
                duration_ms = started.elapsed().as_millis(),
                "xhttp packet-up bridge failed"
            );
            warn!(
                inbound_tag,
                conn_id, session_id, reason, "xhttp packet-up bridge failed"
            );
            Err(err)
        }
    }
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

pub(crate) async fn h2_send_chunk(
    send: &mut h2::SendStream<Bytes>,
    chunk: Bytes,
) -> io::Result<()> {
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

pub(crate) async fn write_http1_chunked_chunk<S: AsyncWrite + Unpin>(
    writer: &mut S,
    chunk: &[u8],
) -> io::Result<()> {
    if chunk.is_empty() {
        writer.write_all(b"0\r\n\r\n").await?;
    } else {
        let header = format!("{:x}\r\n", chunk.len());
        writer.write_all(header.as_bytes()).await?;
        writer.write_all(chunk).await?;
        writer.write_all(b"\r\n").await?;
    }
    writer.flush().await
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
#[path = "../../../tests/unit/transport/xhttp/bridge.rs"]
mod tests;
