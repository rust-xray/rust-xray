use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

pub const ENV_XHTTP_PACKET_UP_MAX_QUEUED_BYTES: &str = "RUST_XRAY_XHTTP_PACKET_UP_MAX_QUEUED_BYTES";
pub const DEFAULT_PACKET_UP_MAX_QUEUED_BYTES: usize = 256 * 1024;
pub const DEFAULT_PACKET_UP_INPUT_CHANNEL_SLOTS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketUpInputError {
    SessionClosed,
    Backpressure,
}

impl std::fmt::Display for PacketUpInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionClosed => write!(f, "packet-up session input closed"),
            Self::Backpressure => write!(f, "packet-up session input backpressure"),
        }
    }
}

impl std::error::Error for PacketUpInputError {}

pub struct PacketUpBoundedInput {
    tx: Mutex<Option<mpsc::Sender<Bytes>>>,
    rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
    queued_bytes: Arc<AtomicUsize>,
    max_queued_bytes: usize,
    closed: AtomicBool,
}

impl PacketUpBoundedInput {
    pub fn new(max_queued_bytes: usize, channel_slots: usize) -> Self {
        let (tx, rx) = mpsc::channel(channel_slots);
        Self {
            tx: Mutex::new(Some(tx)),
            rx: Mutex::new(Some(rx)),
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            max_queued_bytes,
            closed: AtomicBool::new(false),
        }
    }

    pub fn from_env() -> Self {
        Self::new(
            parse_max_queued_bytes_from_env(),
            DEFAULT_PACKET_UP_INPUT_CHANNEL_SLOTS,
        )
    }

    pub fn for_test(max_queued_bytes: usize, channel_slots: usize) -> Self {
        Self::new(max_queued_bytes, channel_slots)
    }

    pub fn max_queued_bytes(&self) -> usize {
        self.max_queued_bytes
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::SeqCst)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn try_write_chunk(&self, chunk: Bytes) -> Result<(), PacketUpInputError> {
        if chunk.is_empty() {
            return Ok(());
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(PacketUpInputError::SessionClosed);
        }

        let len = chunk.len();
        loop {
            let current = self.queued_bytes.load(Ordering::SeqCst);
            if current.saturating_add(len) > self.max_queued_bytes {
                return Err(PacketUpInputError::Backpressure);
            }
            if self
                .queued_bytes
                .compare_exchange(current, current + len, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }

        let tx = {
            let guard = self.tx.lock().expect("packet-up input tx lock poisoned");
            guard.as_ref().cloned()
        };
        let Some(tx) = tx else {
            self.queued_bytes.fetch_sub(len, Ordering::SeqCst);
            self.closed.store(true, Ordering::SeqCst);
            return Err(PacketUpInputError::SessionClosed);
        };

        match tx.try_send(chunk) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.queued_bytes.fetch_sub(len, Ordering::SeqCst);
                Err(PacketUpInputError::Backpressure)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.queued_bytes.fetch_sub(len, Ordering::SeqCst);
                self.closed.store(true, Ordering::SeqCst);
                Err(PacketUpInputError::SessionClosed)
            }
        }
    }

    pub fn take_reader(&self) -> Option<PacketUpSessionInputReader> {
        let mut guard = self.rx.lock().expect("packet-up input rx lock poisoned");
        guard.take().map(|rx| PacketUpSessionInputReader {
            rx,
            queued_bytes: Arc::clone(&self.queued_bytes),
            current: None,
            pos: 0,
        })
    }

    pub fn close(&self) {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let mut guard = self.tx.lock().expect("packet-up input tx lock poisoned");
        guard.take();
    }
}

pub struct PacketUpSessionInputReader {
    rx: mpsc::Receiver<Bytes>,
    queued_bytes: Arc<AtomicUsize>,
    current: Option<Bytes>,
    pos: usize,
}

impl PacketUpSessionInputReader {
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::SeqCst)
    }
}

impl AsyncRead for PacketUpSessionInputReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(current) = self.current.take() {
                let copied = copy_chunk_into_buf(&current, &mut self.pos, buf);
                if self.pos < current.len() {
                    self.current = Some(current);
                } else {
                    self.pos = 0;
                }
                if copied > 0 {
                    self.queued_bytes.fetch_sub(copied, Ordering::SeqCst);
                    return Poll::Ready(Ok(()));
                }
                self.pos = 0;
            }

            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    let copied = copy_chunk_into_buf(&chunk, &mut self.pos, buf);
                    if self.pos < chunk.len() {
                        self.current = Some(chunk);
                    } else {
                        self.pos = 0;
                    }
                    if copied > 0 {
                        self.queued_bytes.fetch_sub(copied, Ordering::SeqCst);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn copy_chunk_into_buf(chunk: &Bytes, pos: &mut usize, buf: &mut ReadBuf<'_>) -> usize {
    let available = chunk.len().saturating_sub(*pos);
    if available == 0 {
        return 0;
    }
    let to_copy = available.min(buf.remaining());
    let end = *pos + to_copy;
    buf.put_slice(&chunk[*pos..end]);
    *pos = end;
    to_copy
}

fn parse_max_queued_bytes_from_env() -> usize {
    match std::env::var(ENV_XHTTP_PACKET_UP_MAX_QUEUED_BYTES) {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => DEFAULT_PACKET_UP_MAX_QUEUED_BYTES,
        },
        Err(_) => DEFAULT_PACKET_UP_MAX_QUEUED_BYTES,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/transport/xhttp/packet_up_input.rs"]
mod tests;
