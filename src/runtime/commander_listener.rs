//! Internal Commander outbound listener (Xray `app/commander/outbound.go` parity).

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_stream::Stream;
use tonic::transport::server::Connected;
use tracing::debug;

/// Upstream `OutboundListener` queue capacity.
pub const COMMANDER_OUTBOUND_BUFFER: usize = 4;

/// Async IO handle handed from the data plane to tonic.
pub trait CommanderIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> CommanderIo for T {}

pub struct CommanderConnection {
    inner: Box<dyn CommanderIo>,
}

impl CommanderConnection {
    pub fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            inner: Box::new(stream),
        }
    }
}

impl AsyncRead for CommanderConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CommanderConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connected for CommanderConnection {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

/// Bounded in-memory listener fed by Commander outbound dispatch.
#[derive(Debug)]
pub struct CommanderOutboundListener {
    sender: Mutex<Option<mpsc::Sender<CommanderConnection>>>,
    closed: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
}

impl CommanderOutboundListener {
    /// Create listener + single consumer stream for tonic.
    pub fn pair() -> (Arc<Self>, CommanderIncoming) {
        let (sender, receiver) = mpsc::channel(COMMANDER_OUTBOUND_BUFFER);
        let (closed, closed_rx) = watch::channel(false);
        let listener = Arc::new(Self {
            sender: Mutex::new(Some(sender)),
            closed,
            closed_rx: closed_rx.clone(),
        });
        let incoming = CommanderIncoming {
            receiver,
            closed_rx,
        };
        (listener, incoming)
    }

    pub fn is_closed(&self) -> bool {
        *self.closed_rx.borrow()
    }

    pub fn try_push(&self, stream: TcpStream) -> bool {
        self.try_push_io(stream)
    }

    pub fn try_push_io<S>(&self, stream: S) -> bool
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.try_push_connection(CommanderConnection::new(stream))
    }

    fn try_push_connection(&self, stream: CommanderConnection) -> bool {
        if *self.closed_rx.borrow() {
            return false;
        }
        let guard = self.sender.lock().expect("commander sender lock");
        let Some(sender) = guard.as_ref() else {
            return false;
        };
        match sender.try_send(stream) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                false
            }
        }
    }

    pub fn close(&self) {
        let _ = self.closed.send(true);
        *self.sender.lock().expect("commander sender lock") = None;
    }

    pub fn queued_len(&self) -> usize {
        let guard = self.sender.lock().expect("commander sender lock");
        let Some(sender) = guard.as_ref() else {
            return 0;
        };
        sender.max_capacity().saturating_sub(sender.capacity())
    }
}

/// Stream of accepted Commander connections for tonic `serve_with_incoming`.
pub struct CommanderIncoming {
    receiver: mpsc::Receiver<CommanderConnection>,
    closed_rx: watch::Receiver<bool>,
}

impl Stream for CommanderIncoming {
    type Item = Result<CommanderConnection, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed_rx.has_changed().unwrap_or(false) {
            let _ = self.closed_rx.borrow_and_update();
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(stream)) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending if *self.closed_rx.borrow() => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Handle returned when internal Commander mode starts.
#[derive(Debug)]
pub struct InternalCommanderHandle {
    listener: Arc<CommanderOutboundListener>,
    shutdown: Arc<AtomicBool>,
}

impl InternalCommanderHandle {
    pub fn new(listener: Arc<CommanderOutboundListener>) -> Self {
        Self {
            listener,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn listener(&self) -> Arc<CommanderOutboundListener> {
        Arc::clone(&self.listener)
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.listener.close();
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst) || self.listener.is_closed()
    }
}

/// Close the Commander listener (for tests/shutdown).
pub fn close_commander_listener(listener: &CommanderOutboundListener) {
    listener.close();
    debug!("commander outbound listener closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn commander_listener_drops_when_buffer_full() {
        let (listener, mut incoming) = CommanderOutboundListener::pair();
        let bind = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = bind.local_addr().expect("addr");
        for _ in 0..4 {
            let accept = bind.accept();
            tokio::spawn(async move {
                let _ = tokio::net::TcpStream::connect(addr).await;
            });
            let (stream, _) = accept.await.expect("accept");
            assert!(listener.try_push(stream));
        }

        let overflow = tokio::net::TcpStream::connect(addr).await.expect("connect");
        assert!(!listener.try_push(overflow));

        let mut accepted = 0usize;
        let drain = tokio::time::timeout(Duration::from_millis(500), async {
            while incoming.next().await.is_some() {
                accepted += 1;
            }
        });
        let _ = drain.await;
        assert_eq!(accepted, 4);
    }
}
