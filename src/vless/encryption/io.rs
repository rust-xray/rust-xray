use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Buffered async I/O for VLESS encryption handshake (read-ahead + write pass-through).
pub struct HandshakeStream<S> {
    inner: S,
    buffer: BytesMut,
}

impl<S> HandshakeStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buffer: BytesMut::new(),
        }
    }

    pub async fn read_exact(&mut self, len: usize) -> io::Result<Bytes>
    where
        S: AsyncRead + Unpin,
    {
        while self.buffer.len() < len {
            let mut chunk = vec![0u8; len.saturating_sub(self.buffer.len()).max(512)];
            let read = self.inner.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF during VLESS encryption handshake",
                ));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
        Ok(self.buffer.split_to(len).freeze())
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        AsyncWriteExt::write_all(&mut self.inner, data).await
    }

    pub fn buffered_prefix(&self) -> Bytes {
        self.buffer.clone().freeze()
    }

    pub fn into_prefix_stream(self) -> PrefixStream<S> {
        PrefixStream {
            inner: self.inner,
            prefix: self.buffer.freeze(),
            prefix_offset: 0,
        }
    }
}

/// Stream adapter exposing buffered handshake prefix before delegating to inner I/O.
pub struct PrefixStream<S> {
    inner: S,
    prefix: Bytes,
    prefix_offset: usize,
}

impl<S> PrefixStream<S> {
    pub fn new(inner: S, prefix: Bytes) -> Self {
        Self {
            inner,
            prefix,
            prefix_offset: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn prefix_remaining(&self) -> usize {
        self.prefix.len().saturating_sub(self.prefix_offset)
    }
}

impl<S> AsyncRead for PrefixStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let filled_before = buf.filled().len();

        while buf.remaining() > 0 {
            if this.prefix_offset < this.prefix.len() {
                let to_copy = (this.prefix.len() - this.prefix_offset).min(buf.remaining());
                buf.put_slice(&this.prefix[this.prefix_offset..this.prefix_offset + to_copy]);
                this.prefix_offset += to_copy;
                continue;
            }

            match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() > filled_before {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    if buf.filled().len() > filled_before {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for PrefixStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

impl<S> AsyncWrite for HandshakeStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}
