use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// AsyncRead adapter that serves a byte prefix before delegating to an inner stream.
pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    prefix_offset: usize,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            prefix_offset: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn prefix_remaining(&self) -> usize {
        self.prefix.len().saturating_sub(self.prefix_offset)
    }
}

impl<S> AsyncRead for PrefixedStream<S>
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

impl<S> AsyncWrite for PrefixedStream<S>
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

#[cfg(test)]
#[path = "../../tests/unit/tls/prefixed.rs"]
mod tests;
