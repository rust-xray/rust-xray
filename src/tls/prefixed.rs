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
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use tokio::io::AsyncReadExt;

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    fn noop_waker() -> Waker {
        static VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    struct OneShotReader {
        data: Vec<u8>,
        offset: usize,
    }

    impl AsyncRead for OneShotReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset >= self.data.len() {
                return Poll::Ready(Ok(()));
            }
            let to_copy = (self.data.len() - self.offset).min(buf.remaining());
            buf.put_slice(&self.data[self.offset..self.offset + to_copy]);
            self.offset += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn prefixed_stream_serves_prefix_before_inner() {
        block_on(async {
            let inner = OneShotReader {
                data: b"inner".to_vec(),
                offset: 0,
            };
            let mut stream = PrefixedStream::new(inner, b"pre".to_vec());
            let mut buf = [0u8; 8];
            let read = stream.read(&mut buf).await.expect("read");
            assert_eq!(&buf[..read], b"preinner");
        });
    }

    #[test]
    fn prefixed_stream_prefix_survives_partial_reads() {
        let inner = OneShotReader {
            data: b"tail".to_vec(),
            offset: 0,
        };
        let mut stream = PrefixedStream::new(inner, b"123456".to_vec());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 4];
        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf.filled(), b"1234");

        let mut buf2 = [0u8; 6];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf2),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(read_buf2.filled(), b"56tail");
    }
}
