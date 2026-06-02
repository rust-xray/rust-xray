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
