use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Async duplex half that serves scripted reads and captures writes.
pub struct ScriptStream {
    read_data: Vec<u8>,
    read_offset: usize,
    written: Vec<u8>,
}

impl ScriptStream {
    pub fn from_read(data: Vec<u8>) -> Self {
        Self {
            read_data: data,
            read_offset: 0,
            written: Vec::new(),
        }
    }

    pub fn written(&self) -> &[u8] {
        &self.written
    }

    pub fn into_written(self) -> Vec<u8> {
        self.written
    }
}

impl AsyncRead for ScriptStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_offset >= self.read_data.len() {
            return Poll::Ready(Ok(()));
        }
        let to_copy = (self.read_data.len() - self.read_offset).min(buf.remaining());
        buf.put_slice(&self.read_data[self.read_offset..self.read_offset + to_copy]);
        self.read_offset += to_copy;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Reads at most `chunk_size` bytes per poll.
pub struct ChunkedReader<R> {
    inner: R,
    chunk_size: usize,
}

impl<R> ChunkedReader<R> {
    pub fn new(inner: R, chunk_size: usize) -> Self {
        Self { inner, chunk_size }
    }
}

impl<R> AsyncRead for ChunkedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let cap = self.chunk_size.min(buf.remaining());
        let mut tmp = vec![0u8; cap];
        let mut sub = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.inner).poll_read(cx, &mut sub) {
            Poll::Ready(Ok(())) => {
                if sub.filled().is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    buf.put_slice(sub.filled());
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// One-byte-at-a-time reader wrapper for fragmentation tests.
pub struct FragmentReader<R> {
    inner: R,
}

impl<R> FragmentReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R> AsyncRead for FragmentReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut one = [0u8; 1];
        let mut sub = ReadBuf::new(&mut one);
        match Pin::new(&mut self.inner).poll_read(cx, &mut sub) {
            Poll::Ready(Ok(())) => {
                if sub.filled().is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    buf.put_slice(sub.filled());
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Writes at most one chunk per poll using a repeating chunk-size pattern.
pub struct PatternFragmentWriter<W> {
    inner: W,
    pattern: Vec<usize>,
    index: usize,
}

impl<W> PatternFragmentWriter<W> {
    pub fn new(inner: W, pattern: &[usize]) -> Self {
        Self {
            inner,
            pattern: pattern.to_vec(),
            index: 0,
        }
    }
}

impl<W> AsyncWrite for PatternFragmentWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = self.pattern[self.index % self.pattern.len()];
        self.index += 1;
        let n = buf.len().min(chunk);
        Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<W> AsyncRead for PatternFragmentWriter<W>
where
    W: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Fragment reads one byte at a time; writes pass through unchanged.
pub struct FragmentReadPassthroughWrite<S> {
    inner: S,
}

impl<S> FragmentReadPassthroughWrite<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> AsyncRead for FragmentReadPassthroughWrite<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut one = [0u8; 1];
        let mut sub = ReadBuf::new(&mut one);
        match Pin::new(&mut self.inner).poll_read(cx, &mut sub) {
            Poll::Ready(Ok(())) => {
                if sub.filled().is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    buf.put_slice(sub.filled());
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for FragmentReadPassthroughWrite<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<R> AsyncWrite for FragmentReader<R>
where
    R: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Mock writer accepting a fixed number of bytes per poll (cycles chunk sizes).
pub struct PartialWriteStream {
    chunk_sizes: Vec<usize>,
    chunk_index: usize,
    written: Arc<Mutex<Vec<u8>>>,
    pending_after_writes: usize,
    writes_seen: usize,
}

impl PartialWriteStream {
    pub fn cycling_1_2_3() -> Self {
        Self {
            chunk_sizes: vec![1, 2, 3],
            chunk_index: 0,
            written: Arc::new(Mutex::new(Vec::new())),
            pending_after_writes: 0,
            writes_seen: 0,
        }
    }

    pub fn with_pending_after(mut self, n: usize) -> Self {
        self.pending_after_writes = n;
        self
    }

    pub fn written(&self) -> Vec<u8> {
        self.written.lock().expect("lock").clone()
    }

    pub fn written_handle(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.written)
    }
}

impl AsyncWrite for PartialWriteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.writes_seen < self.pending_after_writes {
            self.writes_seen += 1;
            return Poll::Pending;
        }
        let chunk = self.chunk_sizes[self.chunk_index % self.chunk_sizes.len()];
        self.chunk_index += 1;
        let n = buf.len().min(chunk);
        self.written
            .lock()
            .expect("lock")
            .extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// EOF reader that returns data then clean EOF.
pub struct EofAfterReader {
    data: Vec<u8>,
    offset: usize,
}

impl EofAfterReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }
}

impl AsyncRead for EofAfterReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset >= self.data.len() {
            return Poll::Ready(Ok(()));
        }
        let n = (self.data.len() - self.offset).min(buf.remaining());
        buf.put_slice(&self.data[self.offset..self.offset + n]);
        self.offset += n;
        Poll::Ready(Ok(()))
    }
}

/// Combined read/write halves for stream matrix tests.
pub struct ReadWritePair<R, W> {
    pub read: R,
    pub write: W,
}

impl<R, W> ReadWritePair<R, W> {
    pub fn new(read: R, write: W) -> Self {
        Self { read, write }
    }
}

impl<R, W> AsyncRead for ReadWritePair<R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl<R, W> AsyncWrite for ReadWritePair<R, W>
where
    W: AsyncWrite + Unpin,
    R: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

/// Strips a fixed 16-byte server 0-RTT prewrite before delegating reads.
pub struct StripServerPrewriteReader<R> {
    inner: R,
    expected: [u8; 16],
    matched: usize,
}

impl<R> StripServerPrewriteReader<R> {
    pub fn new(inner: R, expected: [u8; 16]) -> Self {
        Self {
            inner,
            expected,
            matched: 0,
        }
    }
}

impl<R> AsyncRead for StripServerPrewriteReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while self.matched < 16 {
            let mut one = [0u8; 1];
            let mut sub = ReadBuf::new(&mut one);
            match Pin::new(&mut self.inner).poll_read(cx, &mut sub) {
                Poll::Ready(Ok(())) => {
                    if sub.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    if sub.filled()[0] != self.expected[self.matched] {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected 0-RTT server prewrite byte",
                        )));
                    }
                    self.matched += 1;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R> AsyncWrite for StripServerPrewriteReader<R>
where
    R: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
