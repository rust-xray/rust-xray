//! Forced-partial AsyncWrite coverage, old/new pending progression accounting,
//! wire-equivalence checks, and release-mode structural benchmarks for PERF-1B.

use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::AsyncWrite;

use super::{
    new_shared_traffic_state, noop_waker, VisionRelayStream, VisionRelayWriter, USER_UUID,
};
use crate::reality::tls13::ApplicationStreamDirectRelay;

// ---------------------------------------------------------------------------
// Configurable forced-partial underlying writer (shared by Writer + Stream)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ForcedPartialWriteConfig {
    pub max_bytes_per_poll: usize,
    /// Return `Poll::Pending` on every Nth underlying `poll_write` (1-based).
    pub pending_every_n: Option<usize>,
    /// After this many payload bytes have been accepted, return `Ok(0)`.
    pub write_zero_after_bytes: Option<usize>,
    /// After this many payload bytes have been accepted, return the given error.
    pub write_error_after_bytes: Option<(usize, ErrorKind)>,
    pub flush_error: Option<ErrorKind>,
    pub shutdown_error: Option<ErrorKind>,
}

impl ForcedPartialWriteConfig {
    fn full_write() -> Self {
        Self {
            max_bytes_per_poll: usize::MAX,
            pending_every_n: None,
            write_zero_after_bytes: None,
            write_error_after_bytes: None,
            flush_error: None,
            shutdown_error: None,
        }
    }

    fn chunk(chunk: usize) -> Self {
        Self {
            max_bytes_per_poll: chunk,
            ..Self::full_write()
        }
    }

    fn intermittent_pending(chunk: usize, every_n: usize) -> Self {
        Self {
            max_bytes_per_poll: chunk,
            pending_every_n: Some(every_n),
            ..Self::full_write()
        }
    }
}

#[derive(Debug)]
pub struct ForcedPartialWriteMock {
    config: ForcedPartialWriteConfig,
    pub data: Vec<u8>,
    poll_write_calls: usize,
    pub flush_calls: usize,
    pub shutdown_calls: usize,
    bytes_accepted: usize,
}

impl ForcedPartialWriteMock {
    pub fn new(config: ForcedPartialWriteConfig) -> Self {
        Self {
            config,
            data: Vec::new(),
            poll_write_calls: 0,
            flush_calls: 0,
            shutdown_calls: 0,
            bytes_accepted: 0,
        }
    }

    pub fn captured(&self) -> &[u8] {
        &self.data
    }
}

impl AsyncWrite for ForcedPartialWriteMock {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.poll_write_calls += 1;
        if let Some(every_n) = self.config.pending_every_n {
            if self.poll_write_calls.is_multiple_of(every_n) {
                return Poll::Pending;
            }
        }

        if let Some(limit) = self.config.write_zero_after_bytes {
            if self.bytes_accepted >= limit {
                return Poll::Ready(Ok(0));
            }
        }

        if let Some((limit, kind)) = self.config.write_error_after_bytes {
            if self.bytes_accepted >= limit {
                return Poll::Ready(Err(Error::new(kind, "forced partial mock write error")));
            }
        }

        let room = self
            .config
            .write_zero_after_bytes
            .or_else(|| self.config.write_error_after_bytes.map(|(limit, _)| limit))
            .map(|limit| limit.saturating_sub(self.bytes_accepted))
            .unwrap_or(buf.len());

        let n = buf.len().min(self.config.max_bytes_per_poll).min(room);
        self.data.extend_from_slice(&buf[..n]);
        self.bytes_accepted += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.flush_calls += 1;
        if let Some(kind) = self.config.flush_error {
            Poll::Ready(Err(Error::new(kind, "forced partial mock flush error")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.shutdown_calls += 1;
        if let Some(kind) = self.config.shutdown_error {
            Poll::Ready(Err(Error::new(kind, "forced partial mock shutdown error")))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

// ---------------------------------------------------------------------------
// Writer kind abstraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum RelayKind {
    Writer,
    Stream,
}

enum RelayHandle {
    Writer(VisionRelayWriter<ForcedPartialWriteMock>),
    Stream(VisionRelayStream<ForcedPartialWriteMock>),
}

impl RelayHandle {
    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self {
            Self::Writer(w) => Pin::new(w).poll_write(cx, buf),
            Self::Stream(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self {
            Self::Writer(w) => Pin::new(w).poll_flush(cx),
            Self::Stream(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self {
            Self::Writer(w) => Pin::new(w).poll_shutdown(cx),
            Self::Stream(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn captured(&self) -> &[u8] {
        match self {
            Self::Writer(w) => w.inner.captured(),
            Self::Stream(s) => s.inner.captured(),
        }
    }

    fn flush_calls(&self) -> usize {
        match self {
            Self::Writer(w) => w.inner.flush_calls,
            Self::Stream(s) => s.inner.flush_calls,
        }
    }

    fn shutdown_calls(&self) -> usize {
        match self {
            Self::Writer(w) => w.inner.shutdown_calls,
            Self::Stream(s) => s.inner.shutdown_calls,
        }
    }

    fn pending_empty(&self) -> bool {
        match self {
            Self::Writer(w) => w.pending_write.is_empty(),
            Self::Stream(s) => s.pending_write.is_empty(),
        }
    }
}

fn fresh_traffic() -> super::SharedTrafficState {
    new_shared_traffic_state(USER_UUID)
}

fn make_relay(kind: RelayKind, mock: ForcedPartialWriteMock) -> RelayHandle {
    let traffic = fresh_traffic();
    match kind {
        RelayKind::Writer => RelayHandle::Writer(VisionRelayWriter::new(
            mock,
            Arc::clone(&traffic),
            USER_UUID,
            None,
        )),
        RelayKind::Stream => {
            RelayHandle::Stream(VisionRelayStream::new(mock, traffic, USER_UUID, None))
        }
    }
}

fn make_relay_with_direct(
    kind: RelayKind,
    mock: ForcedPartialWriteMock,
    direct: ApplicationStreamDirectRelay,
) -> RelayHandle {
    let traffic = fresh_traffic();
    match kind {
        RelayKind::Writer => RelayHandle::Writer(VisionRelayWriter::new(
            mock,
            Arc::clone(&traffic),
            USER_UUID,
            Some(direct),
        )),
        RelayKind::Stream => RelayHandle::Stream(VisionRelayStream::new(
            mock,
            traffic,
            USER_UUID,
            Some(direct),
        )),
    }
}

fn snapshot_wire_frame(relay: &RelayHandle) -> Vec<u8> {
    let mut frame = relay.captured().to_vec();
    match relay {
        RelayHandle::Writer(w) => frame.extend_from_slice(&w.pending_write),
        RelayHandle::Stream(s) => frame.extend_from_slice(&s.pending_write),
    }
    frame
}

fn drain_pending_only(relay: &mut RelayHandle, resume_payload: &[u8]) {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..65_536 {
        if relay.pending_empty() {
            return;
        }
        match relay.poll_write(&mut cx, resume_payload) {
            Poll::Pending => continue,
            Poll::Ready(Ok(_)) => continue,
            Poll::Ready(Err(err)) => panic!("drain_pending_only failed: {err}"),
        }
    }
    panic!("drain_pending_only exceeded iteration budget");
}

fn drive_write_until_pending(relay: &mut RelayHandle, payload: &[u8]) {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    match relay.poll_write(&mut cx, payload) {
        Poll::Pending => {}
        Poll::Ready(Ok(_)) if !relay.pending_empty() => {}
        Poll::Ready(Ok(_)) => panic!("write completed before leaving pending bytes"),
        Poll::Ready(Err(err)) => panic!("unexpected write error while forcing pending: {err}"),
    }
}

fn drive_write_to_completion(
    relay: &mut RelayHandle,
    payload: &[u8],
) -> Poll<std::io::Result<usize>> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut offset = 0usize;
    for _ in 0..65_536 {
        if offset >= payload.len() && relay.pending_empty() {
            return Poll::Ready(Ok(payload.len()));
        }
        let slice = &payload[offset..];
        match relay.poll_write(&mut cx, slice) {
            Poll::Pending => continue,
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Ok(if offset == 0 { 0 } else { payload.len() }));
            }
            Poll::Ready(Ok(n)) => {
                if !relay.pending_empty() {
                    continue;
                }
                if n >= slice.len() {
                    return Poll::Ready(Ok(payload.len()));
                }
                offset += n;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
    }
    Poll::Pending
}

fn drain_via_flush(relay: &mut RelayHandle) -> Poll<std::io::Result<()>> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut last = Poll::Pending;
    for _ in 0..65_536 {
        last = relay.poll_flush(&mut cx);
        if matches!(last, Poll::Ready(_)) {
            break;
        }
    }
    last
}

fn drain_via_shutdown(relay: &mut RelayHandle) -> Poll<std::io::Result<()>> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut last = Poll::Pending;
    for _ in 0..65_536 {
        last = relay.poll_shutdown(&mut cx);
        if matches!(last, Poll::Ready(_)) {
            break;
        }
    }
    last
}

fn assert_exact_wire(relay: &RelayHandle, expected_frame: &[u8], label: &str) {
    assert_eq!(
        relay.captured(),
        expected_frame,
        "{label}: underlying wire bytes must match expected padded frame exactly"
    );
}

// ---------------------------------------------------------------------------
// Error-state semantics (documented + tested)
// ---------------------------------------------------------------------------
//
// | Event                         | pending_write | pending_original_len | Resume? |
// |-------------------------------|---------------|----------------------|---------|
// | App empty write               | unchanged     | unchanged            | yes     |
// | Underlying Ok(0) WriteZero    | RETAINED      | cleared on Err path  | NO*     |
// | Underlying write Err          | cleared       | cleared              | NO      |
// | Pending drain Err (write)     | cleared       | cleared              | NO      |
// | Flush after pending drained   | empty         | None                 | yes     |
// | Flush Err on underlying       | empty         | None                 | partial |
// | Shutdown Err on underlying    | empty         | None                 | partial |
//
// *WriteZero leaves pending_write populated while pending_original_len is
//  cleared; a subsequent application write would panic on expect(). Treat as
//  terminal — the AsyncWrite contract violation poisons relay state.

#[test]
fn vision_forced_partial_error_state_write_zero_is_terminal() {
    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let payload = b"write-zero-terminal-check";

        let mock = ForcedPartialWriteMock::new(ForcedPartialWriteConfig {
            max_bytes_per_poll: 4,
            write_zero_after_bytes: Some(4),
            ..ForcedPartialWriteConfig::full_write()
        });
        let mut relay = make_relay(kind, mock);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = relay.poll_write(&mut cx, payload);
        let golden_prefix = relay.captured().to_vec();
        let mut saw_zero = false;
        for _ in 0..256 {
            match relay.poll_write(&mut cx, payload) {
                Poll::Ready(Err(err)) if err.kind() == ErrorKind::WriteZero => {
                    saw_zero = true;
                    break;
                }
                Poll::Pending => continue,
                Poll::Ready(Ok(_)) if !relay.pending_empty() => continue,
                other => panic!("{kind:?}: unexpected poll while forcing WriteZero: {other:?}"),
            }
        }
        assert!(saw_zero, "{kind:?}: expected WriteZero");
        assert!(
            !relay.pending_empty(),
            "{kind:?}: pending_write retained after WriteZero (terminal poison)"
        );
        assert_eq!(
            relay.captured(),
            golden_prefix.as_slice(),
            "no duplicate retry"
        );
    }
}

#[test]
fn vision_forced_partial_error_state_write_err_clears_pending() {
    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let mock = ForcedPartialWriteMock::new(ForcedPartialWriteConfig {
            max_bytes_per_poll: 4,
            write_error_after_bytes: Some((8, ErrorKind::BrokenPipe)),
            ..ForcedPartialWriteConfig::full_write()
        });
        let mut relay = make_relay(kind, mock);
        let payload = b"mid-frame-write-error";

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut saw_err = false;
        for _ in 0..256 {
            match relay.poll_write(&mut cx, payload) {
                Poll::Ready(Err(err)) if err.kind() == ErrorKind::BrokenPipe => {
                    saw_err = true;
                    break;
                }
                Poll::Pending => continue,
                Poll::Ready(Ok(_)) if !relay.pending_empty() => continue,
                other => panic!("{kind:?}: unexpected poll while forcing write error: {other:?}"),
            }
        }
        assert!(saw_err, "{kind:?}: expected BrokenPipe");
        assert!(
            relay.pending_empty(),
            "{kind:?}: pending cleared on write Err"
        );
        assert_eq!(
            relay.captured().len(),
            8,
            "no bytes retried after error point"
        );
    }
}

// ---------------------------------------------------------------------------
// Test matrix A–L (both VisionRelayWriter and VisionRelayStream)
// ---------------------------------------------------------------------------

macro_rules! matrix_case {
    ($name:ident, $kind:expr, $config:expr, $payload:expr) => {
        #[test]
        fn $name() {
            let payload: &[u8] = $payload;
            let mut relay = make_relay($kind, ForcedPartialWriteMock::new($config));
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let first = relay.poll_write(&mut cx, payload);
            let expected = snapshot_wire_frame(&relay);
            if !relay.pending_empty() {
                let result = drive_write_to_completion(&mut relay, payload);
                assert!(
                    matches!(result, Poll::Ready(Ok(n)) if n == payload.len()),
                    "write must report original payload length, first={first:?}"
                );
            } else {
                assert!(
                    matches!(first, Poll::Ready(Ok(n)) if n == payload.len()),
                    "single poll must complete write when no pending bytes remain"
                );
            }
            assert_exact_wire(&relay, &expected, stringify!($name));
        }
    };
}

// A: full write
matrix_case!(
    vision_writer_matrix_a_full_write,
    RelayKind::Writer,
    ForcedPartialWriteConfig::full_write(),
    b"matrix-a-full-write-payload"
);
matrix_case!(
    vision_stream_matrix_a_full_write,
    RelayKind::Stream,
    ForcedPartialWriteConfig::full_write(),
    b"matrix-a-full-write-payload"
);

// B: 1-byte writes
matrix_case!(
    vision_writer_matrix_b_1byte,
    RelayKind::Writer,
    ForcedPartialWriteConfig::chunk(1),
    b"matrix-b-one-byte-chunk-writes!!"
);
matrix_case!(
    vision_stream_matrix_b_1byte,
    RelayKind::Stream,
    ForcedPartialWriteConfig::chunk(1),
    b"matrix-b-one-byte-chunk-writes!!"
);

// C: 64-byte writes
matrix_case!(
    vision_writer_matrix_c_64byte,
    RelayKind::Writer,
    ForcedPartialWriteConfig::chunk(64),
    &[0xAB; 200]
);
matrix_case!(
    vision_stream_matrix_c_64byte,
    RelayKind::Stream,
    ForcedPartialWriteConfig::chunk(64),
    &[0xAB; 200]
);

// D: 256-byte writes
matrix_case!(
    vision_writer_matrix_d_256byte,
    RelayKind::Writer,
    ForcedPartialWriteConfig::chunk(256),
    &[0xCD; 900]
);
matrix_case!(
    vision_stream_matrix_d_256byte,
    RelayKind::Stream,
    ForcedPartialWriteConfig::chunk(256),
    &[0xCD; 900]
);

// E: intermittent Poll::Pending
matrix_case!(
    vision_writer_matrix_e_intermittent_pending,
    RelayKind::Writer,
    ForcedPartialWriteConfig::intermittent_pending(17, 3),
    b"matrix-e-intermittent-pending-bytes"
);
matrix_case!(
    vision_stream_matrix_e_intermittent_pending,
    RelayKind::Stream,
    ForcedPartialWriteConfig::intermittent_pending(17, 3),
    b"matrix-e-intermittent-pending-bytes"
);

// F: zero write (application-level empty buffer)
#[test]
fn vision_forced_partial_matrix_f_zero_write() {
    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let mut relay = make_relay(
            kind,
            ForcedPartialWriteMock::new(ForcedPartialWriteConfig::chunk(1)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(relay.poll_write(&mut cx, &[]), Poll::Ready(Ok(0))),
            "{kind:?}: empty application write returns Ok(0)"
        );
        assert!(relay.captured().is_empty());
    }
}

// G: write error mid-frame
#[test]
fn vision_forced_partial_matrix_g_write_error_mid_frame() {
    vision_forced_partial_error_state_write_err_clears_pending();
}

// H: flush with pending frame
#[test]
fn vision_forced_partial_matrix_h_flush_drains_pending() {
    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let payload = b"flush-must-drain-pending-frame-first";

        let mut relay = make_relay(
            kind,
            ForcedPartialWriteMock::new(ForcedPartialWriteConfig::chunk(1)),
        );
        drive_write_until_pending(&mut relay, payload);
        let expected = snapshot_wire_frame(&relay);
        assert!(!relay.pending_empty());

        let flush = drain_via_flush(&mut relay);
        assert!(
            matches!(flush, Poll::Ready(Ok(()))),
            "{kind:?}: flush succeeds"
        );
        assert!(
            relay.pending_empty(),
            "{kind:?}: pending drained before flush"
        );
        assert_eq!(relay.captured(), expected.as_slice());
        assert_eq!(
            relay.flush_calls(),
            1,
            "{kind:?}: underlying flush called once"
        );
    }
}

// I: shutdown with pending frame
#[test]
fn vision_forced_partial_matrix_i_shutdown_drains_pending() {
    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let payload = b"shutdown-must-drain-pending-frame-first";

        let mut relay = make_relay(
            kind,
            ForcedPartialWriteMock::new(ForcedPartialWriteConfig::chunk(1)),
        );
        drive_write_until_pending(&mut relay, payload);
        let expected = snapshot_wire_frame(&relay);
        assert!(!relay.pending_empty());

        let shutdown = drain_via_shutdown(&mut relay);
        assert!(
            matches!(shutdown, Poll::Ready(Ok(()))),
            "{kind:?}: shutdown succeeds"
        );
        assert!(
            relay.pending_empty(),
            "{kind:?}: pending drained before shutdown"
        );
        assert_eq!(relay.captured(), expected.as_slice());
        assert_eq!(
            relay.shutdown_calls(),
            1,
            "{kind:?}: underlying shutdown called once"
        );
    }
}

// J: second application write ordering
#[test]
fn vision_forced_partial_matrix_j_second_write_ordering() {
    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let first = b"first-application-write";
        let second = b"second-application-write";

        let mut relay = make_relay(
            kind,
            ForcedPartialWriteMock::new(ForcedPartialWriteConfig::chunk(13)),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = relay.poll_write(&mut cx, first);
        let expected_first = snapshot_wire_frame(&relay);
        let r1 = drive_write_to_completion(&mut relay, first);
        assert!(matches!(r1, Poll::Ready(Ok(n)) if n == first.len()));
        assert_eq!(relay.captured(), expected_first.as_slice());

        let before_second = relay.captured().len();
        let _ = relay.poll_write(&mut cx, second);
        let expected_second = snapshot_wire_frame(&relay)[before_second..].to_vec();
        let r2 = drive_write_to_completion(&mut relay, second);
        assert!(matches!(r2, Poll::Ready(Ok(n)) if n == second.len()));

        let mut expected = expected_first;
        expected.extend_from_slice(&expected_second);
        assert_exact_wire(&relay, &expected, "second write ordering");
    }
}

// K: DIRECT requested while pending frame exists
#[test]
fn vision_forced_partial_matrix_k_direct_after_pending() {
    use std::sync::atomic::{AtomicBool, Ordering};

    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let payload = b"pending-before-direct";
        let direct_bytes = b"RAW-DIRECT-BYTES";

        let reader_flag = Arc::new(AtomicBool::new(false));
        let writer_flag = Arc::new(AtomicBool::new(false));
        let direct = ApplicationStreamDirectRelay::from_shared(
            Arc::clone(&reader_flag),
            Arc::clone(&writer_flag),
        );

        let mut relay = make_relay_with_direct(
            kind,
            ForcedPartialWriteMock::new(ForcedPartialWriteConfig::chunk(1)),
            direct.clone(),
        );

        drive_write_until_pending(&mut relay, payload);
        let expected_padded = snapshot_wire_frame(&relay);
        assert!(!relay.pending_empty());
        direct.enable_writer();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let direct_result = relay.poll_write(&mut cx, direct_bytes);
        assert!(
            matches!(direct_result, Poll::Pending),
            "{kind:?}: DIRECT write must wait for pending padded frame"
        );
        assert!(
            !relay.captured().ends_with(direct_bytes),
            "{kind:?}: no raw DIRECT bytes before pending completes"
        );

        drain_pending_only(&mut relay, payload);
        assert!(relay.pending_empty());

        let direct_finish = drive_write_to_completion(&mut relay, direct_bytes);
        assert!(
            matches!(direct_finish, Poll::Ready(Ok(n)) if n == direct_bytes.len()),
            "{kind:?}: direct write must complete, got {direct_finish:?}"
        );

        let mut expected = expected_padded;
        expected.extend_from_slice(direct_bytes);
        assert_exact_wire(&relay, &expected, "DIRECT after pending");
        assert!(
            writer_flag.load(Ordering::SeqCst),
            "{kind:?}: DIRECT writer enabled"
        );
    }
}

// L: repeated Pending + short writes + DIRECT
#[test]
fn vision_forced_partial_matrix_l_pending_short_direct() {
    use std::sync::atomic::AtomicBool;

    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let padded_payload = b"combo-pending-short-direct";
        let direct_tail = b"DIRECT-TAIL";

        let reader_flag = Arc::new(AtomicBool::new(false));
        let writer_flag = Arc::new(AtomicBool::new(false));
        let direct = ApplicationStreamDirectRelay::from_shared(
            Arc::clone(&reader_flag),
            Arc::clone(&writer_flag),
        );

        let config = ForcedPartialWriteConfig::intermittent_pending(3, 2);
        let mut relay =
            make_relay_with_direct(kind, ForcedPartialWriteMock::new(config), direct.clone());
        let _ = drive_write_to_completion(&mut relay, padded_payload);
        let padded_len = relay.captured().len();
        direct.enable_writer();
        let direct_result = drive_write_to_completion(&mut relay, direct_tail);
        assert!(
            matches!(direct_result, Poll::Ready(Ok(n)) if n == direct_tail.len()),
            "{kind:?}: direct tail must complete"
        );

        assert_eq!(
            &relay.captured()[padded_len..],
            direct_tail,
            "{kind:?}: direct bytes follow padded frame"
        );
        assert_eq!(
            relay.captured().len(),
            padded_len + direct_tail.len(),
            "{kind:?}: no loss or duplication"
        );
    }
}

// ---------------------------------------------------------------------------
// Old vs new pending progression accounting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OldProgressionStats {
    clone_ops: usize,
    payload_bytes_cloned: usize,
    drain_ops: usize,
    shifted_bytes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NewProgressionStats {
    metadata_clone_ops: usize,
    slice_ops: usize,
    payload_bytes_copied: usize,
    drain_ops: usize,
    shifted_bytes: usize,
}

struct OldPendingModel {
    pending: Vec<u8>,
    stats: OldProgressionStats,
}

impl OldPendingModel {
    fn new(frame: Vec<u8>) -> Self {
        Self {
            pending: frame,
            stats: OldProgressionStats::default(),
        }
    }

    fn progress(&mut self, n: usize) {
        self.stats.clone_ops += 1;
        self.stats.payload_bytes_cloned += self.pending.len();
        let suffix = self.pending.len().saturating_sub(n);
        self.stats.drain_ops += 1;
        self.stats.shifted_bytes += suffix;
        self.pending.drain(..n.min(self.pending.len()));
    }

    fn finished(&self) -> bool {
        self.pending.is_empty()
    }
}

struct NewPendingModel {
    pending: Bytes,
    stats: NewProgressionStats,
}

impl NewPendingModel {
    fn new(frame: Vec<u8>) -> Self {
        Self {
            pending: Bytes::from(frame),
            stats: NewProgressionStats::default(),
        }
    }

    fn progress(&mut self, n: usize) {
        self.stats.metadata_clone_ops += 1;
        if n >= self.pending.len() {
            self.pending.clear();
        } else {
            self.stats.slice_ops += 1;
            self.pending = self.pending.slice(n..);
        }
    }

    fn finished(&self) -> bool {
        self.pending.is_empty()
    }
}

fn simulate_partial_progression(
    frame: &[u8],
    chunk: usize,
) -> (OldProgressionStats, NewProgressionStats) {
    let mut old = OldPendingModel::new(frame.to_vec());
    let mut new = NewPendingModel::new(frame.to_vec());

    while !old.finished() || !new.finished() {
        let remaining = old.pending.len().max(new.pending.len());
        let n = chunk.min(remaining).max(1);
        if !old.finished() {
            old.progress(n);
        }
        if !new.finished() {
            new.progress(n);
        }
    }
    (old.stats, new.stats)
}

#[test]
fn vision_pending_progression_old_vs_new_accounting() {
    let workloads: &[(usize, usize)] =
        &[(1024, 1), (8192, 64), (8192, 256), (4096, 1024), (512, 512)];

    let mut old_totals = OldProgressionStats::default();
    let mut new_totals = NewProgressionStats::default();

    for &(frame_len, chunk) in workloads {
        let frame = vec![0x5A; frame_len];
        let (old, new) = simulate_partial_progression(&frame, chunk);
        old_totals.clone_ops += old.clone_ops;
        old_totals.payload_bytes_cloned += old.payload_bytes_cloned;
        old_totals.drain_ops += old.drain_ops;
        old_totals.shifted_bytes += old.shifted_bytes;

        new_totals.metadata_clone_ops += new.metadata_clone_ops;
        new_totals.slice_ops += new.slice_ops;
        new_totals.payload_bytes_copied += new.payload_bytes_copied;
        new_totals.drain_ops += new.drain_ops;
        new_totals.shifted_bytes += new.shifted_bytes;

        assert_eq!(
            new.payload_bytes_copied, 0,
            "frame_len={frame_len} chunk={chunk}: NEW must not copy payload on progression"
        );
        assert_eq!(
            new.drain_ops, 0,
            "frame_len={frame_len} chunk={chunk}: NEW must not drain"
        );
        assert_eq!(
            new.shifted_bytes, 0,
            "frame_len={frame_len} chunk={chunk}: NEW must not shift suffix bytes"
        );
    }

    assert!(old_totals.clone_ops > 0, "OLD model must perform clone ops");
    assert!(old_totals.payload_bytes_cloned > 0);
    assert!(old_totals.drain_ops > 0);
    assert!(old_totals.shifted_bytes > 0);

    // Store totals for benchmark/report via stderr when run with --nocapture.
    eprintln!(
        "PERF-1B accounting OLD clone_ops={} payload_cloned={} drain_ops={} shifted={}",
        old_totals.clone_ops,
        old_totals.payload_bytes_cloned,
        old_totals.drain_ops,
        old_totals.shifted_bytes
    );
    eprintln!(
        "PERF-1B accounting NEW metadata_clones={} slices={} payload_copied={} drain_ops={} shifted={}",
        new_totals.metadata_clone_ops,
        new_totals.slice_ops,
        new_totals.payload_bytes_copied,
        new_totals.drain_ops,
        new_totals.shifted_bytes
    );
}

// ---------------------------------------------------------------------------
// Wire-equivalence: old progression model vs live Vision writers
// ---------------------------------------------------------------------------

fn old_model_wire_output(frame: &[u8], chunk: usize) -> Vec<u8> {
    let mut old = OldPendingModel::new(frame.to_vec());
    let mut out = Vec::new();
    while !old.finished() {
        let n = chunk.min(old.pending.len()).max(1);
        let pending = old.pending.clone();
        out.extend_from_slice(&pending[..n]);
        old.progress(n);
    }
    out
}

fn wire_output_via_impl(payload: &[u8], chunk: usize, kind: RelayKind) -> (Vec<u8>, Vec<u8>) {
    wire_output_with_traffic(payload, chunk, kind, fresh_traffic())
}

fn make_tls_direct_traffic() -> super::SharedTrafficState {
    let traffic = fresh_traffic();
    {
        let mut locked = traffic.lock().expect("lock");
        locked.enable_xtls = true;
        locked.is_tls = true;
        locked.is_tls12_or_above = true;
    }
    traffic
}

fn make_relay_with_traffic(
    kind: RelayKind,
    mock: ForcedPartialWriteMock,
    traffic: super::SharedTrafficState,
) -> RelayHandle {
    match kind {
        RelayKind::Writer => {
            RelayHandle::Writer(VisionRelayWriter::new(mock, traffic, USER_UUID, None))
        }
        RelayKind::Stream => {
            RelayHandle::Stream(VisionRelayStream::new(mock, traffic, USER_UUID, None))
        }
    }
}

fn wire_output_with_traffic(
    payload: &[u8],
    chunk: usize,
    kind: RelayKind,
    traffic: super::SharedTrafficState,
) -> (Vec<u8>, Vec<u8>) {
    let mut relay = make_relay_with_traffic(
        kind,
        ForcedPartialWriteMock::new(ForcedPartialWriteConfig::chunk(chunk)),
        traffic,
    );
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let _ = relay.poll_write(&mut cx, payload);

    let mut frame = relay.captured().to_vec();
    match &relay {
        RelayHandle::Writer(w) => frame.extend_from_slice(&w.pending_write),
        RelayHandle::Stream(s) => frame.extend_from_slice(&s.pending_write),
    }

    let _ = drive_write_to_completion(&mut relay, payload);
    (frame, relay.captured().to_vec())
}

#[test]
fn vision_wire_equivalence_old_model_vs_new_impl() {
    let tls_app = [0x17u8, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    let large_payload = vec![0x42; 4096];

    for kind in [RelayKind::Writer, RelayKind::Stream] {
        let scenarios: Vec<(&str, Vec<u8>, usize, bool)> = vec![
            (
                "ordinary-padding",
                b"ordinary-vision-padding-payload".to_vec(),
                7,
                false,
            ),
            ("direct-command-frame", tls_app.to_vec(), 11, true),
            ("tls-shaped", tls_app.to_vec(), 5, false),
            ("large-payload", large_payload.clone(), 256, false),
            ("fragmented-1byte", b"frag-me".to_vec(), 1, false),
        ];

        for (label, payload, chunk, tls_direct) in scenarios {
            let (frame, new_out) = if tls_direct {
                wire_output_with_traffic(&payload, chunk, kind, make_tls_direct_traffic())
            } else {
                wire_output_via_impl(&payload, chunk, kind)
            };

            let old_out = old_model_wire_output(&frame, chunk);
            assert_eq!(
                old_out, new_out,
                "{kind:?} {label}: wire output must be byte-identical"
            );
            assert_eq!(new_out, frame, "{kind:?} {label}: must match padded frame");
        }
    }
}

// ---------------------------------------------------------------------------
// Memory retention audit
// ---------------------------------------------------------------------------
//
// - Maximum pending frame size is bounded by MAX_VISION_FRAME (8192) plus UUID
//   header and random padding (see xtls_padding).
// - `pending_write` holds a `Bytes` handle to the full padded frame until the
//   last byte is accepted by the underlying writer.
// - Partial progress uses `Bytes::slice`, which keeps the original backing
//   allocation alive until `pending_write` is cleared — no payload copy occurs.
// - Retention lasts only until the current frame fully drains; the next write
//   replaces `pending_write` with a fresh `Bytes::from(padded)`.

#[test]
fn vision_pending_bytes_slice_retains_backing_until_clear() {
    let large = vec![0xEE; 8192];
    let mut pending = Bytes::from(large);
    let original_ptr = pending.as_ptr();
    pending = pending.slice(8190..);
    assert_eq!(pending.len(), 2);
    assert_eq!(
        pending.as_ptr(),
        original_ptr.wrapping_add(8190),
        "slice is a view into the same backing allocation"
    );
    pending.clear();
    assert!(pending.is_empty());
}

// ---------------------------------------------------------------------------
// Release-mode structural benchmark (informational; not run in normal CI)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BenchRow {
    frame_kb: usize,
    chunk: usize,
    median_ns: u128,
    p95_ns: u128,
    new_metadata_clones: usize,
    new_payload_copied: usize,
}

fn bench_progression(frame_len: usize, chunk: usize, iterations: usize) -> BenchRow {
    let frame = vec![0x7B; frame_len];
    let mut samples = Vec::with_capacity(iterations);
    let mut meta = 0usize;
    let mut copied = 0usize;

    for _ in 0..iterations {
        let start = std::time::Instant::now();
        let (_, new) = simulate_partial_progression(&frame, chunk);
        samples.push(start.elapsed().as_nanos());
        meta += new.metadata_clone_ops;
        copied += new.payload_bytes_copied;
    }

    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    let p95 = samples[(samples.len() * 95) / 100];

    BenchRow {
        frame_kb: frame_len / 1024,
        chunk,
        median_ns: median,
        p95_ns: p95,
        new_metadata_clones: meta,
        new_payload_copied: copied,
    }
}

/// Run with: `cargo test --release vision_pending_progression_benchmark -- --ignored --nocapture`
#[ignore]
#[test]
fn vision_pending_progression_benchmark() {
    let frame_sizes = [1024, 8192, 16384];
    let chunks = [1, 64, 256, 1024];
    let iterations = 5000;

    eprintln!(
        "PERF-1B benchmark (release structural progression, {} iters each):",
        iterations
    );
    for frame in frame_sizes {
        for chunk in chunks {
            if chunk > frame {
                continue;
            }
            let row = bench_progression(frame, chunk, iterations);
            eprintln!(
                "  frame={}KiB chunk={}B median={}ns p95={}ns meta_clones={} payload_copied={}",
                row.frame_kb,
                row.chunk,
                row.median_ns,
                row.p95_ns,
                row.new_metadata_clones,
                row.new_payload_copied
            );
            assert_eq!(row.new_payload_copied, 0);
        }
        let full = bench_progression(frame, frame, iterations);
        eprintln!(
            "  frame={}KiB chunk=full median={}ns p95={}ns meta_clones={} payload_copied={}",
            full.frame_kb,
            full.median_ns,
            full.p95_ns,
            full.new_metadata_clones,
            full.new_payload_copied
        );
    }
}
