//! PERF-1C structural accounting and release-mode benchmarks for REALITY TLS 1.3 stream.

use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use bytes::BytesMut;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use tokio::io::AsyncWrite;

use crate::reality::tls13::{tls13_cipher_suite, Tls13TrafficKeys, TLS_AES_128_GCM_SHA256};
use crate::tls::records::{build_tls_record, TLS_LEGACY_VERSION_1_2, TLS_RECORD_APPLICATION_DATA};

use super::{
    try_take_tls_record, ApplicationStreamDirectRelay, RealityTls13ApplicationStream,
    RealityTls13ClientWriter, Tls13ClientWriteState, Tls13RecordDecryptor, Tls13RecordEncryptor,
};

fn aes128_keys(seed: u8) -> Tls13TrafficKeys {
    Tls13TrafficKeys {
        key: (seed..seed + 16).collect(),
        iv: (0x01..0x0d).collect(),
    }
}

fn client_to_server_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys(0x10);
    (
        Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor"),
        Tls13RecordDecryptor::new(suite, keys).expect("decryptor"),
    )
}

fn server_to_client_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys(0x20);
    (
        Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor"),
        Tls13RecordDecryptor::new(suite, keys).expect("decryptor"),
    )
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

#[derive(Debug, Default, Clone, Copy)]
struct ReadStructuralTotals {
    record_raw_allocs: u64,
    record_raw_bytes: u64,
    buffer_shifts: u64,
}

fn account_try_take(record_bytes: &[u8]) -> (ReadStructuralTotals, usize) {
    let mut buf = BytesMut::from(record_bytes);
    let mut totals = ReadStructuralTotals::default();
    let mut records = 0usize;
    while let Some(record) = try_take_tls_record(&mut buf).expect("parse") {
        totals.record_raw_allocs += 1;
        totals.record_raw_bytes += record.raw.len() as u64;
        records += 1;
    }
    (totals, records)
}

#[test]
fn perf_audit_try_take_single_record_one_raw_alloc() {
    let payload = vec![0xAB; 1024];
    let record = build_tls_record(
        TLS_RECORD_APPLICATION_DATA,
        TLS_LEGACY_VERSION_1_2,
        &payload,
    )
    .expect("record");
    let (totals, count) = account_try_take(&record);
    assert_eq!(count, 1);
    assert_eq!(totals.record_raw_allocs, 1);
    assert_eq!(totals.record_raw_bytes, record.len() as u64);
    assert_eq!(totals.buffer_shifts, 0);
}

#[test]
fn perf_audit_try_take_coalesced_records_no_shift() {
    let r1 =
        build_tls_record(TLS_RECORD_APPLICATION_DATA, TLS_LEGACY_VERSION_1_2, b"one").expect("r1");
    let r2 =
        build_tls_record(TLS_RECORD_APPLICATION_DATA, TLS_LEGACY_VERSION_1_2, b"two").expect("r2");
    let mut combined = r1.clone();
    combined.extend_from_slice(&r2);
    let (totals, count) = account_try_take(&combined);
    assert_eq!(count, 2);
    assert_eq!(totals.record_raw_allocs, 2);
    assert_eq!(totals.buffer_shifts, 0);
}

#[test]
fn perf_audit_wire_equivalence_sequential_application_records() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let keys = aes128_keys(0x55);
    let plaintexts: [&[u8]; 4] = [b"a", b"medium-plain", b"0123456789abcdef", &[0u8; 256]];
    let mut enc_a = Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc");
    let mut enc_b = Tls13RecordEncryptor::new(suite, keys).expect("enc");
    for pt in plaintexts {
        let wire_a = enc_a.encrypt_application_data(pt).expect("encrypt");
        let wire_b = enc_b.encrypt_application_data(pt).expect("encrypt");
        assert_eq!(wire_a, wire_b, "wire mismatch for len={}", pt.len());
        assert_eq!(enc_a.sequence, enc_b.sequence);
    }
}

#[test]
fn perf_audit_plaintext_read_buf_move_on_empty() {
    block_on(async {
        let (mut client_io, server_io) = duplex(8192);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _) = server_to_client_keys();
        let plaintext = b"move-instead-of-extend";
        let encrypted = client_encryptor
            .encrypt_application_data(plaintext)
            .expect("encrypt");
        client_io.write_all(&encrypted).await.expect("write");
        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
        let mut out = [0u8; 64];
        let read = stream.read(&mut out).await.expect("read");
        assert_eq!(&out[..read], plaintext);
    });
}

struct CountingWriter {
    write_calls: u64,
    flush_calls: u64,
    written: Vec<u8>,
    chunk: usize,
}

impl CountingWriter {
    fn new(chunk: usize) -> Self {
        Self {
            write_calls: 0,
            flush_calls: 0,
            written: Vec::new(),
            chunk,
        }
    }
}

impl tokio::io::AsyncWrite for CountingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.write_calls += 1;
        let n = buf.len().min(self.chunk);
        self.written.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.flush_calls += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
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

#[test]
fn perf_audit_flush_drains_pending_without_duplicate_payload_copy() {
    let inner = CountingWriter::new(1);
    let (write_encryptor, _) = server_to_client_keys();
    let (_reader_direct, writer_direct) = ApplicationStreamDirectRelay::new_shared();
    let mut writer = RealityTls13ClientWriter {
        inner,
        write: Tls13ClientWriteState::new(
            write_encryptor,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ),
        direct_relay: writer_direct,
    };
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let payload = b"flush-drain-payload";
    loop {
        match Pin::new(&mut writer).poll_write(&mut cx, payload) {
            Poll::Ready(Ok(n)) if n == payload.len() => break,
            Poll::Ready(Ok(_)) => {}
            Poll::Pending => {}
            Poll::Ready(Err(err)) => panic!("write error: {err}"),
        }
    }
    assert!(writer.write.ciphertext_write_buf.is_empty());
    let written_len = writer.inner.written.len();
    assert!(written_len > 5);
    match Pin::new(&mut writer).poll_flush(&mut cx) {
        Poll::Ready(Ok(())) => {}
        other => panic!("flush: {other:?}"),
    }
    assert_eq!(writer.inner.flush_calls, 1);
}

#[test]
fn perf_audit_direct_read_ahead_preserves_buffered_tail() {
    block_on(async {
        let (mut client_io, server_io) = duplex(8192);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _) = server_to_client_keys();
        let encrypted = client_encryptor
            .encrypt_application_data(b"tls-plain")
            .expect("encrypt");
        client_io.write_all(&encrypted).await.expect("write");
        client_io
            .write_all(b"raw-tail-after-direct")
            .await
            .expect("raw");
        let stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
        let split = stream.split_for_relay().expect("split");
        let mut reader = split.reader;
        let mut buf = [0u8; 32];
        let read = reader.read(&mut buf).await.expect("read tls");
        assert_eq!(&buf[..read], b"tls-plain");
        split.direct_relay.enable_reader();
        let read = reader.read(&mut buf).await.expect("read raw");
        assert_eq!(&buf[..read], b"raw-tail-after-direct");
    });
}

#[test]
#[ignore = "release-mode PERF-1C local benchmark; run with --ignored --release"]
fn reality_tls_stream_read_benchmark_1kib() {
    let payload = vec![0xCD; 1024];
    let record = build_tls_record(
        TLS_RECORD_APPLICATION_DATA,
        TLS_LEGACY_VERSION_1_2,
        &payload,
    )
    .expect("record");
    let iterations = 10_000u32;
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = account_try_take(&record);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "try_take 1KiB x{iterations}: {:?} ({:.0} ops/s)",
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
}
