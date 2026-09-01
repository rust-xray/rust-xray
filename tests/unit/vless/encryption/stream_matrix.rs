use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::vless::encryption::aead::TrafficAeadKind;
use crate::vless::encryption::header::{
    decode_traffic_header, MAX_TRAFFIC_PAYLOAD_LEN, MIN_TRAFFIC_PAYLOAD_LEN,
};
use crate::vless::encryption::stream::MAX_TRAFFIC_PLAINTEXT_PER_RECORD;
use crate::vless::encryption::{
    reset_test_seal_count, test_seal_count, EncryptedReader, EncryptedWriter, MAX_NONCE,
};

use super::stream_common::{
    build_client_frames, client_writer_keys, dummy_handshake_result, expected_server_frame,
    make_encrypted_on, make_encrypted_on_with_result, test_direction_keys,
};
use super::stream_helpers::{FragmentReader, PartialWriteStream, ReadWritePair, ScriptStream};

async fn read_all_plaintext<S>(
    stream: &mut crate::vless::encryption::stream::VlessEncryptedStream<S>,
) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await?;
    Ok(out)
}

fn build_chacha_client_frame(plaintext: &[u8]) -> Vec<u8> {
    let (mut keys, _) = client_writer_keys();
    keys.aead.set_kind(TrafficAeadKind::ChaCha20Poly1305);
    let mut writer = EncryptedWriter::new(keys);
    writer.build_record(plaintext).expect("seal").to_vec()
}

// --- #2 Partial inner write ---

#[tokio::test]
async fn partial_inner_write_emits_exact_ciphertext_once() {
    let plaintext = b"partial-write-plaintext-chunk";
    let expected = expected_server_frame(plaintext);

    let partial = PartialWriteStream::cycling_1_2_3();
    let written = partial.written_handle();
    let inner = ReadWritePair::new(ScriptStream::from_read(Vec::new()), partial);
    let mut stream = make_encrypted_on(inner, true);

    stream.write_all(plaintext).await.expect("write");
    stream.flush().await.expect("flush");
    assert_eq!(*written.lock().expect("lock"), expected);
}

#[tokio::test]
async fn partial_inner_write_pending_does_not_reencrypt() {
    let plaintext = b"pending-no-reencrypt";
    let expected = expected_server_frame(plaintext);

    let partial = PartialWriteStream::cycling_1_2_3().with_pending_after(1);
    let written = partial.written_handle();
    let inner = ReadWritePair::new(ScriptStream::from_read(Vec::new()), partial);
    let mut stream = make_encrypted_on(inner, true);

    let n = stream.write(plaintext).await.expect("write");
    assert_eq!(n, plaintext.len());

    stream.flush().await.expect("flush drains pending frame");
    assert_eq!(*written.lock().expect("lock"), expected);
}

#[tokio::test]
async fn partial_inner_write_shutdown_drains_pending_frame() {
    let plaintext = b"shutdown-drain";
    let expected = expected_server_frame(plaintext);

    let partial = PartialWriteStream::cycling_1_2_3();
    let written = partial.written_handle();
    let inner = ReadWritePair::new(ScriptStream::from_read(Vec::new()), partial);
    let mut stream = make_encrypted_on(inner, true);
    stream.write_all(plaintext).await.expect("write");
    stream.shutdown().await.expect("shutdown");

    assert_eq!(*written.lock().expect("lock"), expected);
}

// --- #4 Reader fragmentation matrix ---

#[test]
fn two_records_encrypted_reader_direct() {
    let wire = build_client_frames(&[b"record-a", b"record-b-longer"]);
    let (_upload, download, united) = test_direction_keys();
    let mut reader = EncryptedReader::new(download, united, true);
    let mut offset = 0usize;
    for expected in [b"record-a".as_slice(), b"record-b-longer".as_slice()] {
        let header: [u8; 5] = wire[offset..offset + 5].try_into().expect("header");
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let body = &wire[offset + 5..offset + 5 + payload_len];
        let plain = reader
            .decrypt_record(&header, body)
            .expect("decrypt record");
        assert_eq!(plain.as_ref(), expected);
        offset += 5 + payload_len;
    }
}

#[tokio::test]
async fn reader_fragmentation_header_one_byte_at_a_time() {
    let plain = b"frag-header-only";
    let wire = build_client_frames(&[plain]);
    let inner = FragmentReader::new(ScriptStream::from_read(wire));
    let mut stream = make_encrypted_on(inner, true);
    let out = read_all_plaintext(&mut stream).await.expect("read");
    assert_eq!(out, plain);
}

#[tokio::test]
async fn reader_fragmentation_body_one_byte_at_a_time() {
    let plain: Vec<u8> = (0..128).map(|i| i as u8).collect();
    let wire = build_client_frames(&[plain.as_slice()]);
    let inner = FragmentReader::new(ScriptStream::from_read(wire));
    let mut stream = make_encrypted_on(inner, true);
    let out = read_all_plaintext(&mut stream).await.expect("read");
    assert_eq!(out, plain);
}

#[tokio::test]
async fn reader_fragmentation_header_complete_body_fragmented() {
    let plain = b"header-ok-body-frag";
    let wire = build_client_frames(&[plain]);
    let inner = FragmentReader::new(ScriptStream::from_read(wire));
    let mut stream = make_encrypted_on(inner, true);
    let out = read_all_plaintext(&mut stream).await.expect("read");
    assert_eq!(out, plain);
}

#[tokio::test]
async fn reader_two_records_coalesced() {
    let a = b"record-a";
    let b = b"record-b-longer";
    let wire = build_client_frames(&[a, b]);
    let mut stream = make_encrypted_on(ScriptStream::from_read(wire), true);
    let out = read_all_plaintext(&mut stream).await.expect("read");
    assert_eq!(out, [a.as_slice(), b.as_slice()].concat());
}

#[tokio::test]
async fn reader_three_records_coalesced() {
    let wire = build_client_frames(&[b"one", b"two", b"three"]);
    let mut stream = make_encrypted_on(ScriptStream::from_read(wire), true);
    let out = read_all_plaintext(&mut stream).await.expect("read");
    assert_eq!(out, b"onetwothree");
}

#[tokio::test]
async fn reader_one_complete_plus_partial_next() {
    let a = b"complete";
    let b = b"partial-next-record";
    let wire = build_client_frames(&[a, b]);
    let cut = wire.len() - 3;
    let mut stream = make_encrypted_on(ScriptStream::from_read(wire[..cut].to_vec()), true);
    let mut out = Vec::new();
    let read = stream.read_to_end(&mut out).await;
    assert!(
        read.is_err() || out == *a,
        "partial next record must not yield extra plaintext"
    );
    if read.is_ok() {
        assert_eq!(out, a);
    }
}

#[tokio::test]
async fn reader_eof_exactly_between_records() {
    let wire = build_client_frames(&[b"first", b"second"]);
    let first_len = build_client_frames(&[b"first"]).len();
    let mut stream = make_encrypted_on(ScriptStream::from_read(wire[..first_len].to_vec()), true);
    let out = read_all_plaintext(&mut stream).await.expect("read");
    assert_eq!(out, b"first");
}

#[tokio::test]
async fn reader_eof_mid_header_errors() {
    let wire = build_client_frames(&[b"x"]);
    let mut stream = make_encrypted_on(ScriptStream::from_read(wire[..3].to_vec()), true);
    let err = read_all_plaintext(&mut stream).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn reader_eof_mid_ciphertext_errors() {
    let wire = build_client_frames(&[b"mid-body"]);
    let mut stream = make_encrypted_on(ScriptStream::from_read(wire[..8].to_vec()), true);
    let err = read_all_plaintext(&mut stream).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn reader_bad_tag_errors() {
    let mut wire = build_client_frames(&[b"tag-fail"]);
    let last = wire.len() - 1;
    wire[last] ^= 0xff;
    let mut stream = make_encrypted_on(ScriptStream::from_read(wire), true);
    let err = read_all_plaintext(&mut stream).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

// --- #5 Writer record size matrix ---

fn assert_wire_records_within_upstream_bounds(wire: &[u8]) {
    let mut offset = 0usize;
    while offset < wire.len() {
        assert!(
            wire.len() - offset >= 5,
            "truncated traffic header at offset {offset}"
        );
        let header: [u8; 5] = wire[offset..offset + 5].try_into().expect("header");
        let payload_len = decode_traffic_header(&header).expect("valid traffic header") as usize;
        assert!(
            payload_len >= MIN_TRAFFIC_PAYLOAD_LEN as usize,
            "payload below minimum at offset {offset}"
        );
        assert!(
            payload_len <= MAX_TRAFFIC_PAYLOAD_LEN as usize,
            "payload above maximum at offset {offset}"
        );
        let plaintext_len = payload_len.saturating_sub(16);
        assert!(
            plaintext_len <= MAX_TRAFFIC_PLAINTEXT_PER_RECORD,
            "plaintext chunk {plaintext_len} exceeds upstream max at offset {offset}"
        );
        offset += 5 + payload_len;
    }
    assert_eq!(offset, wire.len(), "trailing bytes after last record");
}

async fn write_plaintext_through_encrypted_stream(plain: &[u8]) -> Vec<u8> {
    let inner = ScriptStream::from_read(Vec::new());
    let mut stream = make_encrypted_on(inner, true);
    stream.write_all(plain).await.expect("write");
    stream.flush().await.expect("flush");
    stream.into_inner().into_inner().into_written()
}

fn build_client_wire_chunked(plain: &[u8]) -> Vec<u8> {
    let (keys, _) = client_writer_keys();
    let mut writer = EncryptedWriter::new(keys);
    let mut wire = Vec::new();
    let mut offset = 0usize;
    while offset < plain.len() {
        let end = (offset + MAX_TRAFFIC_PLAINTEXT_PER_RECORD).min(plain.len());
        let frame = writer
            .build_record(&plain[offset..end])
            .expect("seal chunk");
        wire.extend_from_slice(&frame);
        offset = end;
    }
    wire
}

#[tokio::test]
async fn writer_record_size_matrix() {
    let sizes = [
        1usize,
        MAX_TRAFFIC_PLAINTEXT_PER_RECORD - 1,
        MAX_TRAFFIC_PLAINTEXT_PER_RECORD,
        MAX_TRAFFIC_PLAINTEXT_PER_RECORD + 1,
        64 * 1024,
        1024 * 1024,
    ];
    for size in sizes {
        let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let wire = write_plaintext_through_encrypted_stream(&plain).await;
        assert_wire_records_within_upstream_bounds(&wire);

        let (upload, _, united) = test_direction_keys();
        let mut reader = EncryptedReader::new(upload, united, true);
        reader.clear_first_record_for_test();
        let mut offset = 0usize;
        let mut out = Vec::new();
        while offset < wire.len() {
            let header: [u8; 5] = wire[offset..offset + 5].try_into().expect("header");
            let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let body = &wire[offset + 5..offset + 5 + payload_len];
            out.extend_from_slice(&reader.decrypt_record(&header, body).expect("decrypt"));
            offset += 5 + payload_len;
        }
        assert_eq!(out, plain, "size {size}");
    }
}

// --- #8 AEAD first-record autodetection ---

#[tokio::test]
async fn aead_autodetect_server_aes_prefers_client_chacha_first_record() {
    let plain = b"chacha-first-record";
    let wire = build_chacha_client_frame(plain);

    let (upload, download, united) = test_direction_keys();
    let result = dummy_handshake_result(upload, download, united, true);
    let mut stream = make_encrypted_on_with_result(ScriptStream::from_read(wire), result);
    let out = read_all_plaintext(&mut stream).await.expect("read");
    assert_eq!(out, plain);
    assert_eq!(
        stream.reader_aead_kind_for_test(),
        TrafficAeadKind::ChaCha20Poly1305
    );
    assert!(!stream.reader_is_first_record_for_test());
}

#[tokio::test]
async fn aead_cipher_locks_after_first_success_tampered_second_fails() {
    let first = b"lock-first";
    let second = b"lock-second";
    let mut wire = build_client_frames(&[first, second]);
    let tamper_idx = build_client_frames(&[first]).len() + 10;
    wire[tamper_idx] ^= 0x55;

    let (upload, download, united) = test_direction_keys();
    let result = dummy_handshake_result(upload, download, united, true);
    let mut stream = make_encrypted_on_with_result(ScriptStream::from_read(wire), result);
    let err = read_all_plaintext(&mut stream).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(!stream.reader_is_first_record_for_test());
    assert_eq!(
        stream.reader_aead_kind_for_test(),
        TrafficAeadKind::Aes256Gcm
    );
}

// --- #9 MaxNonce stream rotation ---

#[tokio::test]
async fn maxnonce_writer_rotation_through_vless_encrypted_stream() {
    let first = b"nonce-fe-record";
    let second = b"nonce-ff-rotate-record";
    let mut near_max = [0u8; 12];
    near_max[11] = 0xfe;

    let inner = ScriptStream::from_read(Vec::new());
    let mut stream = make_encrypted_on(inner, true);
    stream.set_writer_nonce_for_test(near_max);
    stream.write_all(first).await.expect("write1");
    stream.write_all(second).await.expect("write2");
    stream.flush().await.expect("flush");
    let wire = stream.into_inner().into_inner().into_written();
    assert_wire_records_within_upstream_bounds(&wire);

    let (upload, _, united) = test_direction_keys();
    let mut reader = EncryptedReader::new(upload, united, true);
    reader.clear_first_record_for_test();
    reader.set_nonce_for_test(near_max);

    let mut offset = 0usize;
    let mut out = Vec::new();
    while offset < wire.len() {
        let header: [u8; 5] = wire[offset..offset + 5].try_into().expect("header");
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let body = &wire[offset + 5..offset + 5 + payload_len];
        out.extend_from_slice(&reader.decrypt_record(&header, body).expect("decrypt"));
        offset += 5 + payload_len;
    }
    assert_eq!(out, [first.as_slice(), second.as_slice()].concat());
}

#[test]
fn maxnonce_reader_rotation_through_encrypted_reader() {
    let first = b"nonce-fe";
    let second = b"nonce-ff-rotate";
    let mut near_max = [0u8; 12];
    near_max[11] = 0xfe;
    let (mut client_keys, united) = client_writer_keys();
    client_keys.aead.set_nonce_for_test(near_max);
    let mut client_writer = EncryptedWriter::new(client_keys);
    let mut wire = client_writer.build_record(first).expect("seal1").to_vec();
    wire.extend_from_slice(&client_writer.build_record(second).expect("seal2"));

    let (_upload, mut download, united) = test_direction_keys();
    download.aead.set_nonce_for_test(near_max);
    let mut reader = EncryptedReader::new(download, united, true);
    reader.clear_first_record_for_test();
    let mut offset = 0usize;
    let mut out = Vec::new();
    while offset < wire.len() {
        let header: [u8; 5] = wire[offset..offset + 5].try_into().expect("header");
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let body = &wire[offset + 5..offset + 5 + payload_len];
        out.extend_from_slice(&reader.decrypt_record(&header, body).expect("open"));
        offset += 5 + payload_len;
    }
    assert_eq!(out, [first.as_slice(), second.as_slice()].concat());
}

// --- #28 Backpressure: single pending frame ---

#[tokio::test]
async fn writer_backpressure_plaintext_queued_until_pending_drained() {
    let partial = PartialWriteStream::cycling_1_2_3();
    let written = partial.written_handle();
    let inner = ReadWritePair::new(ScriptStream::from_read(Vec::new()), partial);
    let mut stream = make_encrypted_on(inner, true);

    stream.write_all(b"record-one").await.expect("write1");
    stream.flush().await.expect("flush1");
    let after_one = written.lock().expect("lock").len();
    stream.write_all(b"record-two").await.expect("write2");
    stream.flush().await.expect("flush2");
    assert!(
        written.lock().expect("lock").len() > after_one,
        "second record appended after first pending frame drained"
    );
}

#[tokio::test]
async fn writer_backpressure_large_plaintext_single_pending_frame() {
    let partial = PartialWriteStream::cycling_1_2_3().with_pending_after(2);
    let written = partial.written_handle();
    let inner = ReadWritePair::new(ScriptStream::from_read(Vec::new()), partial);
    let mut stream = make_encrypted_on(inner, true);

    let large = vec![0xCDu8; 6000];
    stream.write_all(&large).await.expect("large write");
    stream.flush().await.expect("flush");
    let wire = written.lock().expect("lock").clone();
    assert!(!wire.is_empty());
    assert!(
        wire.len() > large.len(),
        "encrypted wire must include AEAD overhead"
    );
}
