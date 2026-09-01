use std::io;

use tokio::io::AsyncReadExt;

use crate::vless::encryption::header::MAX_TRAFFIC_PAYLOAD_LEN;
use crate::vless::encryption::stream::MAX_TRAFFIC_PLAINTEXT_PER_RECORD;

use super::stream_common::{build_client_frames, make_encrypted_on};
use super::stream_helpers::ScriptStream;

async fn read_plaintext_or_err(wire: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut stream = make_encrypted_on(ScriptStream::from_read(wire), true);
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await?;
    Ok(out)
}

async fn expect_kind(wire: Vec<u8>, kind: io::ErrorKind) {
    let err = read_plaintext_or_err(wire).await.unwrap_err();
    assert_eq!(err.kind(), kind, "error = {err}");
}

#[tokio::test]
async fn malformed_invalid_content_type_prefix() {
    let mut wire = build_client_frames(&[b"ok"]);
    wire[0] = 0x16;
    expect_kind(wire, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn malformed_invalid_tls_version() {
    let mut wire = build_client_frames(&[b"ok"]);
    wire[2] = 0x04;
    expect_kind(wire, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn malformed_length_below_aead_tag() {
    let wire = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    expect_kind(wire, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn malformed_length_above_maximum() {
    let over = MAX_TRAFFIC_PAYLOAD_LEN.saturating_add(1);
    let wire = vec![0x17, 0x03, 0x03, (over >> 8) as u8, over as u8];
    expect_kind(wire, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn malformed_zero_payload_length_forbidden() {
    let wire = vec![0x17, 0x03, 0x03, 0x00, 0x00];
    expect_kind(wire, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn malformed_truncated_header() {
    expect_kind(vec![0x17, 0x03, 0x03], io::ErrorKind::UnexpectedEof).await;
}

#[tokio::test]
async fn malformed_truncated_body() {
    let mut wire = build_client_frames(&[b"trunc-body"]);
    wire.truncate(wire.len() - 4);
    expect_kind(wire, io::ErrorKind::UnexpectedEof).await;
}

#[tokio::test]
async fn malformed_bad_tag() {
    let mut wire = build_client_frames(&[b"tag"]);
    let last = wire.len() - 1;
    wire[last] ^= 0xff;
    expect_kind(wire, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn malformed_tampered_aad_header() {
    let mut wire = build_client_frames(&[b"aad"]);
    wire[3] ^= 0x01;
    let err = read_plaintext_or_err(wire).await.unwrap_err();
    assert!(
        matches!(
            err.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
        ),
        "error = {err}"
    );
}

#[tokio::test]
async fn malformed_tampered_ciphertext() {
    let mut wire = build_client_frames(&[b"cipher"]);
    wire[8] ^= 0x55;
    expect_kind(wire, io::ErrorKind::InvalidData).await;
}

#[tokio::test]
async fn malformed_eof_mid_record() {
    let wire = build_client_frames(&[b"mid"]);
    let cut = wire.len() / 2;
    expect_kind(wire[..cut].to_vec(), io::ErrorKind::UnexpectedEof).await;
}

#[tokio::test]
async fn oversized_plaintext_splits_into_multiple_records_via_stream() {
    use tokio::io::AsyncWriteExt;
    let oversized_len = MAX_TRAFFIC_PLAINTEXT_PER_RECORD + 100;
    let plain: Vec<u8> = (0..oversized_len).map(|i| i as u8).collect();
    let inner = ScriptStream::from_read(Vec::new());
    let mut stream = make_encrypted_on(inner, true);
    stream.write_all(&plain).await.expect("write");
    stream.flush().await.expect("flush");
    let wire = stream.into_inner().into_inner().into_written();
    assert!(
        wire.len() > 5 + MAX_TRAFFIC_PLAINTEXT_PER_RECORD + 16,
        "stream must emit more than one record for oversized plaintext"
    );
}
