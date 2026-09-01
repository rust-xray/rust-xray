//! 0-RTT server PreWrite (pending_prewrite) and 1-RTT CommonConn regression.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::vless::encryption::aead::{TrafficAead, TrafficAeadKind};
use crate::vless::encryption::header::encode_traffic_header;
use crate::vless::encryption::VlessEncryptionServer;

use super::client_sim::{
    build_zero_rtt_client_hello, perform_1rtt_and_capture_resume, seal_client_traffic,
    server_config_with_ticket_lifetime, server_secret_for_tests,
};
use super::stream_helpers::{PartialWriteStream, ReadWritePair, ScriptStream};
use super::test_rng::TestHandshakeRng;

const GO_AES_HEADER: &str = "1703030027";
const GO_AES_CIPHERTEXT: &str =
    "40751f2b0d052a5050b809e607a5f05a55bda0c172d90cb463ec3d55c603313ace0f3e5d9b2794";
const GO_CHACHA_CIPHERTEXT: &str =
    "ec82862fcbdb1f8560bcf8d51f2acb4ff7f62e4e5ba19840b216b763cdc97be083f67d9c6c0b76";

fn golden_united() -> [u8; 96] {
    let mut arr = [0u8; 96];
    arr[0] = 0x01;
    arr[32] = 0x02;
    arr[64] = 0x03;
    arr
}

#[test]
fn one_rtt_commonconn_go_golden_unchanged_after_pending_prewrite_addition() {
    let united = golden_united();
    let ctx = b"golden-traffic-context-1234567890";
    let plaintext = b"vless-traffic-plaintext";
    let mut aead = TrafficAead::new(ctx, &united, true);
    assert_eq!(aead.kind(), TrafficAeadKind::Aes256Gcm);

    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (plaintext.len() + 16) as u16);
    assert_eq!(
        header
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        GO_AES_HEADER
    );

    let mut buffer = plaintext.to_vec();
    let sealed = aead.seal_in_place(&mut buffer, &header).expect("seal");
    assert_eq!(
        buffer[..sealed]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        GO_AES_CIPHERTEXT
    );
}

#[test]
fn one_rtt_commonconn_chacha_golden_unchanged_after_pending_prewrite_addition() {
    let united = golden_united();
    let ctx = b"golden-traffic-context-1234567890";
    let plaintext = b"vless-traffic-plaintext";
    let mut aead = TrafficAead::new(ctx, &united, false);
    assert_eq!(aead.kind(), TrafficAeadKind::ChaCha20Poly1305);

    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (plaintext.len() + 16) as u16);
    assert_eq!(
        header
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        GO_AES_HEADER
    );

    let mut buffer = plaintext.to_vec();
    let sealed = aead.seal_in_place(&mut buffer, &header).expect("seal");
    assert_eq!(
        buffer[..sealed]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        GO_CHACHA_CIPHERTEXT
    );
}

#[tokio::test]
async fn zero_rtt_prewrite_prepended_exactly_once_on_first_server_write() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (resume, _) = perform_1rtt_and_capture_resume(&server, &config, 99).await;

    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(7));
    let mut writer = super::client_sim::client_zero_rtt_upload_writer(&resume, &parts, &enc_ticket);
    let frame = seal_client_traffic(&mut writer, b"trigger-server-write").expect("seal");
    let mut wire = hello;
    wire.extend_from_slice(&frame);

    let (result, prefix_stream) = server
        .handshake(ScriptStream::from_read(wire), &mut TestHandshakeRng::new(5))
        .await
        .expect("0rtt");
    let prewrite = result.server_prewrite.expect("prewrite");
    assert_eq!(prewrite.len(), 16);

    let partial = PartialWriteStream::cycling_1_2_3();
    let written = partial.written_handle();
    let pair = ReadWritePair::new(prefix_stream, partial);
    let mut stream = super::stream_common::make_encrypted_on_with_result(pair, result);

    stream.write_all(b"server-reply").await.expect("write");
    stream.flush().await.expect("flush");

    let bytes = written.lock().expect("lock").clone();
    assert!(
        bytes.windows(16).any(|w| w == prewrite),
        "prewrite must appear in first server write burst"
    );
    let count = bytes.windows(16).filter(|w| *w == prewrite).count();
    assert_eq!(count, 1, "prewrite must not duplicate");
}

#[tokio::test]
async fn zero_rtt_prewrite_survives_partial_inner_writes() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (resume, _) = perform_1rtt_and_capture_resume(&server, &config, 99).await;

    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(8));
    let mut writer = super::client_sim::client_zero_rtt_upload_writer(&resume, &parts, &enc_ticket);
    let frame = seal_client_traffic(&mut writer, b"partial-write-check").expect("seal");
    let mut wire = hello;
    wire.extend_from_slice(&frame);

    let (result, prefix_stream) = server
        .handshake(ScriptStream::from_read(wire), &mut TestHandshakeRng::new(6))
        .await
        .expect("0rtt");
    let prewrite = result.server_prewrite.expect("prewrite");

    let partial = PartialWriteStream::cycling_1_2_3().with_pending_after(1);
    let written = partial.written_handle();
    let pair = ReadWritePair::new(prefix_stream, partial);
    let mut stream = super::stream_common::make_encrypted_on_with_result(pair, result);

    stream
        .write_all(b"server-partial-reply-bytes")
        .await
        .expect("partial write all");
    stream.flush().await.expect("flush");

    let bytes = written.lock().expect("lock").clone();
    assert!(
        bytes.windows(16).any(|w| w == prewrite),
        "prewrite must survive partial writes"
    );
    assert_eq!(
        bytes.windows(16).filter(|w| *w == prewrite).count(),
        1,
        "prewrite must appear exactly once"
    );
}

#[tokio::test]
async fn one_rtt_handshake_has_no_server_prewrite() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, _) = super::client_sim::build_native_x25519_client_hello(
        &config,
        &secret,
        &mut TestHandshakeRng::new(42),
    );
    let (result, _) = server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(99),
        )
        .await
        .expect("1rtt");
    assert!(!result.is_zero_rtt);
    assert!(result.server_prewrite.is_none());
}

#[tokio::test]
async fn zero_rtt_prewrite_not_repeated_on_second_server_write() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (resume, _) = perform_1rtt_and_capture_resume(&server, &config, 99).await;

    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(9));
    let mut writer = super::client_sim::client_zero_rtt_upload_writer(&resume, &parts, &enc_ticket);
    let frame = seal_client_traffic(&mut writer, b"trigger-server-write").expect("seal");
    let mut wire = hello;
    wire.extend_from_slice(&frame);

    let (result, prefix_stream) = server
        .handshake(ScriptStream::from_read(wire), &mut TestHandshakeRng::new(5))
        .await
        .expect("0rtt");
    let prewrite = result.server_prewrite.expect("prewrite");

    let partial = PartialWriteStream::cycling_1_2_3();
    let written = partial.written_handle();
    let pair = ReadWritePair::new(prefix_stream, partial);
    let mut stream = super::stream_common::make_encrypted_on_with_result(pair, result);

    stream.write_all(b"first-chunk").await.expect("write1");
    stream.flush().await.expect("flush1");
    stream.write_all(b"second-chunk").await.expect("write2");
    stream.flush().await.expect("flush2");

    let bytes = written.lock().expect("lock").clone();
    assert_eq!(
        bytes.windows(16).filter(|w| *w == prewrite).count(),
        1,
        "prewrite must not repeat on second server write"
    );
}
