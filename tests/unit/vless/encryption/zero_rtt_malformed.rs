//! Malformed 0-RTT handshake matrix and fragmentation/coalescing coverage.

use std::sync::Arc;

use tokio::io::AsyncReadExt;

use crate::vless::encryption::handshake::{ENCRYPTED_TICKET_LEN, ZERO_RTT_LENGTH};
use crate::vless::encryption::stream::VlessEncryptedStream;
use crate::vless::encryption::{HandshakeError, VlessEncryptionServer};

use super::client_sim::{
    build_native_x25519_client_hello, build_zero_rtt_client_hello, build_zero_rtt_coalesced_wire,
    client_zero_rtt_upload_writer, perform_1rtt_and_capture_resume, seal_client_traffic,
    server_config_with_ticket_lifetime, server_secret_for_tests, ClientResumeState,
};
use super::stream_helpers::{FragmentReader, ScriptStream};
use super::test_rng::TestHandshakeRng;

fn server_pair() -> (
    VlessEncryptionServer,
    crate::vless::encryption::Mlkem768X25519PlusConfig,
) {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    (server, config)
}

#[tokio::test]
async fn zero_rtt_truncated_ticket_ciphertext_rejected() {
    let (server, config) = server_pair();
    let secret = server_secret_for_tests();
    let fake = ClientResumeState {
        ticket: [0xAB; 16],
        pfs_key: [0x11; 64],
        client_iv: [0u8; 16],
        use_aes: true,
    };
    let (mut hello, _, _) =
        build_zero_rtt_client_hello(&config, &fake, &secret, &mut TestHandshakeRng::new(1));
    hello.truncate(hello.len().saturating_sub(ENCRYPTED_TICKET_LEN / 2));
    let err = server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(2),
        )
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn zero_rtt_corrupt_ticket_tag_rejected() {
    let server = Arc::new(server_pair().0);
    let config = server_config_with_ticket_lifetime(&server_secret_for_tests(), 600, 600);
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let secret = server_secret_for_tests();
    let (mut hello, _, _) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(3));
    if let Some(last) = hello.last_mut() {
        *last ^= 0xFF;
    }
    let err = server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(4),
        )
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn zero_rtt_non_sentinel_encrypted_length_stays_one_rtt_or_fails() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(5));
    let err = server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(6),
        )
        .await;
    assert!(err.is_ok() || matches!(err, Err(HandshakeError::Malformed(_))));
}

#[tokio::test]
async fn zero_rtt_bad_traffic_immediately_after_accepted_resume_fails_read() {
    let server = Arc::new(server_pair().0);
    let config = server_config_with_ticket_lifetime(&server_secret_for_tests(), 600, 600);
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let secret = server_secret_for_tests();
    let (hello, _, _) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(9));
    let mut wire = hello;
    wire.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x20]);
    wire.extend_from_slice(&[0u8; 32]);
    let (result, prefix) = server
        .handshake(
            ScriptStream::from_read(wire),
            &mut TestHandshakeRng::new(10),
        )
        .await
        .expect("resume accepted");
    assert!(result.is_zero_rtt);
    let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
    let mut sink = [0u8; 16];
    assert!(stream.read(&mut sink).await.is_err());
}

#[tokio::test]
async fn zero_rtt_coalesced_and_fragmented_reads_same_payload() {
    let server = Arc::new(server_pair().0);
    let config = server_config_with_ticket_lifetime(&server_secret_for_tests(), 600, 600);
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let secret = server_secret_for_tests();
    let payload = b"frag-matrix-payload";
    let (coalesced, _, _) = build_zero_rtt_coalesced_wire(
        &config,
        &resume,
        &secret,
        &mut TestHandshakeRng::new(11),
        &[payload],
    );
    let (fragmented_wire, _, _) = build_zero_rtt_coalesced_wire(
        &config,
        &resume,
        &secret,
        &mut TestHandshakeRng::new(12),
        &[payload],
    );

    let (result, prefix) = server
        .handshake(
            ScriptStream::from_read(coalesced),
            &mut TestHandshakeRng::new(20),
        )
        .await
        .expect("coalesced");
    assert!(result.is_zero_rtt);
    let mut encrypted = VlessEncryptedStream::from_handshake(prefix, result);
    let mut out = [0u8; 64];
    let n = encrypted.read(&mut out).await.expect("read coalesced");
    assert_eq!(&out[..n], payload);

    let (result, prefix) = server
        .handshake(
            FragmentReader::new(ScriptStream::from_read(fragmented_wire)),
            &mut TestHandshakeRng::new(21),
        )
        .await
        .expect("fragmented");
    assert!(result.is_zero_rtt);
    let mut encrypted = VlessEncryptedStream::from_handshake(prefix, result);
    let mut out = [0u8; 64];
    let n = encrypted.read(&mut out).await.expect("read fragmented");
    assert_eq!(&out[..n], payload);
}

#[tokio::test]
async fn zero_rtt_one_byte_reads_complete_handshake() {
    let server = Arc::new(server_pair().0);
    let config = server_config_with_ticket_lifetime(&server_secret_for_tests(), 600, 600);
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let secret = server_secret_for_tests();
    let (wire, _, _) = build_zero_rtt_coalesced_wire(
        &config,
        &resume,
        &secret,
        &mut TestHandshakeRng::new(12),
        &[b"one-byte-reads"],
    );
    let fragmented = FragmentReader::new(ScriptStream::from_read(wire));
    let (result, prefix) = server
        .handshake(fragmented, &mut TestHandshakeRng::new(13))
        .await
        .expect("fragmented");
    assert!(result.is_zero_rtt);
    let mut encrypted = VlessEncryptedStream::from_handshake(prefix, result);
    let mut out = [0u8; 32];
    let n = encrypted.read(&mut out).await.expect("read");
    assert_eq!(&out[..n], b"one-byte-reads");
}

#[test]
fn zero_rtt_length_sentinel_is_32() {
    assert_eq!(ZERO_RTT_LENGTH, 32);
}

#[tokio::test]
async fn zero_rtt_truncated_iv_rejected() {
    let (server, config) = server_pair();
    let secret = server_secret_for_tests();
    let fake = ClientResumeState {
        ticket: [0xAB; 16],
        pfs_key: [0x11; 64],
        client_iv: [0u8; 16],
        use_aes: true,
    };
    let (hello, _, _) =
        build_zero_rtt_client_hello(&config, &fake, &secret, &mut TestHandshakeRng::new(14));
    let truncated = hello[..hello.len().min(12)].to_vec();
    let err = server
        .handshake(
            ScriptStream::from_read(truncated),
            &mut TestHandshakeRng::new(15),
        )
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn zero_rtt_corrupt_nfs_relay_rejected() {
    let server = Arc::new(server_pair().0);
    let config = server_config_with_ticket_lifetime(&server_secret_for_tests(), 600, 600);
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let secret = server_secret_for_tests();
    let (mut hello, _, _) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(16));
    hello[20] ^= 0x55;
    let err = server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(17),
        )
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn zero_rtt_exact_wire_replay_rejected() {
    let server = Arc::new(server_pair().0);
    let config = server_config_with_ticket_lifetime(&server_secret_for_tests(), 600, 600);
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let secret = server_secret_for_tests();
    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(18));
    let mut writer = client_zero_rtt_upload_writer(&resume, &parts, &enc_ticket);
    let frame = seal_client_traffic(&mut writer, b"replay-wire").expect("seal");
    let wire = [hello, frame].concat();
    server
        .handshake(
            ScriptStream::from_read(wire.clone()),
            &mut TestHandshakeRng::new(19),
        )
        .await
        .expect("first");
    let err = server
        .handshake(
            ScriptStream::from_read(wire),
            &mut TestHandshakeRng::new(20),
        )
        .await;
    assert!(matches!(err, Err(HandshakeError::ReplayRejected)));
}

#[tokio::test]
async fn zero_rtt_accepted_resume_post_traffic_failure_writes_no_noise() {
    let server = Arc::new(server_pair().0);
    let config = server_config_with_ticket_lifetime(&server_secret_for_tests(), 600, 600);
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let secret = server_secret_for_tests();
    let (hello, _, _) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(21));
    let mut wire = hello;
    wire.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x20]);
    wire.extend_from_slice(&[0u8; 32]);
    let mut io = ScriptStream::from_read(wire);
    let (result, prefix) = server
        .handshake(&mut io, &mut TestHandshakeRng::new(22))
        .await
        .expect("accepted");
    assert!(result.is_zero_rtt);
    let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
    let mut sink = [0u8; 16];
    assert!(stream.read(&mut sink).await.is_err());
    assert!(
        io.written().is_empty(),
        "post-accept traffic failure must not emit invalid-ticket noise"
    );
}
