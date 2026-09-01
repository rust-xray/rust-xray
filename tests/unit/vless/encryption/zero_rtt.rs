//! 0-RTT ticket resume, replay, expiry, and malformed-input coverage.

use std::sync::Arc;

use tokio::io::AsyncReadExt;

use crate::vless::encryption::handshake::HandshakeError;
use crate::vless::encryption::stream::VlessEncryptedStream;
use crate::vless::encryption::{VlessEncryptionServer, X25519SecretKey, XorMode};

use super::client_sim::{
    build_zero_rtt_client_hello, client_zero_rtt_upload_writer, perform_1rtt_and_capture_resume,
    seal_client_traffic, server_config_with_ticket_lifetime, ClientResumeState,
};
use super::stream_helpers::{FragmentReader, ScriptStream};
use super::test_rng::TestHandshakeRng;

fn server_secret() -> X25519SecretKey {
    X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8))
}

#[tokio::test]
async fn native_zero_rtt_resume_accepts_immediate_traffic() {
    let secret = server_secret();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let (zero_hello, zero_parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(7));
    let plaintext = b"zero-rtt-immediate-payload";
    let mut writer = client_zero_rtt_upload_writer(&resume, &zero_parts, &enc_ticket);
    let frame = seal_client_traffic(&mut writer, plaintext).expect("seal");

    let mut wire = zero_hello;
    wire.extend_from_slice(&frame);

    let (result, prefix) = server
        .handshake(ScriptStream::from_read(wire), &mut TestHandshakeRng::new(5))
        .await
        .expect("0rtt handshake");
    assert!(result.is_zero_rtt);
    let mut encrypted = VlessEncryptedStream::from_handshake(prefix, result);
    let mut out = vec![0u8; 256];
    let n = encrypted.read(&mut out).await.expect("read");
    out.truncate(n);
    assert_eq!(out, plaintext);
}

#[tokio::test]
async fn zero_rtt_replay_rejects_duplicate_hello() {
    let secret = server_secret();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(7));
    let mut writer = client_zero_rtt_upload_writer(&resume, &parts, &enc_ticket);
    let frame = seal_client_traffic(&mut writer, b"first").expect("seal");
    let wire = [hello, frame].concat();

    server
        .handshake(
            ScriptStream::from_read(wire.clone()),
            &mut TestHandshakeRng::new(5),
        )
        .await
        .expect("first 0rtt");

    let err = match server
        .handshake(ScriptStream::from_read(wire), &mut TestHandshakeRng::new(6))
        .await
    {
        Err(err) => err,
        Ok(_) => panic!("replay must fail"),
    };
    assert!(matches!(err, HandshakeError::ReplayRejected));
}

#[tokio::test]
async fn zero_rtt_unknown_ticket_writes_noise_and_fails() {
    let secret = server_secret();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let fake_resume = ClientResumeState {
        ticket: [0xEE; 16],
        pfs_key: [0x11; 64],
        client_iv: [0u8; 16],
        use_aes: true,
    };
    let (hello, _, _) = build_zero_rtt_client_hello(
        &config,
        &fake_resume,
        &secret,
        &mut TestHandshakeRng::new(3),
    );
    let err = match server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(4),
        )
        .await
    {
        Err(err) => err,
        Ok(_) => panic!("unknown ticket"),
    };
    assert!(matches!(
        err,
        HandshakeError::UnknownSession | HandshakeError::ExpiredSession
    ));
}

#[tokio::test]
async fn zero_rtt_fragmented_reads_complete_handshake() {
    let secret = server_secret();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(8));
    let mut writer = client_zero_rtt_upload_writer(&resume, &parts, &enc_ticket);
    let frame = seal_client_traffic(&mut writer, b"frag-check").expect("seal");
    let wire = [hello, frame].concat();

    let fragmented = server
        .handshake(
            FragmentReader::new(ScriptStream::from_read(wire)),
            &mut TestHandshakeRng::new(5),
        )
        .await
        .expect("fragmented")
        .0;

    assert!(fragmented.is_zero_rtt);
}

#[tokio::test]
async fn concurrent_zero_rtt_same_wire_one_replay() {
    let secret = server_secret();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(10));
    let mut writer = client_zero_rtt_upload_writer(&resume, &parts, &enc_ticket);
    let frame = seal_client_traffic(&mut writer, b"race").expect("seal");
    let wire = [hello, frame].concat();

    let server_a = server.clone();
    let server_b = server.clone();
    let wire_a = wire.clone();
    let wire_b = wire;
    let task_a = tokio::spawn(async move {
        server_a
            .handshake(
                ScriptStream::from_read(wire_a),
                &mut TestHandshakeRng::new(5),
            )
            .await
    });
    let task_b = tokio::spawn(async move {
        server_b
            .handshake(
                ScriptStream::from_read(wire_b),
                &mut TestHandshakeRng::new(6),
            )
            .await
    });

    let (a, b) = tokio::join!(task_a, task_b);
    let outcomes = [a.expect("task a"), b.expect("task b")];
    let successes = outcomes.iter().filter(|r| r.is_ok()).count();
    let replay_rejects = outcomes
        .iter()
        .filter(|r| matches!(r, Err(HandshakeError::ReplayRejected)))
        .count();
    assert_eq!(successes, 1, "exactly one concurrent resume should win");
    assert_eq!(replay_rejects, 1, "duplicate wire must replay-reject");
}
