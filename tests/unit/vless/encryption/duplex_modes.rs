//! Full-duplex xorpub/random 1-RTT tests using the shared client session adapter.

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use crate::vless::encryption::client_session::{
    derive_client_session, read_server_1rtt_response, server_1rtt_response_len,
    ClientEncryptedStream,
};
use crate::vless::encryption::stream::{VlessEncryptedStream, MAX_TRAFFIC_PLAINTEXT_PER_RECORD};
use crate::vless::encryption::{VlessEncryptionServer, X25519SecretKey, XorMode};

use super::client_sim::{
    build_native_x25519_client_hello, client_complete_1rtt_handshake, client_encrypted_stream,
    server_config_from_single_x25519,
};
use super::stream_helpers::{FragmentReadPassthroughWrite, PatternFragmentWriter};
use super::test_rng::TestHandshakeRng;

const SERVER_RNG_SEED: u64 = 99;
const CLIENT_HELLO_RNG_SEED: u64 = 42;

fn server_secret() -> X25519SecretKey {
    X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8))
}

fn config_with_xor_mode(mode: XorMode) -> crate::vless::encryption::Mlkem768X25519PlusConfig {
    let mut config = server_config_from_single_x25519(&server_secret());
    config.xor_mode = mode;
    config
}

fn payload_a() -> Vec<u8> {
    (0..1237).map(|i| (i % 251) as u8).collect()
}

fn payload_b() -> Vec<u8> {
    (0..2741).map(|i| ((i * 7) % 253) as u8).collect()
}

async fn run_full_duplex(mode: XorMode, client_a: &[u8], server_b: &[u8]) {
    let client_a = client_a.to_vec();
    let server_b = server_b.to_vec();
    let secret = server_secret();
    let config = config_with_xor_mode(mode);
    let client_config = config.clone();
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) = build_native_x25519_client_hello(
        &config,
        &secret,
        &mut TestHandshakeRng::new(CLIENT_HELLO_RNG_SEED),
    );

    let (client_io, server_io) = duplex(256 * 1024);
    let client_a_for_server = client_a.clone();
    let server_b_for_server = server_b.clone();

    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(SERVER_RNG_SEED))
            .await
            .expect("server handshake");
        assert_eq!(result.xor_mode, mode);

        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut buf = vec![0u8; client_a_for_server.len().max(8192)];
        let n = stream.read(&mut buf).await.expect("server read A");
        assert_eq!(
            &buf[..n],
            client_a_for_server.as_slice(),
            "server must read exact client payload A"
        );

        stream
            .write_all(&server_b_for_server)
            .await
            .expect("server write B");
        stream.flush().await.expect("server flush");
    });

    let client_task = tokio::spawn(async move {
        let mut encrypted = client_complete_1rtt_handshake(
            client_io,
            &hello,
            &parts,
            &client_config,
            SERVER_RNG_SEED,
            mode,
        )
        .await
        .expect("client handshake");

        encrypted
            .write_all(&client_a)
            .await
            .expect("client write A");
        encrypted.flush().await.expect("client flush A");

        let mut out_b = vec![0u8; server_b.len()];
        encrypted
            .read_exact(&mut out_b)
            .await
            .expect("client read B");
        assert_eq!(out_b, server_b, "client must read exact server payload B");
    });

    let (client_result, server_result) = tokio::join!(client_task, server_task);
    server_result.expect("server task");
    client_result.expect("client task");
}

async fn run_multi_record_duplex(mode: XorMode) {
    let max_chunk = vec![0xABu8; MAX_TRAFFIC_PLAINTEXT_PER_RECORD];
    let chunks = vec![b"tiny-uplink".to_vec(), max_chunk, b"tail-uplink".to_vec()];
    let down = [b"ack1", b"ack2", b"ack3"];

    let secret = server_secret();
    let config = config_with_xor_mode(mode);
    let client_config = config.clone();
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) = build_native_x25519_client_hello(
        &config,
        &secret,
        &mut TestHandshakeRng::new(CLIENT_HELLO_RNG_SEED),
    );

    let (client_io, server_io) = duplex(512 * 1024);
    let chunks_for_server = chunks.clone();

    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(SERVER_RNG_SEED))
            .await
            .expect("server handshake");
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut collected = Vec::new();
        for _ in 0..chunks_for_server.len() {
            let mut buf = vec![0u8; MAX_TRAFFIC_PLAINTEXT_PER_RECORD + 64];
            let n = stream.read(&mut buf).await.expect("server read chunk");
            collected.extend_from_slice(&buf[..n]);
        }
        let expected: Vec<u8> = chunks_for_server
            .iter()
            .flat_map(|c| c.iter().copied())
            .collect();
        assert_eq!(collected, expected);

        for piece in &down {
            stream.write_all(*piece).await.expect("server write");
            stream.flush().await.expect("server flush");
        }
        let _ = stream.shutdown().await;
    });

    let client_task = tokio::spawn(async move {
        let mut encrypted = client_complete_1rtt_handshake(
            client_io,
            &hello,
            &parts,
            &client_config,
            SERVER_RNG_SEED,
            mode,
        )
        .await
        .expect("client handshake");

        for chunk in &chunks {
            encrypted
                .write_all(chunk)
                .await
                .expect("client write chunk");
            encrypted.flush().await.expect("client flush chunk");
        }

        for piece in &down {
            let mut buf = vec![0u8; piece.len()];
            encrypted.read_exact(&mut buf).await.expect("client read");
            assert_eq!(buf.as_slice(), *piece);
        }
    });

    server_task.await.expect("server");
    client_task.await.expect("client");
}

#[tokio::test]
async fn xorpub_full_duplex_asymmetric_payloads() {
    run_full_duplex(XorMode::XorPub, &payload_a(), &payload_b()).await;
}

#[tokio::test]
async fn random_full_duplex_asymmetric_payloads() {
    run_full_duplex(XorMode::Random, &payload_a(), &payload_b()).await;
}

#[tokio::test]
async fn xorpub_multi_record_both_directions() {
    run_multi_record_duplex(XorMode::XorPub).await;
}

#[tokio::test]
async fn random_multi_record_both_directions() {
    run_multi_record_duplex(XorMode::Random).await;
}

#[tokio::test]
async fn server_hello_padding_boundary_before_traffic() {
    let secret = server_secret();
    let config = config_with_xor_mode(XorMode::Native);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) = build_native_x25519_client_hello(
        &config,
        &secret,
        &mut TestHandshakeRng::new(CLIENT_HELLO_RNG_SEED),
    );

    let response_len = server_1rtt_response_len(&config, SERVER_RNG_SEED);
    assert!(
        response_len
            > crate::vless::encryption::handshake::PFS_SERVER_EXCHANGE_LEN
                + crate::vless::encryption::handshake::ENCRYPTED_TICKET_LEN,
        "fixture must include non-zero server padding"
    );

    let (client_io, server_io) = duplex(128 * 1024);
    let immediate = b"first-record-after-padding-boundary".to_vec();
    let client_config = config.clone();
    let immediate_for_server = immediate.clone();
    let expected_immediate = immediate.clone();

    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(SERVER_RNG_SEED))
            .await
            .expect("server handshake");
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut buf = vec![0u8; immediate_for_server.len()];
        let n = stream.read(&mut buf).await.expect("read immediate traffic");
        buf.truncate(n);
        buf
    });

    let client_task = tokio::spawn(async move {
        let mut encrypted = client_complete_1rtt_handshake(
            client_io,
            &hello,
            &parts,
            &client_config,
            SERVER_RNG_SEED,
            XorMode::Native,
        )
        .await
        .expect("client handshake");
        encrypted
            .write_all(&immediate)
            .await
            .expect("write immediate traffic");
        encrypted.flush().await.expect("flush");
    });

    let received = server_task.await.expect("server");
    client_task.await.expect("client");
    assert_eq!(received, expected_immediate);
}

#[tokio::test]
async fn xorpub_direction_swap_fails_decrypt() {
    direction_swap_negative(XorMode::XorPub, false).await;
}

#[tokio::test]
async fn random_direction_swap_fails_decrypt() {
    direction_swap_negative(XorMode::Random, true).await;
}

async fn direction_swap_negative(mode: XorMode, swap_xor_iv_ticket: bool) {
    let secret = server_secret();
    let config = config_with_xor_mode(mode);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) = build_native_x25519_client_hello(
        &config,
        &secret,
        &mut TestHandshakeRng::new(CLIENT_HELLO_RNG_SEED),
    );

    let (client_io, server_io) = duplex(128 * 1024);
    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(SERVER_RNG_SEED))
            .await
            .expect("server handshake");
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut buf = [0u8; 32];
        stream.read(&mut buf).await
    });

    let client_task = tokio::spawn(async move {
        let mut io = client_io;
        io.write_all(&hello).await.expect("hello");
        let response = read_server_1rtt_response(&mut io, &config, SERVER_RNG_SEED)
            .await
            .expect("response");
        let mut session = derive_client_session(&parts.as_material(), &response).expect("session");
        if swap_xor_iv_ticket {
            std::mem::swap(&mut session.ticket, &mut session.client_iv);
        } else {
            std::mem::swap(&mut session.upload, &mut session.download);
        }
        let mut bad = ClientEncryptedStream::from_session(io, session, mode).expect("stream");
        bad.write_all(b"bad-direction").await.expect("write");
        bad.flush().await.expect("flush");
    });

    let server_read = server_task.await.expect("server");
    client_task.await.expect("client");
    assert!(
        server_read.is_err(),
        "swapped direction state must fail server decrypt"
    );
}

#[tokio::test]
async fn random_fragmented_outer_xor_stream() {
    let secret = server_secret();
    let config = config_with_xor_mode(XorMode::Random);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) = build_native_x25519_client_hello(
        &config,
        &secret,
        &mut TestHandshakeRng::new(CLIENT_HELLO_RNG_SEED),
    );
    let uplink = payload_a();
    let downlink = payload_b();
    let downlink_expected = downlink.clone();

    let (client_io, server_io) = duplex(512 * 1024);

    let uplink_for_server = uplink.clone();
    let downlink_for_server = downlink.clone();
    let client_config = config.clone();

    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(SERVER_RNG_SEED))
            .await
            .expect("server handshake");
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut buf = vec![0u8; uplink_for_server.len()];
        stream.read_exact(&mut buf).await.expect("read uplink");
        assert_eq!(buf, uplink_for_server);
        stream
            .write_all(&downlink_for_server)
            .await
            .expect("write downlink");
        stream.flush().await.expect("flush");
        let _ = stream.shutdown().await;
    });

    let client_task = tokio::spawn(async move {
        let mut io = client_io;
        io.write_all(&hello).await.expect("client hello");
        let response = read_server_1rtt_response(&mut io, &client_config, SERVER_RNG_SEED)
            .await
            .expect("server response");
        let mut encrypted = client_encrypted_stream(
            PatternFragmentWriter::new(io, &[1, 3, 7, 2, 17]),
            &parts,
            &response,
            XorMode::Random,
        )
        .expect("client stream");
        encrypted.write_all(&uplink).await.expect("write uplink");
        encrypted.flush().await.expect("flush");

        let mut out = vec![0u8; downlink.len()];
        encrypted.read_exact(&mut out).await.expect("read downlink");
        assert_eq!(out, downlink_expected);
    });

    server_task.await.expect("server");
    client_task.await.expect("client");
}

#[tokio::test]
async fn random_fragmented_read_path() {
    let secret = server_secret();
    let config = config_with_xor_mode(XorMode::Random);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) = build_native_x25519_client_hello(
        &config,
        &secret,
        &mut TestHandshakeRng::new(CLIENT_HELLO_RNG_SEED),
    );
    let uplink = b"frag-uplink".to_vec();
    let downlink = payload_b();
    let downlink_expected = downlink.clone();

    let (client_io, server_io) = duplex(256 * 1024);

    let uplink_for_server = uplink.clone();
    let downlink_for_server = downlink.clone();
    let client_config = config.clone();

    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(SERVER_RNG_SEED))
            .await
            .expect("handshake");
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut buf = vec![0u8; uplink_for_server.len()];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(buf, uplink_for_server);
        stream.write_all(&downlink_for_server).await.expect("write");
        stream.flush().await.expect("flush");
        let _ = stream.shutdown().await;
    });

    let client_task = tokio::spawn(async move {
        let mut io = client_io;
        io.write_all(&hello).await.expect("client hello");
        let response = read_server_1rtt_response(&mut io, &client_config, SERVER_RNG_SEED)
            .await
            .expect("server response");
        let mut encrypted = client_encrypted_stream(
            FragmentReadPassthroughWrite::new(io),
            &parts,
            &response,
            XorMode::Random,
        )
        .expect("client stream");
        encrypted.write_all(&uplink).await.expect("write");
        encrypted.flush().await.expect("flush");

        let mut out = vec![0u8; downlink.len()];
        encrypted.read_exact(&mut out).await.expect("read");
        assert_eq!(out, downlink_expected);
    });

    server_task.await.expect("server");
    client_task.await.expect("client");
}
