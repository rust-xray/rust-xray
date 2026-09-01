//! Full 1-RTT handshake + CommonConn traffic for xorpub/random modes.

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use crate::vless::encryption::io::PrefixStream;
use crate::vless::encryption::stream::VlessEncryptedStream;
use crate::vless::encryption::{VlessEncryptionServer, X25519SecretKey, XorMode};

use super::client_sim::{
    build_native_x25519_client_hello, client_complete_1rtt_handshake,
    server_config_from_single_x25519,
};
use super::stream_helpers::ScriptStream;
use super::test_rng::TestHandshakeRng;

fn server_secret() -> X25519SecretKey {
    X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8))
}

fn config_with_xor_mode(mode: XorMode) -> crate::vless::encryption::Mlkem768X25519PlusConfig {
    let mut config = server_config_from_single_x25519(&server_secret());
    config.xor_mode = mode;
    config
}

async fn full_handshake_traffic_roundtrip(mode: XorMode, plaintext: &[u8]) {
    let plaintext = plaintext.to_vec();
    let secret = server_secret();
    let config = config_with_xor_mode(mode);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let (client_io, server_io) = duplex(65536);
    let expected = plaintext.to_vec();

    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(99))
            .await
            .expect("server handshake");
        assert_eq!(result.xor_mode, mode);
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.expect("read traffic");
        buf.truncate(n);
        buf
    });

    let client_task = tokio::spawn(async move {
        let mut encrypted =
            client_complete_1rtt_handshake(client_io, &hello, &parts, &config, 99, mode)
                .await
                .expect("client handshake");
        encrypted
            .write_all(&plaintext)
            .await
            .expect("write traffic");
        encrypted.flush().await.expect("flush");
        let _ = encrypted.shutdown().await;
    });

    let (received, client_result) = tokio::join!(server_task, client_task);
    let received = received.expect("server task");
    client_result.expect("client task");
    assert_eq!(received, expected);
}

#[tokio::test]
async fn random_full_handshake_and_upload_traffic() {
    full_handshake_traffic_roundtrip(XorMode::Random, b"random-upload-traffic").await;
}

#[tokio::test]
async fn xorpub_full_handshake_and_traffic() {
    full_handshake_traffic_roundtrip(XorMode::XorPub, b"vless-xorpub-traffic-plaintext").await;
}

// Download direction for xorpub/native is covered by `prefix_stream_handshake_plus_traffic_records_read_end`
// and server-side `random_commonconn_server_upload_applies_xor_overlay` (random write XOR).

#[tokio::test]
async fn random_handshake_installs_xorconn_state() {
    let secret = server_secret();
    let config = config_with_xor_mode(XorMode::Random);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(7));
    let (result, _) = server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(5),
        )
        .await
        .expect("handshake");
    assert_eq!(result.xor_mode, XorMode::Random);
    assert!(
        result.xor_conn.is_some(),
        "random mode must install post-handshake XorConn"
    );
}

#[tokio::test]
async fn random_commonconn_server_upload_applies_xor_overlay() {
    let secret = server_secret();
    let config = config_with_xor_mode(XorMode::Random);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(3));
    let (result, prefix) = server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(5),
        )
        .await
        .expect("handshake");

    let native_config = config_with_xor_mode(XorMode::Native);
    let native_server = VlessEncryptionServer::from_config(native_config.clone()).expect("native");
    let (native_hello, _) =
        build_native_x25519_client_hello(&native_config, &secret, &mut TestHandshakeRng::new(3));
    let (native_result, native_prefix) = native_server
        .handshake(
            ScriptStream::from_read(native_hello),
            &mut TestHandshakeRng::new(5),
        )
        .await
        .expect("native handshake");

    let plain = b"xor-overlay-check";
    let write_frame = |result: crate::vless::encryption::handshake::ServerHandshakeResult,
                       prefix: PrefixStream<ScriptStream>| async move {
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        stream.write_all(plain).await.expect("write");
        stream.flush().await.expect("flush");
        let _ = stream.shutdown().await;
        stream.into_inner().into_inner().into_written()
    };

    let random_wire = write_frame(result, prefix).await;
    let native_wire = write_frame(native_result, native_prefix).await;

    assert_eq!(random_wire.len(), native_wire.len());
    assert_ne!(
        random_wire, native_wire,
        "random mode must XOR the outer ciphertext stream"
    );
}
