use crate::vless::encryption::{
    validate_inbound_decryption_with_fallbacks, VlessEncryptionServer, X25519SecretKey, XorMode,
};

use super::client_sim::{build_native_x25519_client_hello, server_config_from_single_x25519};
use super::stream_helpers::{FragmentReader, ScriptStream};
use super::test_rng::TestHandshakeRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn server_secret() -> X25519SecretKey {
    X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8))
}

#[tokio::test]
async fn native_one_rtt_handshake_succeeds() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (client_hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let (result, prefix) = server
        .handshake(
            ScriptStream::from_read(client_hello),
            &mut TestHandshakeRng::new(99),
        )
        .await
        .expect("handshake");

    assert_eq!(result.xor_mode, XorMode::Native);
    assert_eq!(result.download_keys.context_label, parts.client_pfs_public);
    assert_eq!(result.nfs_key.as_bytes(), &parts.nfs_key);
    assert_eq!(prefix.prefix_remaining(), 0);
}

#[tokio::test]
async fn fragmented_reads_match_coalesced_handshake() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let client_hello =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(7)).0;

    let coalesced = server
        .handshake(
            ScriptStream::from_read(client_hello.clone()),
            &mut TestHandshakeRng::new(5),
        )
        .await
        .expect("coalesced")
        .0;

    let fragmented = server
        .handshake(
            FragmentReader::new(ScriptStream::from_read(client_hello)),
            &mut TestHandshakeRng::new(5),
        )
        .await
        .expect("fragmented")
        .0;

    assert_eq!(coalesced.nfs_key.as_bytes(), fragmented.nfs_key.as_bytes());
    assert_eq!(
        coalesced.download_keys.context_label,
        fragmented.download_keys.context_label
    );
}

#[tokio::test]
async fn coalesced_handshake_preserves_future_traffic_prefix() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let mut hello =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(3)).0;
    hello.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef]);

    let (result, mut prefix) = server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(5),
        )
        .await
        .expect("handshake");
    assert_eq!(result.xor_mode, XorMode::Native);
    assert_eq!(prefix.prefix_remaining(), 9);
    let mut buf = [0u8; 9];
    tokio::io::AsyncReadExt::read_exact(&mut prefix, &mut buf)
        .await
        .expect("prefix read");
    assert_eq!(&buf[..5], &[0x17, 0x03, 0x03, 0x00, 0x05]);
}

#[test]
fn encrypted_inbound_with_fallbacks_rejected_at_config() {
    use crate::vless::{fallback::FallbackDest, FallbackConfig};
    let fallbacks = vec![FallbackConfig {
        name: Some("fb".to_string()),
        alpn: None,
        path: None,
        dest: FallbackDest {
            addr: "127.0.0.1:80".to_string(),
        },
        xver: 0,
    }];
    let raw = "mlkem768x25519plus.native.600s.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(validate_inbound_decryption_with_fallbacks(Some(raw), !fallbacks.is_empty()).is_err());
}

/// Captured from Xray 26.3.27 client plain-TCP encryption hello (live fixture keys).
#[test]
fn xray_captured_enc_len_open_diagnostic() {
    use crate::vless::encryption::aead::TrafficAead;
    use crate::vless::encryption::{x25519_ecdh, X25519PublicKey, X25519SecretKey};

    let hello = include_bytes!("../../../fixtures/vless/encryption/xray_26_3_27_client_hello.bin");
    let iv: [u8; 16] = hello[..16].try_into().expect("iv");
    let mut relay = [0u8; 32];
    relay.copy_from_slice(&hello[16..48]);
    let enc_len = &hello[48..66];

    let server_secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let client_public = X25519PublicKey::from_bytes(relay).expect("relay is x25519 pubkey");
    let nfs_key = x25519_ecdh(&server_secret, &client_public).expect("ecdh");

    let (plain, mut aead) =
        TrafficAead::open_auto_kind_with_state(&iv, nfs_key.as_slice(), true, enc_len, &[])
            .expect("nfs enc_len should open against captured xray hello");
    assert_eq!(plain.len(), 2);
    let length = u16::from_be_bytes([plain[0], plain[1]]);
    assert!(length >= 1184 + 32 + 16, "pfs bundle length {length}");
    let enc_pfs = &hello[66..66 + length as usize];
    let pfs_public = aead
        .open(enc_pfs, &[])
        .expect("nfs enc_pfs should open against captured xray hello");
    assert_eq!(pfs_public.len(), 1184 + 32);
}

#[tokio::test]
async fn xray_26_3_27_captured_client_hello_handshake_succeeds() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let server = VlessEncryptionServer::from_config(config).expect("server");
    let hello = include_bytes!("../../../fixtures/vless/encryption/xray_26_3_27_client_hello.bin");
    let (result, prefix) = server
        .handshake(
            ScriptStream::from_read(hello.to_vec()),
            &mut TestHandshakeRng::new(11),
        )
        .await
        .expect("xray captured hello should handshake");
    assert_eq!(result.xor_mode, XorMode::Native);
    assert!(prefix.prefix_remaining() <= hello.len());
}

#[tokio::test]
async fn prefix_stream_handshake_plus_traffic_records_read_end() {
    use super::client_sim::{client_upload_writer, seal_client_traffic};
    use crate::vless::encryption::handshake::{ENCRYPTED_TICKET_LEN, PFS_SERVER_EXCHANGE_LEN};
    use crate::vless::encryption::io::PrefixStream;
    use crate::vless::encryption::stream::VlessEncryptedStream;
    use bytes::Bytes;
    use tokio::io::duplex;

    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let (mut client_io, server_io) = duplex(65536);
    let server_task = tokio::spawn(async move {
        server
            .handshake(server_io, &mut TestHandshakeRng::new(99))
            .await
            .expect("duplex handshake")
    });
    client_io.write_all(&hello).await.expect("hello");
    let mut response = vec![0u8; PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN];
    client_io.read_exact(&mut response).await.expect("response");
    let (result, _prefix) = server_task.await.expect("server task");

    let mut writer = client_upload_writer(&parts, &response).expect("client writer");
    let frame_a = seal_client_traffic(&mut writer, b"frame-a").expect("seal a");
    let frame_b = seal_client_traffic(&mut writer, b"frame-b").expect("seal b");

    let prefix = PrefixStream::new(
        ScriptStream::from_read(Vec::new()),
        Bytes::from([frame_a, frame_b].concat()),
    );
    let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
    let mut out = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut out)
        .await
        .expect("read traffic");
    assert_eq!(out, b"frame-aframe-b");
}
