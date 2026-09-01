use crate::reality::key_share::MLKEM768_CIPHERTEXT_LEN;
use crate::reality::key_share::MLKEM768_ENCAPSULATION_KEY_LEN;
use crate::vless::encryption::keys::{NfsStaticKey, SecretBytes};
use crate::vless::encryption::stream::VlessEncryptedStream;
use crate::vless::encryption::{
    encapsulate_mlkem768, nfs_public_key_hash, NfsServerChain, PaddingProfile, TicketLifetimeRange,
    VlessEncryptionServer, X25519SecretKey, XorMode,
};

use super::client_sim::{
    build_mixed_nfs_client_hello, build_mlkem_only_client_hello, client_complete_1rtt_handshake,
};
use super::stream_helpers::ScriptStream;
use super::test_rng::TestHandshakeRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const GO_MLKEM_SEED: [u8; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
];

fn mlkem_only_config() -> crate::vless::encryption::Mlkem768X25519PlusConfig {
    crate::vless::encryption::Mlkem768X25519PlusConfig {
        xor_mode: XorMode::Native,
        ticket_lifetime: TicketLifetimeRange::disabled(),
        nfs_keys: vec![NfsStaticKey::MlKem768Decapsulation(SecretBytes::new(
            GO_MLKEM_SEED,
        ))],
        padding: PaddingProfile {
            length_ranges: vec![[101, 35, 35]],
            gap_ranges: vec![],
        },
    }
}

fn mixed_x25519_mlkem_config(
    x25519_secret: &X25519SecretKey,
) -> crate::vless::encryption::Mlkem768X25519PlusConfig {
    crate::vless::encryption::Mlkem768X25519PlusConfig {
        xor_mode: XorMode::Native,
        ticket_lifetime: TicketLifetimeRange::disabled(),
        nfs_keys: vec![
            NfsStaticKey::X25519(SecretBytes::new(*x25519_secret.as_bytes())),
            NfsStaticKey::MlKem768Decapsulation(SecretBytes::new(GO_MLKEM_SEED)),
        ],
        padding: PaddingProfile {
            length_ranges: vec![[101, 35, 35]],
            gap_ranges: vec![],
        },
    }
}

#[test]
fn mlkem_only_nfs_derive_pfs_united_roundtrip() {
    let config = mlkem_only_config();
    let chain = NfsServerChain::from_config(&config).expect("chain");
    assert_eq!(chain.key_count(), 1);
    assert_eq!(chain.relays_length(), MLKEM768_CIPHERTEXT_LEN);

    let server_mlkem_public = config.nfs_keys[0].public_key_bytes().expect("mlkem public");
    let ek: [u8; MLKEM768_ENCAPSULATION_KEY_LEN] =
        server_mlkem_public.as_slice().try_into().expect("ek len");
    let (ciphertext, expected_ss) = encapsulate_mlkem768(&ek).expect("encap");

    let iv = [0x44u8; 16];
    let mut relays = ciphertext;
    let nfs_key = chain.derive_nfs_key(&iv, &mut relays).expect("derive nfs");
    assert_eq!(nfs_key.as_bytes(), expected_ss.as_bytes());
}

#[test]
fn mixed_x25519_mlkem_chain_derive_with_hash_check() {
    use crate::reality::key_share::MLKEM768_ENCAPSULATION_KEY_LEN;
    use crate::vless::encryption::xor::CtrStream;

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let client_secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 50) as u8));
    let client_public = crate::vless::encryption::x25519_public_key(&client_secret);
    let config = mixed_x25519_mlkem_config(&secret);
    let chain = NfsServerChain::from_config(&config).expect("chain");
    assert_eq!(chain.key_count(), 2);

    let iv = [0x33u8; 16];
    let mut relays = vec![0u8; chain.relays_length()];
    relays[..32].copy_from_slice(client_public.as_bytes());

    let mlkem_public = config.nfs_keys[1].public_key_bytes().expect("mlkem public");
    relays[32..64].copy_from_slice(&nfs_public_key_hash(&mlkem_public));

    let ek: [u8; MLKEM768_ENCAPSULATION_KEY_LEN] = mlkem_public.as_slice().try_into().expect("ek");
    let (ciphertext, _) = encapsulate_mlkem768(&ek).expect("encap");
    relays[64..64 + MLKEM768_CIPHERTEXT_LEN].copy_from_slice(&ciphertext);

    let x25519_shared = crate::vless::encryption::x25519_ecdh(
        &secret,
        &crate::vless::encryption::X25519PublicKey::from_bytes(*client_public.as_bytes())
            .expect("pk"),
    )
    .expect("ecdh");
    let mut hash_region = nfs_public_key_hash(&mlkem_public);
    let mut ctr = CtrStream::new(x25519_shared.as_slice(), &iv);
    ctr.apply_keystream(&mut hash_region);
    relays[32..64].copy_from_slice(&hash_region);

    chain
        .derive_nfs_key(&iv, &mut relays)
        .expect("mixed chain derive");
}

#[test]
fn mixed_chain_corrupt_relay_hash_rejected() {
    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let client_secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 50) as u8));
    let client_public = crate::vless::encryption::x25519_public_key(&client_secret);
    let config = mixed_x25519_mlkem_config(&secret);
    let chain = NfsServerChain::from_config(&config).expect("chain");

    let iv = [0x33u8; 16];
    let mut relays = vec![0u8; chain.relays_length()];
    relays[..32].copy_from_slice(client_public.as_bytes());
    relays[32..64].fill(0x00);

    let err = chain
        .derive_nfs_key(&iv, &mut relays)
        .expect_err("bad hash");
    assert!(matches!(
        err,
        crate::vless::encryption::HandshakeError::AuthenticationFailed
    ));
}

#[test]
fn mixed_client_hello_nfs_key_matches_chain_derive() {
    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = mixed_x25519_mlkem_config(&secret);
    let chain = NfsServerChain::from_config(&config).expect("chain");
    let (hello, parts) =
        build_mixed_nfs_client_hello(&config, &secret, &mut TestHandshakeRng::new(5));
    let iv: [u8; 16] = hello[..16].try_into().expect("iv");
    let mut relays = hello[16..16 + chain.relays_length()].to_vec();
    let derived = chain
        .derive_nfs_key(&iv, &mut relays)
        .expect("mixed hello relays must derive");
    assert_eq!(
        derived.as_bytes(),
        &parts.nfs_key,
        "client hello NFS AEAD key must match server chain derive"
    );
}

#[test]
fn mixed_client_hello_relays_match_server_chain() {
    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = mixed_x25519_mlkem_config(&secret);
    let chain = NfsServerChain::from_config(&config).expect("chain");
    let (hello, _) = build_mixed_nfs_client_hello(&config, &secret, &mut TestHandshakeRng::new(5));
    let iv: [u8; 16] = hello[..16].try_into().expect("iv");
    let mut relays = hello[16..16 + chain.relays_length()].to_vec();
    chain
        .derive_nfs_key(&iv, &mut relays)
        .expect("mixed hello relays must derive");
}

#[tokio::test]
async fn mlkem_only_full_1rtt_handshake_and_traffic() {
    let config = mlkem_only_config();
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) = build_mlkem_only_client_hello(&config, &mut TestHandshakeRng::new(11));
    let expected = b"mlkem-only-commonconn-traffic";

    let (client_io, server_io) = tokio::io::duplex(65536);
    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(22))
            .await
            .expect("mlkem-only handshake");
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.expect("read");
        buf.truncate(n);
        buf
    });

    let client_task = tokio::spawn(async move {
        let mut encrypted =
            client_complete_1rtt_handshake(client_io, &hello, &parts, &config, 22, XorMode::Native)
                .await
                .expect("client handshake");
        encrypted.write_all(expected).await.expect("traffic");
        encrypted.flush().await.expect("flush");
        let _ = encrypted.shutdown().await;
    });

    let (received, client_result) = tokio::join!(server_task, client_task);
    let received = received.expect("server");
    client_result.expect("client");
    assert_eq!(received, expected);
}

#[tokio::test]
async fn mixed_nfs_scriptstream_handshake_succeeds() {
    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = mixed_x25519_mlkem_config(&secret);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, _) = build_mixed_nfs_client_hello(&config, &secret, &mut TestHandshakeRng::new(5));
    server
        .handshake(
            ScriptStream::from_read(hello),
            &mut TestHandshakeRng::new(6),
        )
        .await
        .expect("mixed scriptstream handshake");
}

#[tokio::test]
async fn mixed_nfs_full_1rtt_handshake_and_traffic() {
    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = mixed_x25519_mlkem_config(&secret);
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (hello, parts) =
        build_mixed_nfs_client_hello(&config, &secret, &mut TestHandshakeRng::new(5));
    let expected = b"mixed-nfs-commonconn-traffic";

    let (client_io, server_io) = tokio::io::duplex(65536);
    let server_task = tokio::spawn(async move {
        let (result, prefix) = server
            .handshake(server_io, &mut TestHandshakeRng::new(6))
            .await
            .expect("mixed handshake");
        let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
        let mut buf = vec![0u8; 256];
        let n = stream.read(&mut buf).await.expect("read");
        buf.truncate(n);
        buf
    });

    let client_task = tokio::spawn(async move {
        let mut encrypted =
            client_complete_1rtt_handshake(client_io, &hello, &parts, &config, 6, XorMode::Native)
                .await
                .expect("client handshake");
        encrypted.write_all(expected).await.expect("traffic");
        encrypted.flush().await.expect("flush");
        let _ = encrypted.shutdown().await;
    });

    let (received, client_result) = tokio::join!(server_task, client_task);
    let received = received.expect("server");
    client_result.expect("client");
    assert_eq!(received, expected);
}
