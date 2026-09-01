use crate::vless::encryption::handshake::HandshakeError;
use crate::vless::encryption::{VlessEncryptionServer, X25519SecretKey};

use super::client_sim::{build_native_x25519_client_hello, server_config_from_single_x25519};
use super::stream_helpers::ScriptStream;
use super::test_rng::TestHandshakeRng;

fn server_secret() -> X25519SecretKey {
    X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8))
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn handshake_err(hello: Vec<u8>) -> HandshakeError {
    let config = server_config_from_single_x25519(&server_secret());
    match block_on(async {
        VlessEncryptionServer::from_config(config)
            .expect("server")
            .handshake(
                ScriptStream::from_read(hello),
                &mut TestHandshakeRng::new(5),
            )
            .await
    }) {
        Ok(_) => panic!("handshake must fail"),
        Err(err) => err,
    }
}

#[test]
fn malformed_truncated_iv() {
    let err = handshake_err(vec![0u8; 8]);
    assert!(matches!(
        err,
        HandshakeError::Truncated | HandshakeError::Io(_)
    ));
}

#[test]
fn malformed_truncated_x25519_relay() {
    let mut hello = vec![0u8; 16 + 20];
    hello[..16].fill(0x44);
    let err = handshake_err(hello);
    assert!(matches!(
        err,
        HandshakeError::Truncated | HandshakeError::Malformed(_) | HandshakeError::Io(_)
    ));
}

#[test]
fn malformed_truncated_encrypted_length() {
    let mut hello = vec![0u8; 16 + 32 + 10];
    hello[..16].fill(0x44);
    hello[16..48].fill(0x55);
    let err = handshake_err(hello);
    assert!(matches!(
        err,
        HandshakeError::Truncated
            | HandshakeError::CryptoFailure(_)
            | HandshakeError::AuthenticationFailed
    ));
}

#[test]
fn malformed_unexpected_eof_mid_handshake() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let (hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(2));
    let cut = hello.len() / 2;
    let err = match block_on(async {
        VlessEncryptionServer::from_config(config)
            .expect("server")
            .handshake(
                ScriptStream::from_read(hello[..cut].to_vec()),
                &mut TestHandshakeRng::new(5),
            )
            .await
    }) {
        Ok(_) => panic!("truncated hello must fail"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        HandshakeError::Truncated | HandshakeError::Io(_)
    ));
}

#[test]
fn malformed_pfs_length_tamper_rejected() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let (mut hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(4));
    if hello.len() > 70 {
        hello[60] ^= 0xff;
        hello[61] ^= 0xff;
    }
    let err = match block_on(async {
        VlessEncryptionServer::from_config(config)
            .expect("server")
            .handshake(
                ScriptStream::from_read(hello),
                &mut TestHandshakeRng::new(5),
            )
            .await
    }) {
        Ok(_) => panic!("bad pfs length must fail"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        HandshakeError::LengthExceeded
            | HandshakeError::CryptoFailure(_)
            | HandshakeError::Malformed(_)
            | HandshakeError::AuthenticationFailed
    ));
}

#[test]
fn malformed_garbage_hello_no_panic() {
    let _ = handshake_err(vec![0u8; 64]);
}

#[test]
fn malformed_x25519_high_bit_public_key_rejected() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let (mut hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(4));
    hello[47] |= 0x80;
    let err = handshake_err(hello);
    assert!(matches!(
        err,
        HandshakeError::AuthenticationFailed
            | HandshakeError::Malformed(_)
            | HandshakeError::CryptoFailure(_)
    ));
}

#[test]
fn malformed_pfs_body_oversized_rejected() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let (mut hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(4));
    // Tamper NFS encrypted length field (after iv+relay) to claim oversized PFS body.
    if hello.len() > 52 {
        hello[48] = 0xff;
        hello[49] = 0xff;
    }
    let err = handshake_err(hello);
    assert!(matches!(
        err,
        HandshakeError::Truncated
            | HandshakeError::LengthExceeded
            | HandshakeError::Malformed(_)
            | HandshakeError::CryptoFailure(_)
            | HandshakeError::AuthenticationFailed
            | HandshakeError::Io(_)
    ));
}

#[test]
fn malformed_bad_client_padding_tag_rejected() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let (mut hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(4));
    if hello.len() > 8 {
        let tail = hello.len() - 1;
        hello[tail] ^= 0xff;
    }
    let err = match block_on(async {
        VlessEncryptionServer::from_config(config)
            .expect("server")
            .handshake(
                ScriptStream::from_read(hello),
                &mut TestHandshakeRng::new(5),
            )
            .await
    }) {
        Ok(_) => panic!("bad padding must fail"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        HandshakeError::Malformed(_)
            | HandshakeError::CryptoFailure(_)
            | HandshakeError::AuthenticationFailed
            | HandshakeError::Truncated
    ));
}

#[test]
fn malformed_pfs_body_too_short_rejected() {
    let secret = server_secret();
    let config = server_config_from_single_x25519(&secret);
    let (hello, _) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(4));
    let cut = hello.len().saturating_sub(40);
    let err = handshake_err(hello[..cut].to_vec());
    assert!(matches!(
        err,
        HandshakeError::Truncated
            | HandshakeError::LengthExceeded
            | HandshakeError::CryptoFailure(_)
            | HandshakeError::Io(_)
    ));
}

#[test]
fn malformed_bad_mlkem_ciphertext_length_rejected() {
    use crate::vless::encryption::keys::{NfsStaticKey, SecretBytes};
    use crate::vless::encryption::{
        Mlkem768X25519PlusConfig, NfsServerChain, PaddingProfile, TicketLifetimeRange, XorMode,
    };

    let mlkem_seed = [0x42u8; 64];
    let config = Mlkem768X25519PlusConfig {
        xor_mode: XorMode::Native,
        ticket_lifetime: TicketLifetimeRange::disabled(),
        nfs_keys: vec![NfsStaticKey::MlKem768Decapsulation(SecretBytes::new(
            mlkem_seed,
        ))],
        padding: PaddingProfile {
            length_ranges: vec![[101, 35, 35]],
            gap_ranges: vec![],
        },
    };
    let chain = NfsServerChain::from_config(&config).expect("chain");
    let iv = [0x44u8; 16];
    let mut relays = vec![0u8; chain.relays_length().saturating_sub(1)];
    let err = chain
        .derive_nfs_key(&iv, &mut relays)
        .expect_err("short relay buffer");
    assert!(matches!(
        err,
        HandshakeError::Malformed(_) | HandshakeError::Truncated
    ));
}
