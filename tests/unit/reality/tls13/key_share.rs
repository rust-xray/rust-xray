use super::*;
use crate::protocol::enums::ProtocolVersion;
use crate::protocol::structs::{
    ClientExtension, ClientHelloPayload, KeyShareEntry, Random, SessionId,
};
use crate::reality::key_share::{
    build_x25519mlkem768_client_key_share, MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN,
    MLKEM768_SHARED_SECRET_LEN, NAMED_GROUP_X25519MLKEM768, X25519_MLKEM768_CLIENT_KEY_SHARE_LEN,
    X25519_MLKEM768_SERVER_KEY_SHARE_LEN, X25519_MLKEM768_SHARED_SECRET_LEN,
};
use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{Decapsulate, Kem, KeyExport};
use x25519_dalek::{PublicKey, StaticSecret};

fn hello_with_keyshares(keyshares: Vec<KeyShareEntry>) -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: vec![ClientExtension::KeyShare(keyshares)],
    }
}

fn hello_without_keyshare() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: Vec::new(),
    }
}

fn sample_client_public_key() -> [u8; 32] {
    let client_secret = StaticSecret::random();
    *PublicKey::from(&client_secret).as_bytes()
}

fn build_hybrid_client_share_with_keypair(
) -> (Vec<u8>, ml_kem::ml_kem_768::DecapsulationKey, StaticSecret) {
    let client_x25519_secret = StaticSecret::random();
    let client_x25519_public = *PublicKey::from(&client_x25519_secret).as_bytes();
    let (dk, ek) = MlKem768::generate_keypair();
    let mut client_hybrid = ek.to_bytes().to_vec();
    client_hybrid.extend_from_slice(&client_x25519_public);
    (client_hybrid, dk, client_x25519_secret)
}

#[test]
fn generate_x25519_server_key_share_lengths() {
    let share =
        generate_x25519_server_key_share(sample_client_public_key()).expect("valid key share");

    assert_eq!(share.group, NAMED_GROUP_X25519);
    assert_eq!(share.key_exchange().len(), X25519_KEY_LEN);
    assert_eq!(share.shared_secret().len(), X25519_KEY_LEN);
}

#[test]
fn encode_key_share_extension_body_for_x25519() {
    let share = Tls13ServerKeyShare::from_test_parts(
        NAMED_GROUP_X25519,
        vec![0x33; X25519_KEY_LEN],
        vec![0x44; X25519_KEY_LEN],
    );

    let body = encode_key_share_extension_body(&share).expect("valid extension body");

    assert_eq!(body.len(), 36);
    assert_eq!(&body[..4], &[0x00, 0x1d, 0x00, 0x20]);
    assert_eq!(&body[4..], &[0x33; X25519_KEY_LEN]);
}

#[test]
fn debug_does_not_contain_shared_secret_bytes() {
    let share = Tls13ServerKeyShare::from_test_parts(
        NAMED_GROUP_X25519,
        vec![0x11; X25519_KEY_LEN],
        vec![0xde; X25519_KEY_LEN],
    );

    let debug = format!("{share:?}");

    assert!(!debug.contains("222"));
    assert!(!debug.contains("0xde"));
    assert!(debug.contains("redacted"));
}

#[test]
fn extract_client_x25519_key_share_returns_none_without_extension() {
    let hello = hello_without_keyshare();
    let extracted = extract_client_x25519_key_share(&hello).expect("valid extraction");

    assert_eq!(extracted, None);
}

#[test]
fn extract_client_x25519_key_share_returns_some_for_valid_x25519() {
    let raw: [u8; 32] = core::array::from_fn(|i| i as u8);
    let hello = hello_with_keyshares(vec![KeyShareEntry::new(NamedGroup::X25519, raw.to_vec())]);

    let extracted = extract_client_x25519_key_share(&hello)
        .expect("valid extraction")
        .expect("X25519 key share present");

    assert_eq!(extracted, raw);
}

#[test]
fn extract_client_x25519_key_share_rejects_wrong_length() {
    let hello = hello_with_keyshares(vec![KeyShareEntry::new(NamedGroup::X25519, vec![0u8; 31])]);

    let err = extract_client_x25519_key_share(&hello).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("32 bytes"));
}

#[test]
fn extract_client_x25519_key_share_ignores_non_x25519_groups() {
    let hello = hello_with_keyshares(vec![KeyShareEntry::new(
        NamedGroup::secp256r1,
        vec![0u8; 65],
    )]);

    let extracted = extract_client_x25519_key_share(&hello).expect("valid extraction");

    assert_eq!(extracted, None);
}

#[test]
fn extract_client_x25519_key_share_prefers_x25519_among_multiple_groups() {
    let raw: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
    let hello = hello_with_keyshares(vec![
        KeyShareEntry::new(NamedGroup::secp256r1, vec![0u8; 65]),
        KeyShareEntry::new(NamedGroup::X25519, raw.to_vec()),
    ]);

    let extracted = extract_client_x25519_key_share(&hello)
        .expect("valid extraction")
        .expect("X25519 key share present");

    assert_eq!(extracted, raw);
}

#[test]
fn extract_client_x25519_key_share_ignores_x25519mlkem768_hybrid_entry() {
    let hybrid_tail: [u8; 32] = core::array::from_fn(|i| 0xC0 + i as u8);
    let hello = hello_with_keyshares(vec![KeyShareEntry::new(
        NamedGroup::X25519MLKEM768,
        build_x25519mlkem768_client_key_share(hybrid_tail),
    )]);

    let extracted = extract_client_x25519_key_share(&hello).expect("valid extraction");

    assert_eq!(extracted, None);
}

#[test]
fn extract_client_x25519_key_share_uses_standalone_not_hybrid_when_both_present() {
    let hybrid_tail: [u8; 32] = [0xAA; 32];
    let standalone: [u8; 32] = core::array::from_fn(|i| 0x44 + i as u8);
    assert_ne!(hybrid_tail, standalone);

    let hello = hello_with_keyshares(vec![
        KeyShareEntry::new(
            NamedGroup::X25519MLKEM768,
            build_x25519mlkem768_client_key_share(hybrid_tail),
        ),
        KeyShareEntry::new(NamedGroup::X25519, standalone.to_vec()),
    ]);

    let extracted = extract_client_x25519_key_share(&hello)
        .expect("valid extraction")
        .expect("standalone X25519 key share present");

    assert_eq!(extracted, standalone);
}

#[test]
fn encode_key_share_extension_body_for_x25519mlkem768() {
    let share = Tls13ServerKeyShare::from_test_parts(
        NAMED_GROUP_X25519MLKEM768,
        vec![0x33; X25519_MLKEM768_SERVER_KEY_SHARE_LEN],
        vec![0x44; X25519_MLKEM768_SHARED_SECRET_LEN],
    );

    let body = encode_key_share_extension_body(&share).expect("valid hybrid extension body");

    assert_eq!(body.len(), 4 + X25519_MLKEM768_SERVER_KEY_SHARE_LEN);
    assert_eq!(&body[..4], &[0x11, 0xec, 0x04, 0x60]);
    assert_eq!(&body[4..], &[0x33; X25519_MLKEM768_SERVER_KEY_SHARE_LEN]);
    assert_eq!(X25519_MLKEM768_SERVER_KEY_SHARE_LEN, 1120);
    assert_eq!(1120, 0x0460);
}

#[test]
fn generate_x25519mlkem768_server_key_share_valid_lengths() {
    let (client_hybrid, _dk, _client_x25519_secret) = build_hybrid_client_share_with_keypair();

    let share = generate_x25519mlkem768_server_key_share(&client_hybrid).expect("valid hybrid");

    assert_eq!(share.group, NAMED_GROUP_X25519MLKEM768);
    assert_eq!(
        share.key_exchange().len(),
        X25519_MLKEM768_SERVER_KEY_SHARE_LEN
    );
    assert_eq!(
        share.shared_secret().len(),
        X25519_MLKEM768_SHARED_SECRET_LEN
    );
}

#[test]
fn generate_x25519mlkem768_server_key_share_wire_layout() {
    let (client_hybrid, _dk, _client_x25519_secret) = build_hybrid_client_share_with_keypair();

    let share = generate_x25519mlkem768_server_key_share(&client_hybrid).expect("valid hybrid");
    let key_exchange = share.key_exchange();

    assert_eq!(key_exchange.len(), X25519_MLKEM768_SERVER_KEY_SHARE_LEN);
    assert_eq!(
        key_exchange[..MLKEM768_CIPHERTEXT_LEN].len(),
        MLKEM768_CIPHERTEXT_LEN
    );
    assert_eq!(
        key_exchange[MLKEM768_CIPHERTEXT_LEN..].len(),
        X25519_KEY_LEN
    );
}

#[test]
fn generate_x25519mlkem768_server_key_share_interop_crypto() {
    let (client_hybrid, client_dk, client_x25519_secret) = build_hybrid_client_share_with_keypair();

    let share = generate_x25519mlkem768_server_key_share(&client_hybrid).expect("valid hybrid");
    let key_exchange = share.key_exchange();

    let mlkem_ciphertext = &key_exchange[..MLKEM768_CIPHERTEXT_LEN];
    let client_mlkem_shared = client_dk
        .decapsulate_slice(mlkem_ciphertext)
        .expect("valid ML-KEM ciphertext");

    let server_x25519_public: [u8; X25519_KEY_LEN] = key_exchange[MLKEM768_CIPHERTEXT_LEN..]
        .try_into()
        .expect("trailing X25519 public key");
    let client_x25519_shared = client_x25519_secret
        .diffie_hellman(&PublicKey::from(server_x25519_public))
        .as_bytes()
        .to_vec();

    let mut client_combined = vec![0u8; X25519_MLKEM768_SHARED_SECRET_LEN];
    client_combined[..MLKEM768_SHARED_SECRET_LEN].copy_from_slice(client_mlkem_shared.as_slice());
    client_combined[MLKEM768_SHARED_SECRET_LEN..].copy_from_slice(&client_x25519_shared);

    assert_eq!(client_combined.as_slice(), share.shared_secret());
}

#[test]
fn generate_x25519mlkem768_server_key_share_secret_order_mlkem_then_x25519() {
    let (client_hybrid, client_dk, client_x25519_secret) = build_hybrid_client_share_with_keypair();

    let share = generate_x25519mlkem768_server_key_share(&client_hybrid).expect("valid hybrid");
    let key_exchange = share.key_exchange();
    let tls_shared = share.shared_secret();

    let mlkem_ciphertext = &key_exchange[..MLKEM768_CIPHERTEXT_LEN];
    let client_mlkem_shared = client_dk
        .decapsulate_slice(mlkem_ciphertext)
        .expect("valid ML-KEM ciphertext");

    let server_x25519_public: [u8; X25519_KEY_LEN] = key_exchange[MLKEM768_CIPHERTEXT_LEN..]
        .try_into()
        .expect("trailing X25519 public key");
    let client_x25519_shared =
        client_x25519_secret.diffie_hellman(&PublicKey::from(server_x25519_public));
    let client_x25519_shared_bytes = client_x25519_shared.as_bytes();

    assert_eq!(
        &tls_shared[..MLKEM768_SHARED_SECRET_LEN],
        client_mlkem_shared.as_slice()
    );
    assert_eq!(
        &tls_shared[MLKEM768_SHARED_SECRET_LEN..],
        client_x25519_shared_bytes
    );
}

#[test]
fn generate_x25519mlkem768_server_key_share_rejects_short_client_share() {
    let err = generate_x25519mlkem768_server_key_share(&vec![
        0u8;
        X25519_MLKEM768_CLIENT_KEY_SHARE_LEN
            - 1
    ])
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("1216"));
}

#[test]
fn generate_x25519mlkem768_server_key_share_rejects_long_client_share() {
    let err = generate_x25519mlkem768_server_key_share(&vec![
        0u8;
        X25519_MLKEM768_CLIENT_KEY_SHARE_LEN
            + 1
    ])
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("1216"));
}

#[test]
fn generate_x25519mlkem768_server_key_share_rejects_invalid_mlkem_encapsulation_key() {
    let client_x25519_public = sample_client_public_key();
    let mut client_hybrid = vec![0xFF; MLKEM768_ENCAPSULATION_KEY_LEN];
    client_hybrid.extend_from_slice(&client_x25519_public);

    let err = generate_x25519mlkem768_server_key_share(&client_hybrid).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("ML-KEM-768"));
}

#[test]
fn extract_client_x25519mlkem768_hybrid_key_share_returns_valid_payload() {
    let hybrid_tail: [u8; 32] = core::array::from_fn(|i| 0xB0 + i as u8);
    let payload = build_x25519mlkem768_client_key_share(hybrid_tail);
    let hello = hello_with_keyshares(vec![KeyShareEntry::new(
        NamedGroup::X25519MLKEM768,
        payload.clone(),
    )]);

    let extracted = extract_client_x25519mlkem768_hybrid_key_share(&hello)
        .expect("valid extraction")
        .expect("hybrid key share present");

    assert_eq!(extracted, payload);
    assert_eq!(extracted.len(), X25519_MLKEM768_CLIENT_KEY_SHARE_LEN);
}

#[test]
fn extract_client_x25519mlkem768_hybrid_key_share_rejects_wrong_length() {
    let hello = hello_with_keyshares(vec![KeyShareEntry::new(
        NamedGroup::X25519MLKEM768,
        vec![0u8; X25519_MLKEM768_CLIENT_KEY_SHARE_LEN - 1],
    )]);

    let err = extract_client_x25519mlkem768_hybrid_key_share(&hello).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("1216"));
}

#[test]
fn encode_key_share_extension_body_rejects_mismatched_hybrid_length() {
    let share = Tls13ServerKeyShare::from_test_parts(
        NAMED_GROUP_X25519MLKEM768,
        vec![0x33; X25519_MLKEM768_SERVER_KEY_SHARE_LEN - 1],
        vec![0x44; X25519_MLKEM768_SHARED_SECRET_LEN],
    );

    let err = encode_key_share_extension_body(&share).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("1120"));
}
