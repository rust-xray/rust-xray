
use super::*;
use crate::protocol::enums::ProtocolVersion;
use crate::protocol::structs::{
    ClientExtension, ClientHelloPayload, KeyShareEntry, Random, SessionId,
};

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

#[test]
fn generate_x25519_server_key_share_lengths() {
    let share =
        generate_x25519_server_key_share(sample_client_public_key()).expect("valid key share");

    assert_eq!(share.group, NAMED_GROUP_X25519);
    assert_eq!(share.public_key.len(), X25519_KEY_LEN);
    assert_eq!(share.shared_secret.len(), X25519_KEY_LEN);
}

#[test]
fn encode_key_share_extension_body_for_x25519() {
    let share = Tls13ServerKeyShare {
        group: NAMED_GROUP_X25519,
        public_key: [0x33; X25519_KEY_LEN],
        shared_secret: [0x44; X25519_KEY_LEN],
    };

    let body = encode_key_share_extension_body(&share).expect("valid extension body");

    assert_eq!(body.len(), 36);
    assert_eq!(&body[..4], &[0x00, 0x1d, 0x00, 0x20]);
    assert_eq!(&body[4..], &[0x33; X25519_KEY_LEN]);
}

#[test]
fn debug_does_not_contain_shared_secret_bytes() {
    let share = Tls13ServerKeyShare {
        group: NAMED_GROUP_X25519,
        public_key: [0x11; X25519_KEY_LEN],
        shared_secret: [0xde; X25519_KEY_LEN],
    };

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
