
use super::*;
use crate::codec::Codec;
use crate::protocol::enums::ProtocolVersion;
use crate::protocol::structs::{ClientExtension, ClientHelloPayload, Random, SessionId};

fn hello_with_x25519_keyshare(payload: Vec<u8>) -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: vec![ClientExtension::KeyShare(vec![KeyShareEntry::new(
            NamedGroup::X25519,
            payload,
        )])],
    }
}

#[test]
fn extract_x25519_keyshare_returns_raw_32_bytes() {
    let raw: [u8; 32] = core::array::from_fn(|i| i as u8);
    let hello = hello_with_x25519_keyshare(raw.to_vec());

    let extracted = extract_x25519_keyshare(&hello).expect("valid X25519 keyshare");

    assert_eq!(extracted, raw);
}

#[test]
fn extract_x25519_keyshare_rejects_get_encoding_prefix_mistake() {
    let raw: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
    let hello = hello_with_x25519_keyshare(raw.to_vec());
    let keyshare = hello.keyshare_extension().unwrap().first().unwrap();

    let extracted = extract_x25519_keyshare(&hello).expect("valid X25519 keyshare");
    let wrong_via_get_encoding = &keyshare.payload.get_encoding()[..32];

    assert_eq!(extracted, raw);
    assert_ne!(extracted.as_slice(), wrong_via_get_encoding);
    assert_eq!(keyshare.payload.get_encoding().len(), 34);
}

#[test]
fn extract_x25519_keyshare_rejects_non_32_byte_payload() {
    let payload = vec![0u8; 34];
    let hello = hello_with_x25519_keyshare(payload);

    assert!(extract_x25519_keyshare(&hello).is_none());
}

#[test]
fn reality_auth_result_debug_redacts_sensitive_fields() {
    let auth = RealityAuthResult {
        auth_key: [7u8; 32],
        client_public_key: [9u8; 32],
    };

    let debug = format!("{auth:?}");

    assert!(debug.contains("auth_key"));
    assert!(debug.contains("client_public_key"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("[7, 7, 7"));
    assert!(!debug.contains("[9, 9, 9"));
}
