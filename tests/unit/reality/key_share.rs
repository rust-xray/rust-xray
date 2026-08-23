use super::*;
use crate::codec::{Codec, Reader};
use crate::protocol::enums::{NamedGroup, ProtocolVersion};
use crate::protocol::structs::{
    ClientExtension, ClientHelloPayload, KeyShareEntry, Random, SessionId,
};

fn key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn pattern_key() -> [u8; 32] {
    core::array::from_fn(|i| 0xC0 + i as u8)
}

fn x25519_entry(k: [u8; 32]) -> KeyShareEntry {
    KeyShareEntry::new(NamedGroup::X25519, k.to_vec())
}

fn hybrid_entry(tail: [u8; 32]) -> KeyShareEntry {
    KeyShareEntry::new(
        NamedGroup::X25519MLKEM768,
        build_x25519mlkem768_client_key_share(tail),
    )
}

fn malformed_x25519(len: usize) -> KeyShareEntry {
    KeyShareEntry::new(NamedGroup::X25519, vec![0u8; len])
}

fn malformed_hybrid(len: usize) -> KeyShareEntry {
    KeyShareEntry::new(NamedGroup::X25519MLKEM768, vec![0u8; len])
}

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

#[test]
fn standalone_x25519_valid_32_bytes() {
    let expected = key(0x01);
    let got = find_reality_auth_x25519_public_key(&[x25519_entry(expected)]);
    assert_eq!(got, Some(expected));
}

#[test]
fn hybrid_only_valid_1216_bytes_returns_trailing_x25519() {
    let tail = key(0x02);
    let got = find_reality_auth_x25519_public_key(&[hybrid_entry(tail)]);
    assert_eq!(got, Some(tail));
    let entry = hybrid_entry(tail);
    let payload = entry.payload.bytes();
    assert_eq!(payload.len(), X25519_MLKEM768_CLIENT_KEY_SHARE_LEN);
    assert_eq!(&payload[MLKEM768_ENCAPSULATION_KEY_LEN..], tail.as_slice());
}

#[test]
fn reality_auth_prefers_standalone_x25519_over_hybrid_regardless_of_order() {
    let hybrid_trailing_a: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
    let standalone_b: [u8; 32] = core::array::from_fn(|i| 0xB0 + i as u8);
    assert_ne!(hybrid_trailing_a, standalone_b);

    let shares = vec![hybrid_entry(hybrid_trailing_a), x25519_entry(standalone_b)];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(standalone_b),
        "standalone X25519 must win even when hybrid appears first"
    );
}

#[test]
fn hybrid_before_standalone_prefers_standalone() {
    let hybrid_tail = key(0xAA);
    let standalone = key(0xBB);
    let shares = vec![hybrid_entry(hybrid_tail), x25519_entry(standalone)];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(standalone)
    );
}

#[test]
fn standalone_before_hybrid_prefers_standalone() {
    let standalone = key(0xBB);
    let hybrid_tail = key(0xAA);
    let shares = vec![x25519_entry(standalone), hybrid_entry(hybrid_tail)];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(standalone)
    );
}

#[test]
fn malformed_x25519_len_31_falls_back_to_valid_hybrid() {
    let hybrid_tail = key(0x03);
    let shares = vec![malformed_x25519(31), hybrid_entry(hybrid_tail)];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(hybrid_tail)
    );
}

#[test]
fn malformed_x25519_len_33_falls_back_to_valid_hybrid() {
    let hybrid_tail = key(0x04);
    let shares = vec![malformed_x25519(33), hybrid_entry(hybrid_tail)];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(hybrid_tail)
    );
}

#[test]
fn hybrid_len_1215_is_unusable() {
    assert!(find_reality_auth_x25519_public_key(&[malformed_hybrid(1215)]).is_none());
}

#[test]
fn hybrid_len_1217_is_unusable() {
    assert!(find_reality_auth_x25519_public_key(&[malformed_hybrid(1217)]).is_none());
}

#[test]
fn unknown_group_with_valid_hybrid_uses_hybrid() {
    let hybrid_tail = key(0x05);
    let shares = vec![
        KeyShareEntry::new(NamedGroup::secp256r1, vec![0u8; 65]),
        hybrid_entry(hybrid_tail),
    ];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(hybrid_tail)
    );
}

#[test]
fn unknown_group_only_has_no_usable_auth_key() {
    let shares = vec![KeyShareEntry::new(NamedGroup::secp384r1, vec![0u8; 97])];
    assert!(find_reality_auth_x25519_public_key(&shares).is_none());
}

#[test]
fn multiple_malformed_x25519_then_valid_standalone() {
    let standalone = key(0x06);
    let shares = vec![
        malformed_x25519(31),
        malformed_x25519(33),
        x25519_entry(standalone),
    ];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(standalone)
    );
}

#[test]
fn multiple_hybrid_entries_uses_first_valid() {
    let first_tail = key(0x07);
    let second_tail = key(0x08);
    let shares = vec![malformed_hybrid(1215), hybrid_entry(second_tail)];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(second_tail)
    );
    let _ = first_tail;
}

#[test]
fn standalone_returns_bytes_without_crypto_validation() {
    let zero = [0u8; 32];
    let random = core::array::from_fn(|i| (i * 7) as u8);
    assert_eq!(
        find_reality_auth_x25519_public_key(&[x25519_entry(zero)]),
        Some(zero)
    );
    assert_eq!(
        find_reality_auth_x25519_public_key(&[x25519_entry(random)]),
        Some(random)
    );
}

#[test]
fn named_group_x25519mlkem768_wire_value_and_unknown_alias() {
    assert_eq!(
        u16::from(NamedGroup::X25519MLKEM768),
        NAMED_GROUP_X25519MLKEM768
    );
    assert_eq!(NAMED_GROUP_X25519MLKEM768, 0x11ec);
    assert!(is_x25519mlkem768_group(NamedGroup::X25519MLKEM768));
    assert!(is_x25519mlkem768_group(NamedGroup::Unknown(
        NAMED_GROUP_X25519MLKEM768
    )));
}

#[test]
fn clienthello_key_share_extension_roundtrip_extracts_hybrid_trailing_x25519() {
    let tail = pattern_key();
    let hello = hello_with_keyshares(vec![hybrid_entry(tail)]);

    let mut encoded = Vec::new();
    hello.encode(&mut encoded);
    let mut reader = Reader::init(&encoded);
    let parsed = ClientHelloPayload::read(&mut reader).expect("parse ClientHello");

    let keyshares = parsed.keyshare_extension().expect("key_share extension");
    assert_eq!(keyshares.len(), 1);
    assert_eq!(keyshares[0].group(), NamedGroup::X25519MLKEM768);
    assert_eq!(
        keyshares[0].payload.bytes().len(),
        X25519_MLKEM768_CLIENT_KEY_SHARE_LEN
    );

    let extracted = find_reality_auth_x25519_public_key(keyshares).expect("auth key");
    assert_eq!(extracted, tail);
}
