use uuid::Uuid;

use crate::vless::uuid_lookup::vless_lookup_uuid;

fn uuid_with_bytes_6_7(a: u8, b: u8) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes[6] = a;
    bytes[7] = b;
    Uuid::from_bytes(bytes)
}

#[test]
fn lookup_zeros_bytes_6_and_7() {
    let wire = uuid_with_bytes_6_7(0x12, 0x34);
    let lookup = vless_lookup_uuid(&wire);
    let mut expected = *wire.as_bytes();
    expected[6] = 0;
    expected[7] = 0;
    assert_eq!(lookup, Uuid::from_bytes(expected));
}

#[test]
fn equivalent_wire_uuids_share_lookup_key() {
    let a = uuid_with_bytes_6_7(0xab, 0xcd);
    let b = uuid_with_bytes_6_7(0x00, 0x00);
    assert_eq!(vless_lookup_uuid(&a), vless_lookup_uuid(&b));
}

#[test]
fn distinct_uuids_remain_distinct_after_lookup() {
    let left = Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid");
    let right = Uuid::parse_str("00000000-0000-0000-0000-000000000002").expect("uuid");
    assert_ne!(vless_lookup_uuid(&left), vless_lookup_uuid(&right));
}
