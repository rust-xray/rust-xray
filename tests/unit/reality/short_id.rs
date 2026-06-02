
use super::*;

#[test]
fn parse_short_id_hex_empty_string() {
    assert_eq!(parse_short_id_hex("").unwrap(), Vec::<u8>::new());
}

#[test]
fn parse_short_id_hex_single_byte() {
    assert_eq!(parse_short_id_hex("00").unwrap(), vec![0x00]);
}

#[test]
fn parse_short_id_hex_max_eight_bytes() {
    assert_eq!(
        parse_short_id_hex("0123456789abcdef").unwrap(),
        vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    );
}

#[test]
fn parse_short_id_hex_rejects_odd_length() {
    let err = parse_short_id_hex("abc").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("invalid REALITY shortId 'abc'"));
    assert!(err.to_string().contains("even-length hex"));
}

#[test]
fn parse_short_id_hex_rejects_too_long() {
    let err = parse_short_id_hex("0123456789abcdef0").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("0123456789abcdef0"));
}

#[test]
fn parse_short_id_hex_rejects_non_hex_symbol() {
    let err = parse_short_id_hex("012g").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("012g"));
}
