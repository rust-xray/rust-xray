
use super::*;

#[test]
fn dns_tcp_encode_decode() {
    let query = [0x12, 0x34, 0x01, 0x00];
    let frame = encode_dns_tcp_frame(&query).unwrap();
    assert_eq!(&frame[..2], &[0x00, 0x04]);
    assert_eq!(decode_dns_tcp_frame(&frame).unwrap(), query);
}

#[test]
fn dns_tcp_reject_truncated() {
    assert!(decode_dns_tcp_frame(&[0x00]).is_err());
    assert!(decode_dns_tcp_frame(&[0x00, 0x04, 0x12]).is_err());
}

#[test]
fn dns_tcp_reject_zero_length() {
    assert!(encode_dns_tcp_frame(&[]).is_err());
    assert!(decode_dns_tcp_frame(&[0x00, 0x00]).is_err());
}
