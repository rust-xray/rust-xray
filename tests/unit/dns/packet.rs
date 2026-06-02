
use super::*;
use std::net::{IpAddr, Ipv4Addr};

fn example_query() -> Vec<u8> {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    packet.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    packet
}

#[test]
fn parse_question_key_normalizes_qname() {
    let key = parse_dns_question_key(&example_query(), "1.1.1.1:53").unwrap();
    assert_eq!(key.qname, "example.com");
    assert_eq!(key.qtype, 1);
    assert_eq!(key.qclass, 1);
}

#[test]
fn malformed_query_rejected() {
    assert!(parse_dns_question_key(&[0x00], "127.0.0.1:53").is_err());
}

#[test]
fn parse_response_ttl_from_answer() {
    let mut packet = example_query();
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet[6] = 0x00;
    packet[7] = 0x01;
    packet.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 168, 0, 1,
    ]);
    assert_eq!(parse_response_min_ttl(&packet), Some(60));
}

#[test]
fn rewrite_dns_response_id_for_query_rewrites_transaction_id() {
    let current_query = [0xab, 0xcd, 0x01, 0x00];
    let cached_response = [0x12, 0x34, 0x81, 0x80];
    let rewritten = rewrite_dns_response_id_for_query(&cached_response, &current_query).unwrap();
    assert_eq!(&rewritten[..2], &[0xab, 0xcd]);
    assert_eq!(&rewritten[2..], &cached_response[2..]);
}

#[test]
fn rewrite_dns_response_id_rejects_short_packets() {
    assert!(rewrite_dns_response_id_for_query(&[0x12, 0x34], &[0xab]).is_err());
    assert!(rewrite_dns_response_id_for_query(&[0x12], &[0xab, 0xcd]).is_err());
}

#[test]
fn extract_ipv4_from_response() {
    let mut packet = example_query();
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet[6] = 0x00;
    packet[7] = 0x01;
    packet.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 1, 1, 1,
    ]);
    let ips = extract_ipv4_addresses(&packet);
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
}
