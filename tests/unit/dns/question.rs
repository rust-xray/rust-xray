use super::*;

fn query(qtype: u16) -> Vec<u8> {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    packet.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet
}

#[test]
fn parse_example_com_a() {
    let parsed = parse_dns_question_for_log(&query(1)).unwrap();
    assert_eq!(parsed.qname, "example.com");
    assert_eq!(parsed.qtype, 1);
}

#[test]
fn parse_example_com_aaaa() {
    let parsed = parse_dns_question_for_log(&query(28)).unwrap();
    assert_eq!(parsed.qname, "example.com");
    assert_eq!(parsed.qtype, 28);
}

#[test]
fn malformed_dns_question_returns_none() {
    assert!(parse_dns_question_for_log(&[0x12, 0x34]).is_none());
    let mut packet = query(1);
    packet.truncate(packet.len() - 2);
    assert!(parse_dns_question_for_log(&packet).is_none());
}

#[test]
fn compression_pointer_in_question_returns_none() {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00,
        0x01, 0x00, 0x01,
    ];
    assert!(parse_dns_question_for_log(&packet).is_none());
    packet[12] = 0xff;
    assert!(parse_dns_question_for_log(&packet).is_none());
}
