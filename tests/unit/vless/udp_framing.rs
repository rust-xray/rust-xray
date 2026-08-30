use crate::vless::udp_framing::{
    encode_vless_udp_packet, VlessUdpFramingError, VlessUdpPacketDecoder, VLESS_UDP_MAX_PACKET_LEN,
};

#[test]
fn encode_and_decode_one_packet() {
    let payload = b"deadbeef";
    let framed = encode_vless_udp_packet(payload).expect("encode");
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&framed);
    assert_eq!(
        decoder.next_packet().expect("decode").as_deref(),
        Some(payload.as_slice())
    );
}

#[test]
fn multiple_packets_coalesced() {
    let a = encode_vless_udp_packet(b"aa").expect("a");
    let b = encode_vless_udp_packet(b"bbbb").expect("b");
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&a);
    decoder.push(&b);
    assert_eq!(decoder.next_packet().expect("a").unwrap(), b"aa");
    assert_eq!(decoder.next_packet().expect("b").unwrap(), b"bbbb");
    assert!(decoder.next_packet().expect("done").is_none());
}

#[test]
fn length_prefix_fragmented() {
    let payload = b"xy";
    let mut framed = encode_vless_udp_packet(payload).expect("frame");
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&framed[..1]);
    assert!(decoder.next_packet().expect("partial len").is_none());
    decoder.push(&framed[1..]);
    assert_eq!(decoder.next_packet().expect("full").unwrap(), payload);
}

#[test]
fn payload_fragmented_across_reads() {
    let payload = vec![7u8; 32];
    let framed = encode_vless_udp_packet(&payload).expect("frame");
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&framed[..3]);
    assert!(decoder.next_packet().expect("partial").is_none());
    decoder.push(&framed[3..10]);
    assert!(decoder.next_packet().expect("partial").is_none());
    decoder.push(&framed[10..]);
    assert_eq!(decoder.next_packet().expect("full").unwrap(), payload);
}

#[test]
fn truncated_packet_returns_unexpected_eof() {
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&[0, 4, 1, 2]);
    decoder.mark_eof();
    assert_eq!(
        decoder.next_packet().expect_err("eof"),
        VlessUdpFramingError::UnexpectedEof
    );
}

#[test]
fn maximum_packet_size_round_trip() {
    let payload = vec![9u8; VLESS_UDP_MAX_PACKET_LEN];
    let framed = encode_vless_udp_packet(&payload).expect("encode max");
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&framed);
    assert_eq!(decoder.next_packet().expect("decode").unwrap(), payload);
}

#[test]
fn oversized_encoder_payload_is_rejected() {
    let payload = vec![1u8; VLESS_UDP_MAX_PACKET_LEN + 1];
    assert!(matches!(
        encode_vless_udp_packet(&payload).expect_err("too large"),
        VlessUdpFramingError::PayloadTooLarge { .. }
    ));
}

#[test]
fn zero_length_packet_is_skipped_on_decode() {
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&[0, 0, 0, 2, b'h', b'i']);
    assert_eq!(decoder.next_packet().expect("skip zero").unwrap(), b"hi");
}

#[test]
fn initial_payload_contains_complete_packet() {
    let payload = b"one";
    let framed = encode_vless_udp_packet(payload).expect("frame");
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&framed);
    assert_eq!(decoder.next_packet().expect("one").unwrap(), payload);
}

#[test]
fn initial_payload_contains_multiple_packets() {
    let mut coalesced = encode_vless_udp_packet(b"a").expect("a");
    coalesced.extend(encode_vless_udp_packet(b"bb").expect("b"));
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&coalesced);
    assert_eq!(decoder.next_packet().unwrap().unwrap(), b"a");
    assert_eq!(decoder.next_packet().unwrap().unwrap(), b"bb");
}

#[test]
fn initial_payload_contains_partial_packet() {
    let framed = encode_vless_udp_packet(b"partial").expect("frame");
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&framed[..3]);
    assert!(decoder.next_packet().unwrap().is_none());
    decoder.push(&framed[3..]);
    assert_eq!(decoder.next_packet().unwrap().unwrap(), b"partial");
}

#[test]
fn empty_encode_is_noop_write() {
    assert!(encode_vless_udp_packet(&[]).expect("empty").is_empty());
}
