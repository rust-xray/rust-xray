
use super::*;
use std::net::{IpAddr, Ipv4Addr};

use crate::mux::parser::parse_mux_frame;

#[test]
fn encode_mux_udp_response_frame_matches_xray_cool_golden_bytes() {
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    let frame = encode_mux_udp_packet(0x1234, &destination, b"\x81\x80").unwrap();

    assert_eq!(
        frame,
        vec![
            0x00, 0x0c, // metadata length
            0x12, 0x34, // mux id
            0x02, // status keep
            0x01, // option data
            0x02, // network udp
            0x00, 0x35, // port 53
            0x01, // ipv4 address
            0x01, 0x01, 0x01, 0x01, // 1.1.1.1
            0x00, 0x02, // data length
            0x81, 0x80, // DNS response payload
        ]
    );

    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let parsed = parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
    assert_eq!(parsed.mux_id, 0x1234);
}
