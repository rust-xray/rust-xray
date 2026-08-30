use super::*;
use std::net::IpAddr;

use crate::mux::encoder::{
    encode_mux_end, encode_mux_keep_data, encode_mux_new_tcp, encode_mux_new_udp,
    encode_mux_new_udp_xudp, encode_mux_new_udp_xudp_with_trailing, encode_mux_udp_packet,
};
use crate::mux::frame::{is_xudp_global_id, MUX_NETWORK_UDP, MUX_OPT_DATA, MUX_STATUS_NEW};

#[test]
fn mux_frame_parser_parses_basic_open_data_close_frames() {
    let destination = VlessDestination::Domain("example.com".to_string(), 443);
    let frame = encode_mux_new_tcp(1, &destination, b"GET / HTTP/1.1\r\n\r\n");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let parsed = parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
    assert_eq!(
        parsed,
        MuxFrame {
            mux_id: 1,
            status: MuxStatus::New,
            option: MuxOption { has_data: true },
            command: MuxCommand::Tcp {
                destination: MuxDestination {
                    network: MuxNetwork::Tcp,
                    destination,
                },
                initial_payload: b"GET / HTTP/1.1\r\n\r\n".to_vec()
            }
        }
    );

    let keep = encode_mux_keep_data(1, b"more").unwrap();
    let metadata_len = u16::from_be_bytes([keep[0], keep[1]]) as usize;
    assert_eq!(
        parse_mux_frame(&keep[2..2 + metadata_len], &keep[2 + metadata_len..]).unwrap(),
        MuxFrame {
            mux_id: 1,
            status: MuxStatus::Keep,
            option: MuxOption { has_data: true },
            command: MuxCommand::Data {
                payload: b"more".to_vec()
            }
        }
    );

    let end = encode_mux_end(1);
    let metadata_len = u16::from_be_bytes([end[0], end[1]]) as usize;
    assert_eq!(
        parse_mux_frame(&end[2..2 + metadata_len], &[]).unwrap(),
        MuxFrame {
            mux_id: 1,
            status: MuxStatus::End,
            option: MuxOption { has_data: false },
            command: MuxCommand::Close {
                payload: Vec::new()
            }
        }
    );
}

#[test]
fn malformed_mux_frame_rejected_safely() {
    assert!(parse_mux_frame(&[0, 1, MUX_STATUS_NEW], &[]).is_err());
    assert!(parse_mux_frame(&[0, 1, MUX_STATUS_NEW, MUX_OPT_DATA], &[0]).is_err());
    assert!(parse_mux_frame(&[0, 1, 0xff, 0], &[]).is_err());
}

#[test]
fn mux_frame_parser_accepts_udp_network_0x02() {
    let destination = VlessDestination::Domain("dns.google".to_string(), 53);
    let frame = encode_mux_new_udp(7, &destination, b"\x12\x34dns");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;

    assert_eq!(
        parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap(),
        MuxFrame {
            mux_id: 7,
            status: MuxStatus::New,
            option: MuxOption { has_data: true },
            command: MuxCommand::Udp {
                destination: MuxDestination {
                    network: MuxNetwork::Udp,
                    destination,
                },
                packet: b"\x12\x34dns".to_vec(),
                global_id: None,
            }
        }
    );
}

#[test]
fn mux_frame_parser_accepts_udp_destination_on_keep_frame() {
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    let frame = crate::mux::encoder::encode_mux_keep_udp(9, &destination, b"\x01\x00");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;

    assert_eq!(
        parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap(),
        MuxFrame {
            mux_id: 9,
            status: MuxStatus::Keep,
            option: MuxOption { has_data: true },
            command: MuxCommand::Udp {
                destination: MuxDestination {
                    network: MuxNetwork::Udp,
                    destination,
                },
                packet: b"\x01\x00".to_vec(),
                global_id: None,
            }
        }
    );
}

#[test]
fn encode_mux_udp_response_frame_for_same_mux_id() {
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    let frame = encode_mux_udp_packet(11, &destination, b"\x81\x80").unwrap();
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;

    assert_eq!(
        parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap(),
        MuxFrame {
            mux_id: 11,
            status: MuxStatus::Keep,
            option: MuxOption { has_data: true },
            command: MuxCommand::Udp {
                destination: MuxDestination {
                    network: MuxNetwork::Udp,
                    destination,
                },
                packet: b"\x81\x80".to_vec(),
                global_id: None,
            }
        }
    );
}

#[test]
fn mux_parser_reads_xudp_global_id_on_new_udp() {
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    let global_id = [1, 2, 3, 4, 5, 6, 7, 8];
    let frame = encode_mux_new_udp_xudp(3, &destination, &global_id, b"ping");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let parsed = parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
    assert!(matches!(
        parsed.command,
        MuxCommand::Udp {
            global_id: Some(id),
            ..
        } if id == global_id
    ));
    assert!(is_xudp_global_id(&global_id));
}

#[test]
fn mux_parser_zero_global_id_is_generic_udp() {
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53);
    let frame = encode_mux_new_udp_xudp(4, &destination, &[0; 8], b"ping");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let parsed = parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
    assert!(matches!(
        parsed.command,
        MuxCommand::Udp {
            global_id: None,
            ..
        }
    ));
}

#[test]
fn mux_parser_truncated_global_id_is_generic_udp() {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&5u16.to_be_bytes());
    metadata.push(MuxStatus::New.as_wire());
    metadata.push(MuxOption { has_data: true }.as_wire());
    metadata.push(MUX_NETWORK_UDP);
    metadata.extend_from_slice(&9999u16.to_be_bytes());
    metadata.push(0x01);
    metadata.extend_from_slice(&[1, 2, 3, 4]);
    metadata.extend_from_slice(&[9, 9, 9]);
    let mut frame = Vec::new();
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame.extend_from_slice(&(4u16).to_be_bytes());
    frame.extend_from_slice(b"data");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let parsed = parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
    assert!(matches!(
        parsed.command,
        MuxCommand::Udp {
            global_id: None,
            ..
        }
    ));
}

#[test]
fn mux_parser_tcp_frame_unaffected_by_xudp_metadata_rules() {
    let destination = VlessDestination::Domain("example.com".to_string(), 443);
    let frame = encode_mux_new_tcp(6, &destination, b"hello");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let parsed = parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
    assert!(matches!(parsed.command, MuxCommand::Tcp { .. }));
}

#[test]
fn mux_parser_reads_global_id_when_more_than_eight_trailing_metadata_bytes() {
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    let global_id = [1, 2, 3, 4, 5, 6, 7, 8];
    let frame =
        encode_mux_new_udp_xudp_with_trailing(10, &destination, &global_id, &[0xAA, 0xBB], b"ping");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let parsed = parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
    assert!(matches!(
        parsed.command,
        MuxCommand::Udp {
            global_id: Some(id),
            ..
        } if id == global_id
    ));
}

#[test]
fn mux_parser_exactly_eight_trailing_bytes_parses_global_id() {
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53);
    let global_id = [9, 8, 7, 6, 5, 4, 3, 2];
    let frame = encode_mux_new_udp_xudp(11, &destination, &global_id, b"x");
    let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    let parsed = parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
    assert!(matches!(
        parsed.command,
        MuxCommand::Udp {
            global_id: Some(id),
            ..
        } if id == global_id
    ));
}
