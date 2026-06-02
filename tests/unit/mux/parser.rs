use super::*;
use std::net::IpAddr;

use crate::mux::encoder::{
    encode_mux_end, encode_mux_keep_data, encode_mux_new_tcp, encode_mux_new_udp,
    encode_mux_udp_packet,
};
use crate::mux::frame::{MUX_OPT_DATA, MUX_STATUS_NEW};

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
                packet: b"\x12\x34dns".to_vec()
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
                packet: b"\x01\x00".to_vec()
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
                packet: b"\x81\x80".to_vec()
            }
        }
    );
}
