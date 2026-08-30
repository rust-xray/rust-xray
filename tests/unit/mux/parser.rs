use super::*;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, ReadBuf};

use crate::mux::encoder::{
    encode_mux_end, encode_mux_keep_data, encode_mux_new_tcp, encode_mux_new_udp,
    encode_mux_new_udp_xudp, encode_mux_new_udp_xudp_with_trailing, encode_mux_udp_packet,
};
use crate::mux::frame::{is_xudp_global_id, MUX_NETWORK_UDP, MUX_OPT_DATA, MUX_STATUS_NEW};
use crate::mux::payload::UdpPacket;
use crate::mux::routed_udp::MUX_UDP_ASSOCIATION_QUEUE_CAPACITY;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

struct ChunkedReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos >= self.data.len() {
            return Poll::Ready(Ok(()));
        }
        let remaining = buf.remaining();
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }
        let take = remaining.min(self.chunk).min(self.data.len() - self.pos);
        let end = self.pos + take;
        buf.put_slice(&self.data[self.pos..end]);
        self.pos = end;
        Poll::Ready(Ok(()))
    }
}

fn destinationless_keep_frame(payload: &[u8]) -> Vec<u8> {
    encode_mux_keep_data(0, payload).expect("destination-less keep")
}

fn payload_from_data_command(frame: MuxFrame) -> Bytes {
    match frame.command {
        MuxCommand::Data { payload } => payload,
        other => panic!("expected Data command, got {other:?}"),
    }
}

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
                initial_payload: Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n")
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
                payload: Bytes::from_static(b"more")
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
                payload: Bytes::new()
            }
        }
    );
}

#[test]
fn mux_frame_parser_preserves_live_destinationless_keep() {
    for payload_len in [8, 28, 60] {
        let metadata = [0x00, 0x00, 0x02, 0x01];
        let payload = vec![payload_len as u8; payload_len];
        let mut extra = Vec::with_capacity(payload_len + 2);
        extra.extend_from_slice(&(payload_len as u16).to_be_bytes());
        extra.extend_from_slice(&payload);

        assert_eq!(
            parse_mux_frame(&metadata, &extra).unwrap(),
            MuxFrame {
                mux_id: 0,
                status: MuxStatus::Keep,
                option: MuxOption { has_data: true },
                command: MuxCommand::Data {
                    payload: Bytes::from(payload.clone()),
                },
            }
        );
    }
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
                packet: Bytes::from_static(b"\x12\x34dns"),
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
                packet: Bytes::from_static(b"\x01\x00"),
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
                packet: Bytes::from_static(b"\x81\x80"),
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

#[test]
fn parse_mux_payload_bytes_on_live_sized_buffer_matches_payload_only() {
    for payload_len in [47, 102, 107, 8192] {
        let mut extra = BytesMut::with_capacity(payload_len + 2);
        extra.extend_from_slice(&(payload_len as u16).to_be_bytes());
        extra.extend_from_slice(&vec![0xAB; payload_len]);
        let frozen = extra.freeze();
        assert_eq!(frozen.len(), payload_len + 2);
        let payload = parse_mux_payload_bytes(&frozen).expect("slice payload");
        assert_eq!(payload.len(), payload_len);
        assert_eq!(payload.as_ref(), &vec![0xAB; payload_len]);
    }
}

#[test]
fn parse_mux_payload_slice_retains_oversized_parent_only_when_misused() {
    let payload_len = 8;
    let mut oversized = BytesMut::with_capacity(8192);
    oversized.resize(8192, 0);
    oversized[0..2].copy_from_slice(&(payload_len as u16).to_be_bytes());
    oversized[2..2 + payload_len].copy_from_slice(b"12345678");
    let frozen = oversized.freeze();
    assert_eq!(frozen.len(), 8192);
    let payload = parse_mux_payload_bytes(&frozen).expect("slice from oversized parent");
    assert_eq!(payload.len(), payload_len);
    assert_eq!(payload.as_ref(), b"12345678");
    // Static inference: live read_mux_frame allocates payload_len + 2, not 8192.
}

#[test]
fn parse_mux_payload_bytes_survives_after_parent_extra_dropped() {
    let metadata = [0x00, 0x00, 0x02, 0x01];
    let payload = {
        let mut extra = BytesMut::with_capacity(62);
        extra.extend_from_slice(&60u16.to_be_bytes());
        extra.extend_from_slice(&vec![0xCD; 60]);
        let frozen = extra.freeze();
        let frame = parse_mux_frame_from_bytes(&metadata, &frozen).expect("parse keep");
        payload_from_data_command(frame)
    };
    assert_eq!(payload.len(), 60);
    assert_eq!(payload[0], 0xCD);
    assert_eq!(payload[59], 0xCD);
}

#[test]
fn read_mux_frame_one_frame_in_one_read() {
    block_on(async {
        let frame_bytes = destinationless_keep_frame(b"tiny");
        let mut reader = ChunkedReader {
            data: frame_bytes,
            pos: 0,
            chunk: 4096,
        };
        let parsed = read_mux_frame(&mut reader)
            .await
            .expect("single read frame");
        assert_eq!(payload_from_data_command(parsed).as_ref(), b"tiny");
        assert!(read_mux_frame(&mut reader).await.is_err());
    });
}

#[test]
fn read_mux_frame_two_frames_coalesced_in_one_read() {
    block_on(async {
        let mut data = destinationless_keep_frame(b"first");
        data.extend(destinationless_keep_frame(b"second"));
        let mut reader = ChunkedReader {
            data,
            pos: 0,
            chunk: 8192,
        };
        assert_eq!(
            payload_from_data_command(read_mux_frame(&mut reader).await.unwrap()).as_ref(),
            b"first"
        );
        assert_eq!(
            payload_from_data_command(read_mux_frame(&mut reader).await.unwrap()).as_ref(),
            b"second"
        );
    });
}

#[test]
fn read_mux_frame_fragmented_across_reads() {
    block_on(async {
        let frame_bytes = destinationless_keep_frame(b"fragment-me");
        let mut reader = ChunkedReader {
            data: frame_bytes,
            pos: 0,
            chunk: 3,
        };
        assert_eq!(
            payload_from_data_command(read_mux_frame(&mut reader).await.unwrap()).as_ref(),
            b"fragment-me"
        );
    });
}

#[test]
fn read_mux_frame_first_payload_valid_while_parsing_second() {
    block_on(async {
        let mut data = destinationless_keep_frame(&vec![1u8; 60]);
        data.extend(destinationless_keep_frame(b"tail"));
        let mut reader = ChunkedReader {
            data,
            pos: 0,
            chunk: 5,
        };
        let first = payload_from_data_command(read_mux_frame(&mut reader).await.unwrap());
        assert_eq!(first.len(), 60);
        assert_eq!(first[0], 1);
        assert_eq!(first[59], 1);
        let second = payload_from_data_command(read_mux_frame(&mut reader).await.unwrap());
        assert_eq!(second.as_ref(), b"tail");
        assert_eq!(first.len(), 60);
        assert_eq!(first[0], 1);
    });
}

#[test]
fn read_mux_frame_large_frame_followed_by_tiny_frame() {
    block_on(async {
        let mut data = destinationless_keep_frame(&vec![0xEE; 4096]);
        data.extend(destinationless_keep_frame(b"x"));
        let mut reader = ChunkedReader {
            data,
            pos: 0,
            chunk: 17,
        };
        let large = payload_from_data_command(read_mux_frame(&mut reader).await.unwrap());
        assert_eq!(large.len(), 4096);
        assert_eq!(large[0], 0xEE);
        let tiny = payload_from_data_command(read_mux_frame(&mut reader).await.unwrap());
        assert_eq!(tiny.as_ref(), b"x");
        assert_eq!(large.len(), 4096);
    });
}

#[test]
fn read_mux_frame_destinationless_keep_metadata_and_payload_exact() {
    block_on(async {
        for payload_len in [8, 28, 60] {
            let payload = vec![payload_len as u8; payload_len];
            let frame_bytes = destinationless_keep_frame(&payload);
            assert_eq!(u16::from_be_bytes([frame_bytes[0], frame_bytes[1]]), 4);
            assert_eq!(&frame_bytes[2..6], &[0x00, 0x00, 0x02, 0x01]);
            let mut reader = ChunkedReader {
                data: frame_bytes,
                pos: 0,
                chunk: 7,
            };
            let parsed = payload_from_data_command(read_mux_frame(&mut reader).await.unwrap());
            assert_eq!(parsed.as_ref(), payload.as_slice());
        }
    });
}

#[test]
fn queued_udp_packets_from_live_parse_path_retain_logical_payload_size_only() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(MUX_UDP_ASSOCIATION_QUEUE_CAPACITY);
    let mut expected_total = 0usize;
    for i in 0..MUX_UDP_ASSOCIATION_QUEUE_CAPACITY {
        let payload_len = 47 + (i % 20);
        expected_total += payload_len;
        let mut extra = BytesMut::with_capacity(payload_len + 2);
        extra.extend_from_slice(&(payload_len as u16).to_be_bytes());
        extra.extend_from_slice(&vec![i as u8; payload_len]);
        let frozen = extra.freeze();
        let metadata = [0x00, 0x00, 0x02, 0x01];
        let frame = parse_mux_frame_from_bytes(&metadata, &frozen).expect("keep frame");
        let payload = payload_from_data_command(frame);
        assert_eq!(payload.len(), payload_len);
        tx.try_send(UdpPacket {
            destination: None,
            payload,
        })
        .expect("queue full");
    }
    let mut actual_total = 0usize;
    while let Ok(packet) = rx.try_recv() {
        actual_total += packet.payload.len();
        assert!(packet.payload.len() <= 8192);
    }
    assert_eq!(actual_total, expected_total);
}
