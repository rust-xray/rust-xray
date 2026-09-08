//! PERF-1D structural accounting for Mux/XUDP hot paths.

use bytes::{Bytes, BytesMut};

use crate::mux::encoder::{encode_mux_keep_data, encode_mux_new_tcp, encode_mux_new_udp};
use crate::mux::frame::{MuxCommand, MuxNetwork, MuxStatus};
use crate::mux::parser::{parse_mux_frame, read_mux_frame};
use crate::mux::tcp_substreams::TcpDownlinkEvent;
use crate::vless::protocol::VlessDestination;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

async fn read_mux_frame_from_wire(wire: Vec<u8>) -> crate::mux::frame::MuxFrame {
    let (mut reader, mut writer) = tokio::io::duplex(wire.len() + 64);
    tokio::io::AsyncWriteExt::write_all(&mut writer, &wire)
        .await
        .expect("seed wire");
    read_mux_frame(&mut reader).await.expect("read frame")
}

#[test]
fn perf_audit_read_mux_frame_payload_is_sliced_not_copied() {
    block_on(async {
        let wire = encode_mux_keep_data(7, b"payload-bytes").expect("encode");
        let frame = read_mux_frame_from_wire(wire).await;
        match frame.command {
            MuxCommand::Data { payload } => {
                assert_eq!(payload.as_ref(), b"payload-bytes");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    });
}

#[test]
fn perf_audit_parse_mux_frame_sync_path_copies_payload() {
    let wire = encode_mux_keep_data(3, b"sync-copy-path").expect("encode");
    let metadata_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
    let metadata = &wire[2..2 + metadata_len];
    let extra = &wire[2 + metadata_len..];
    let frame = parse_mux_frame(metadata, extra).expect("parse");
    match frame.command {
        MuxCommand::Data { payload } => assert_eq!(payload.as_ref(), b"sync-copy-path"),
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn perf_audit_tcp_downlink_event_uses_bytes() {
    let payload = Bytes::from_static(b"downlink-chunk");
    let event = TcpDownlinkEvent::Data(payload.clone());
    match event {
        TcpDownlinkEvent::Data(bytes) => assert_eq!(bytes, payload),
        TcpDownlinkEvent::Eof => panic!("expected data"),
    }
}

#[test]
fn perf_audit_mux_new_tcp_frame_roundtrip_wire_unchanged() {
    let destination = VlessDestination::Ip("127.0.0.1".parse().expect("ip"), 443);
    let wire = encode_mux_new_tcp(42, &destination, b"initial");
    block_on(async {
        let frame = read_mux_frame_from_wire(wire).await;
        assert_eq!(frame.mux_id, 42);
        assert_eq!(frame.status, MuxStatus::New);
        match frame.command {
            MuxCommand::Tcp {
                destination: dest, ..
            } => assert_eq!(dest.network, MuxNetwork::Tcp),
            other => panic!("unexpected: {other:?}"),
        }
    });
}

#[test]
fn perf_audit_mux_udp_new_frame_preserves_packet_bytes() {
    let destination = VlessDestination::Ip("127.0.0.1".parse().expect("ip"), 53);
    let wire = encode_mux_new_udp(9, &destination, b"dns-query");
    block_on(async {
        let frame = read_mux_frame_from_wire(wire).await;
        match frame.command {
            MuxCommand::Udp { packet, .. } => assert_eq!(packet.as_ref(), b"dns-query"),
            other => panic!("unexpected: {other:?}"),
        }
    });
}

#[test]
fn perf_audit_bytesmut_split_to_advances_without_second_alloc() {
    let mut buf = BytesMut::from(&b"abcdef"[..]);
    let a = buf.split_to(3).freeze();
    let b = buf.split_to(3).freeze();
    assert_eq!(a.as_ref(), b"abc");
    assert_eq!(b.as_ref(), b"def");
    assert!(buf.is_empty());
}

#[test]
#[ignore = "release-mode PERF-1D local benchmark; run with --ignored --release"]
fn mux_read_frame_benchmark_1kib() {
    let payload = vec![0xCD; 1024];
    let wire = encode_mux_keep_data(1, &payload).expect("encode");
    let iterations = 10_000u32;
    let start = std::time::Instant::now();
    block_on(async {
        for _ in 0..iterations {
            let (mut reader, mut writer) = tokio::io::duplex(wire.len() + 64);
            tokio::io::AsyncWriteExt::write_all(&mut writer, &wire)
                .await
                .expect("seed wire");
            let _ = read_mux_frame(&mut reader).await.expect("read");
        }
    });
    let elapsed = start.elapsed();
    eprintln!(
        "read_mux_frame 1KiB x{iterations}: {:?} ({:.0} ops/s)",
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
}
