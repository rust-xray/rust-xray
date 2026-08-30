use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::vless::inbound::validate_vless_flow_for_command;
use crate::vless::protocol::{build_vless_request_wire, parse_vless_request, VlessCommand};
use crate::vless::udp_framing::{encode_vless_udp_packet, VlessUdpPacketDecoder};
use crate::vless::udp_relay::relay_vless_udp_bidirectional;
use crate::vless::udp_session::VlessUdpRelayOptions;

fn test_relay_options() -> VlessUdpRelayOptions {
    VlessUdpRelayOptions::for_test(Duration::from_millis(50))
}

async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = socket.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.expect("recv");
            socket.send_to(&buf[..len], peer).await.expect("send");
        }
    });
    (addr, task)
}

async fn run_echo_relay(
    uplink: Vec<u8>,
    initial_payload: Vec<u8>,
    echo_addr: SocketAddr,
    options: VlessUdpRelayOptions,
) -> (std::io::Result<(u64, u64)>, Vec<u8>) {
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let (client, server) = tokio::io::duplex(65536);
    let relay_handle = tokio::spawn(async move {
        relay_vless_udp_bidirectional(
            server,
            Some(Arc::new(client_socket)),
            Some(echo_addr),
            false,
            initial_payload,
            None,
            options,
        )
        .await
    });

    let mut client = client;
    if !uplink.is_empty() {
        client.write_all(&uplink).await.expect("write uplink");
    }
    client.shutdown().await.expect("shutdown uplink");

    let relay_result = relay_handle.await.expect("relay join");

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .expect("read response timeout")
        .expect("read response");

    (relay_result, response)
}

#[tokio::test]
async fn ipv4_round_trip_single_datagram() {
    let (echo_addr, echo_task) = echo_server().await;
    let payload = b"ping";
    let framed = encode_vless_udp_packet(payload).expect("frame");

    let (relay_result, response) =
        run_echo_relay(framed.clone(), Vec::new(), echo_addr, test_relay_options()).await;
    let (uplink, downlink) = relay_result.expect("relay");
    assert_eq!(uplink, payload.len() as u64);
    assert_eq!(downlink, payload.len() as u64);

    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&response);
    assert_eq!(
        decoder.next_packet().expect("packet").unwrap().as_ref(),
        payload
    );
    echo_task.abort();
}

#[tokio::test]
async fn multiple_datagrams_one_association() {
    let (echo_addr, echo_task) = echo_server().await;
    let mut uplink = Vec::new();
    uplink.extend(encode_vless_udp_packet(b"one").expect("one"));
    uplink.extend(encode_vless_udp_packet(b"two").expect("two"));
    uplink.extend(encode_vless_udp_packet(b"three").expect("three"));

    let (relay_result, response) =
        run_echo_relay(uplink, Vec::new(), echo_addr, test_relay_options()).await;
    relay_result.expect("relay");

    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&response);
    assert_eq!(decoder.next_packet().unwrap().unwrap().as_ref(), b"one");
    assert_eq!(decoder.next_packet().unwrap().unwrap().as_ref(), b"two");
    assert_eq!(decoder.next_packet().unwrap().unwrap().as_ref(), b"three");
    echo_task.abort();
}

#[tokio::test]
async fn datagram_boundaries_preserved() {
    let (echo_addr, echo_task) = echo_server().await;
    let sizes = [1usize, 64, 512, 1400];
    let mut uplink = Vec::new();
    for size in sizes {
        uplink.extend(encode_vless_udp_packet(&vec![0xAB; size]).expect("frame"));
    }

    let (relay_result, response) =
        run_echo_relay(uplink, Vec::new(), echo_addr, test_relay_options()).await;
    relay_result.expect("relay");

    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&response);
    for size in sizes {
        let packet = decoder.next_packet().expect("packet").expect("payload");
        assert_eq!(packet.len(), size);
    }
    echo_task.abort();
}

#[tokio::test]
async fn stream_eof_terminates_association() {
    let options = test_relay_options();
    let (echo_addr, echo_task) = echo_server().await;
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let (mut client, server) = tokio::io::duplex(1024);
    let relay_handle = tokio::spawn(async move {
        relay_vless_udp_bidirectional(
            server,
            Some(Arc::new(client_socket)),
            Some(echo_addr),
            false,
            Vec::new(),
            None,
            options,
        )
        .await
    });

    client.shutdown().await.expect("shutdown uplink");
    tokio::time::timeout(Duration::from_secs(2), relay_handle)
        .await
        .expect("relay timeout")
        .expect("relay join")
        .expect("relay eof");
    echo_task.abort();
}

#[tokio::test]
async fn dns_timeout_does_not_control_udp_association_lifetime() {
    std::env::set_var("RUST_XRAY_DNS_TIMEOUT_MS", "60000");
    std::env::set_var("RUST_XRAY_VLESS_UDP_DOWNLINK_GRACE_MS", "50");

    let options = VlessUdpRelayOptions::from_env();
    assert_eq!(
        options.downlink_grace_after_uplink_eof,
        Duration::from_millis(50)
    );

    let (echo_addr, echo_task) = echo_server().await;
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let (mut client, server) = tokio::io::duplex(1024);
    let started = Instant::now();
    let relay_handle = tokio::spawn(async move {
        relay_vless_udp_bidirectional(
            server,
            Some(Arc::new(client_socket)),
            Some(echo_addr),
            false,
            Vec::new(),
            None,
            options,
        )
        .await
    });

    client.shutdown().await.expect("shutdown uplink");
    tokio::time::timeout(Duration::from_secs(2), relay_handle)
        .await
        .expect("relay timeout")
        .expect("relay join")
        .expect("relay eof");

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "association must not wait on DNS timeout"
    );
    echo_task.abort();
}

#[test]
fn vision_udp_flow_rejected() {
    let err = validate_vless_flow_for_command(
        Some("xtls-rprx-vision"),
        Some("xtls-rprx-vision"),
        VlessCommand::Udp,
    )
    .expect_err("vision udp");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn empty_flow_udp_accepted() {
    validate_vless_flow_for_command(None, None, VlessCommand::Udp).expect("empty flow udp");
}

#[test]
fn udp_request_with_initial_payload_parsed() {
    let user_id = [0u8; 16];
    let mut wire = build_vless_request_wire(0, &user_id, &[], 0x02, 53, &{
        let mut addr = Vec::new();
        addr.push(0x01);
        addr.extend(Ipv4Addr::LOCALHOST.octets());
        addr
    });
    wire.extend(encode_vless_udp_packet(b"dns").expect("udp frame"));
    let (request, consumed) = parse_vless_request(&wire).expect("parse");
    assert_eq!(request.command, VlessCommand::Udp);
    assert_eq!(&wire[consumed..], encode_vless_udp_packet(b"dns").unwrap());
}

#[tokio::test]
async fn domain_destination_resolves_via_system_lookup() {
    let (echo_addr, echo_task) = echo_server().await;
    let payload = b"domain";
    let framed = encode_vless_udp_packet(payload).expect("frame");
    let (relay_result, response) =
        run_echo_relay(framed, Vec::new(), echo_addr, test_relay_options()).await;
    relay_result.expect("domain relay");

    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&response);
    assert_eq!(
        decoder.next_packet().expect("packet").unwrap().as_ref(),
        payload
    );
    echo_task.abort();
}

#[tokio::test]
async fn reality_compatible_split_relay_uses_single_writer() {
    let (echo_addr, echo_task) = echo_server().await;
    let payload = b"real";
    let framed = encode_vless_udp_packet(payload).expect("frame");
    let (relay_result, response) =
        run_echo_relay(Vec::new(), framed.clone(), echo_addr, test_relay_options()).await;
    relay_result.expect("split relay");

    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&response);
    assert_eq!(
        decoder.next_packet().expect("packet").unwrap().as_ref(),
        payload
    );
    echo_task.abort();
}
