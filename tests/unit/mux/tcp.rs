use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::env_lock::EnvVarGuard;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use bytes::Bytes;

use crate::config::xray::raw::OutboundObject;
use crate::dns::DnsEngine;
use crate::mux::encoder::{
    encode_mux_end, encode_mux_keep_data, encode_mux_new_tcp, encode_mux_new_udp,
};
use crate::mux::frame::{
    MuxCommand, MuxDestination, MuxFrame, MuxNetwork, MuxOption, MuxStatus,
    ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE,
};
use crate::mux::parser::read_mux_frame;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::session::handle_mux_cool_inbound;
use crate::mux::session::handle_mux_cool_inbound_with_env;
use crate::mux::tcp_substreams::{handle_mux_tcp_command, MuxTcpSubstreams};
use crate::mux::xudp::{XudpManager, XudpManagerConfig};
use crate::routing::{RouteSocketMeta, RuntimeRouter};
use crate::runtime::RuntimeOutboundManager;
use crate::vless::protocol::VlessDestination;
use crate::vless::user_manager::VlessAuthenticatedClient;
use uuid::Uuid;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

async fn assert_no_mux_frame_within<R>(reader: &mut R, duration: Duration)
where
    R: AsyncRead + Unpin,
{
    assert!(
        tokio::time::timeout(duration, read_mux_frame(reader))
            .await
            .is_err(),
        "unexpected mux frame received"
    );
}

#[test]
fn generic_udp_domain_opens_persistent_session() {
    block_on(async {
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_port = echo.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, peer)) = echo.recv_from(&mut buf).await else {
                    break;
                };
                echo.send_to(&buf[..len], peer).await.ok();
            }
        });

        let destination = VlessDestination::Domain("127.0.0.1".to_string(), echo_port);
        let open = encode_mux_new_udp(16, &destination, b"hello");
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        client_io
            .write_all(&open)
            .await
            .expect("write mux udp open");

        let handle = tokio::spawn(async move { handle_mux_cool_inbound(&mut server_io).await });
        assert!(
            read_mux_frame(&mut client_io)
                .await
                .expect("read generic udp response")
                .id()
                == 16
        );

        drop(client_io);
        handle.await.expect("join mux handler").unwrap();
    });
}

#[test]
fn generic_udp_relay_returns_mux_response_for_arbitrary_destination() {
    block_on(async {
        let _close_guard = EnvVarGuard::set(ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE, "0").await;
        let udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind generic udp");
        let udp_port = udp.local_addr().expect("udp local addr").port();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (read, peer) = udp.recv_from(&mut buf).await.expect("generic udp recv");
            assert_eq!(&buf[..read], b"hello");
            udp.send_to(b"world", peer).await.expect("generic udp send");
        });

        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
        let open = encode_mux_new_udp(18, &destination, b"hello");
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        client_io
            .write_all(&open)
            .await
            .expect("write generic udp open");

        let handle = tokio::spawn(async move { handle_mux_cool_inbound(&mut server_io).await });
        assert_eq!(
            read_mux_frame(&mut client_io)
                .await
                .expect("read generic udp response"),
            MuxFrame {
                mux_id: 18,
                status: MuxStatus::Keep,
                option: MuxOption { has_data: true },
                command: MuxCommand::Udp {
                    destination: MuxDestination {
                        network: MuxNetwork::Udp,
                        destination,
                    },
                    packet: Bytes::from_static(b"world"),
                    global_id: None,
                }
            }
        );
        assert_no_mux_frame_within(&mut client_io, Duration::from_millis(50)).await;

        drop(client_io);
        handle.await.expect("join mux handler").unwrap();
    });
}

struct TcpEchoTarget {
    port: u16,
    captured: Arc<Mutex<Vec<u8>>>,
}

async fn bind_tcp_echo() -> TcpEchoTarget {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tcp echo");
    let port = listener.local_addr().expect("addr").port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_task = Arc::clone(&captured);
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept tcp echo");
        let mut buf = [0u8; 8192];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    captured_task
                        .lock()
                        .expect("lock capture")
                        .extend_from_slice(&buf[..n]);
                    socket.write_all(&buf[..n]).await.expect("echo tcp");
                }
                Err(_) => break,
            }
        }
    });
    TcpEchoTarget { port, captured }
}

async fn read_mux_frame_timeout<R>(reader: &mut R, duration: Duration) -> std::io::Result<MuxFrame>
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(duration, read_mux_frame(reader))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for mux frame",
            )
        })?
}

fn freedom_route_env() -> MuxRouteEnv {
    let outbound = RuntimeOutboundManager::new();
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("direct".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("freedom outbound");
    let router = RuntimeRouter::new(
        None,
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router");
    MuxRouteEnv {
        router,
        inbound_tag: "vless-in".to_string(),
        auth: VlessAuthenticatedClient {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid"),
            email: Some("mux-tcp@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
            inbound_tag: "vless-in".to_string(),
        },
        socket_meta: RouteSocketMeta::default(),
        sniffing_enabled: false,
        vision_mux_udp_only: false,
        stats: None,
        xudp: XudpManager::new_for_test(XudpManagerConfig {
            expiry: Duration::from_secs(60),
            sweep_interval: Duration::from_secs(3600),
        }),
        test_dispatch_counter: None,
    }
}

#[test]
fn mux_tcp_new_initial_payload_reaches_target() {
    block_on(async {
        let echo = bind_tcp_echo().await;
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), echo.port);
        let open = encode_mux_new_tcp(1, &destination, b"HELLO-INIT");
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        let handle = tokio::spawn(async move { handle_mux_cool_inbound(&mut server_io).await });
        client_io.write_all(&open).await.expect("write tcp open");
        let response = read_mux_frame_timeout(&mut client_io, Duration::from_secs(2))
            .await
            .expect("read echo");
        match response.command {
            MuxCommand::Data { payload } => {
                assert_eq!(payload.as_ref(), b"HELLO-INIT");
            }
            other => panic!("expected keep data response, got {other:?}"),
        }
        assert_eq!(
            echo.captured.lock().expect("lock").as_slice(),
            b"HELLO-INIT"
        );
        client_io
            .write_all(&encode_mux_end(1))
            .await
            .expect("write end");
        drop(client_io);
        handle.await.expect("join").unwrap();
    });
}

#[test]
fn mux_tcp_multiple_keep_frames_reach_target_in_order() {
    block_on(async {
        let echo = bind_tcp_echo().await;
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), echo.port);
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        let handle = tokio::spawn(async move { handle_mux_cool_inbound(&mut server_io).await });
        client_io
            .write_all(&encode_mux_new_tcp(2, &destination, b"A"))
            .await
            .expect("open");
        client_io
            .write_all(&encode_mux_keep_data(2, b"BC").expect("keep1"))
            .await
            .expect("keep1");
        client_io
            .write_all(&encode_mux_keep_data(2, b"DEF").expect("keep2"))
            .await
            .expect("keep2");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(echo.captured.lock().expect("lock").as_slice(), b"ABCDEF");
        let mut combined = Vec::new();
        while let Ok(frame) =
            read_mux_frame_timeout(&mut client_io, Duration::from_millis(200)).await
        {
            if let MuxCommand::Data { payload } = frame.command {
                combined.extend_from_slice(payload.as_ref());
            }
        }
        assert_eq!(combined.as_slice(), b"ABCDEF");
        client_io
            .write_all(&encode_mux_end(2))
            .await
            .expect("write end");
        drop(client_io);
        handle.await.expect("join").unwrap();
    });
}

#[test]
fn mux_tcp_coalesced_frames_parsed_and_relayed() {
    block_on(async {
        let echo = bind_tcp_echo().await;
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), echo.port);
        let mut coalesced = encode_mux_new_tcp(3, &destination, b"ONE");
        coalesced.extend(encode_mux_keep_data(3, b"TWO").expect("keep"));
        coalesced.extend(encode_mux_end(3));
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        let handle = tokio::spawn(async move { handle_mux_cool_inbound(&mut server_io).await });
        client_io
            .write_all(&coalesced)
            .await
            .expect("write coalesced");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(echo.captured.lock().expect("lock").as_slice(), b"ONETWO");
        drop(client_io);
        handle.await.expect("join").unwrap();
    });
}

#[test]
fn mux_tcp_fragmented_writes_still_relay_exact_bytes() {
    block_on(async {
        let echo = bind_tcp_echo().await;
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), echo.port);
        let open = encode_mux_new_tcp(4, &destination, b"frag");
        let keep = encode_mux_keep_data(4, b"ments").expect("keep");
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        let handle = tokio::spawn(async move { handle_mux_cool_inbound(&mut server_io).await });
        for chunk in open.chunks(3) {
            client_io.write_all(chunk).await.expect("fragment open");
        }
        for chunk in keep.chunks(4) {
            client_io.write_all(chunk).await.expect("fragment keep");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(echo.captured.lock().expect("lock").as_slice(), b"fragments");
        client_io
            .write_all(&encode_mux_end(4))
            .await
            .expect("write end");
        drop(client_io);
        handle.await.expect("join").unwrap();
    });
}

#[test]
fn mux_tcp_parallel_substreams_relay_independently() {
    block_on(async {
        let echo_a = bind_tcp_echo().await;
        let echo_b = bind_tcp_echo().await;
        let destination_a = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), echo_a.port);
        let destination_b = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), echo_b.port);
        let (mut client_io, mut server_io) = tokio::io::duplex(16384);
        let handle = tokio::spawn(async move { handle_mux_cool_inbound(&mut server_io).await });
        client_io
            .write_all(&encode_mux_new_tcp(10, &destination_a, b"A1"))
            .await
            .expect("open a");
        client_io
            .write_all(&encode_mux_new_tcp(11, &destination_b, b"B1"))
            .await
            .expect("open b");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(echo_a.captured.lock().expect("lock").as_slice(), b"A1");
        assert_eq!(echo_b.captured.lock().expect("lock").as_slice(), b"B1");
        client_io
            .write_all(&encode_mux_keep_data(10, b"A2").expect("keep a"))
            .await
            .expect("keep a write");
        client_io
            .write_all(&encode_mux_keep_data(11, b"B2").expect("keep b"))
            .await
            .expect("keep b write");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(echo_a.captured.lock().expect("lock").as_slice(), b"A1A2");
        assert_eq!(echo_b.captured.lock().expect("lock").as_slice(), b"B1B2");
        client_io
            .write_all(&encode_mux_end(10))
            .await
            .expect("end a");
        client_io
            .write_all(&encode_mux_keep_data(11, b"B3").expect("keep b2"))
            .await
            .expect("keep b2 write");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(echo_b.captured.lock().expect("lock").as_slice(), b"B1B2B3");
        client_io
            .write_all(&encode_mux_end(11))
            .await
            .expect("end b");
        drop(client_io);
        handle.await.expect("join").unwrap();
    });
}

#[test]
fn mux_tcp_replacement_rejects_stale_downlink_generation() {
    block_on(async {
        let first = bind_tcp_echo().await;
        let second = bind_tcp_echo().await;
        let first_destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), first.port);
        let second_destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), second.port);
        let (downlink_tx, _downlink_rx) = MuxTcpSubstreams::downlink_channel();
        let mut active = MuxTcpSubstreams::new(downlink_tx);

        handle_mux_tcp_command(
            &mut active,
            MuxFrame {
                mux_id: 77,
                status: MuxStatus::New,
                option: MuxOption { has_data: false },
                command: MuxCommand::Tcp {
                    destination: MuxDestination {
                        network: MuxNetwork::Tcp,
                        destination: first_destination,
                    },
                    initial_payload: Bytes::new(),
                },
            },
            None,
        )
        .await
        .expect("open first child");
        assert!(active.is_current(77, 1));

        handle_mux_tcp_command(
            &mut active,
            MuxFrame {
                mux_id: 77,
                status: MuxStatus::New,
                option: MuxOption { has_data: false },
                command: MuxCommand::Tcp {
                    destination: MuxDestination {
                        network: MuxNetwork::Tcp,
                        destination: second_destination,
                    },
                    initial_payload: Bytes::new(),
                },
            },
            None,
        )
        .await
        .expect("replace child");

        assert!(!active.is_current(77, 1));
        assert!(!active.remove_if_current(77, 1));
        assert!(active.is_current(77, 2));
        active.remove(77);
    });
}

#[test]
fn flow_empty_mux_tcp_accepted_via_session_handler() {
    block_on(async {
        let echo = bind_tcp_echo().await;
        let route_env = freedom_route_env();
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), echo.port);
        let (mut client, mut server) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            handle_mux_cool_inbound_with_env(
                &mut server,
                DnsEngine::shared(),
                None,
                Some(route_env),
            )
            .await
        });
        client
            .write_all(&encode_mux_new_tcp(5, &destination, b"OK"))
            .await
            .expect("open");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(echo.captured.lock().expect("lock").as_slice(), b"OK");
        client
            .write_all(&encode_mux_end(5))
            .await
            .expect("write end");
        drop(client);
        server_task.await.expect("join").unwrap();
    });
}

#[test]
fn vision_mux_tcp_rejected_while_udp_path_unchanged() {
    block_on(async {
        let mut route_env = freedom_route_env();
        route_env.vision_mux_udp_only = true;
        let destination = VlessDestination::Domain("example.com".to_string(), 443);
        let (mut client, mut server) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            handle_mux_cool_inbound_with_env(
                &mut server,
                DnsEngine::shared(),
                None,
                Some(route_env),
            )
            .await
        });
        client
            .write_all(&encode_mux_new_tcp(6, &destination, b"GET"))
            .await
            .expect("write tcp");
        drop(client);
        let err = server_task.await.expect("join").unwrap_err();
        assert!(err.to_string().contains("vision mux accepts only udp"));
    });
}
