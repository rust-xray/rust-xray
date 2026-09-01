use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{duplex, AsyncWriteExt};
use tokio::net::UdpSocket;
use uuid::Uuid;

use crate::config::xray::raw::OutboundObject;
use crate::dns::DnsEngine;
use crate::mux::encoder::{
    encode_mux_end, encode_mux_keep_data, encode_mux_keep_udp, encode_mux_new_tcp,
    encode_mux_new_udp,
};
use crate::mux::parser::read_mux_frame;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::session::{handle_mux_cool_inbound, handle_mux_cool_inbound_with_env};
use crate::mux::xudp::{XudpManager, XudpManagerConfig};
use crate::routing::{route_context_from_vless, NetworkKind, RouteSocketMeta, RuntimeRouter};
use crate::runtime::RuntimeOutboundManager;
use crate::stats::{StatsPolicy, StatsRegistry, StatsSession};
use crate::vless::protocol::VlessDestination;
use crate::vless::user_manager::VlessAuthenticatedClient;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

fn test_auth() -> VlessAuthenticatedClient {
    VlessAuthenticatedClient {
        id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid"),
        email: Some("packet@example.test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        inbound_tag: "vless-in".to_string(),
    }
}

fn freedom_router() -> Arc<RuntimeRouter> {
    let outbound = RuntimeOutboundManager::new();
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("direct".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("freedom outbound");
    RuntimeRouter::new(
        None,
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router")
}

fn blackhole_router() -> Arc<RuntimeRouter> {
    let outbound = RuntimeOutboundManager::new();
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("block".to_string()),
            protocol: Some("blackhole".to_string()),
            extra: Default::default(),
        })
        .expect("blackhole outbound");
    RuntimeRouter::new(
        None,
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router")
}

fn test_route_env(
    router: Arc<RuntimeRouter>,
    dispatch_counter: Option<Arc<AtomicUsize>>,
) -> MuxRouteEnv {
    MuxRouteEnv {
        router,
        inbound_tag: "vless-in".to_string(),
        auth: test_auth(),
        socket_meta: RouteSocketMeta::default(),
        sniffing_enabled: false,
        vision_mux_udp_only: false,
        stats: None,
        xudp: XudpManager::new_for_test(XudpManagerConfig {
            expiry: Duration::from_secs(60),
            sweep_interval: Duration::from_secs(3600),
        }),
        test_dispatch_counter: dispatch_counter,
    }
}

async fn bind_echo_udp() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..len], peer).await;
        }
    });
    addr
}

async fn bind_push_udp(responses: Vec<&'static [u8]>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind push");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let mut idx = 0usize;
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = len;
            if idx < responses.len() {
                let _ = socket.send_to(responses[idx], peer).await;
                idx += 1;
            }
        }
    });
    addr
}

#[tokio::test]
async fn generic_mux_udp_new_creates_one_routed_association() {
    let dispatch = Arc::new(AtomicUsize::new(0));
    let route_env = test_route_env(freedom_router(), Some(Arc::clone(&dispatch)));
    let echo = bind_echo_udp().await;
    let destination = VlessDestination::Ip(echo.ip(), echo.port());
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(1, &destination, b"one"))
        .await
        .expect("write new");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client))
            .await
            .expect("timeout")
            .is_ok()
    );
    assert_eq!(dispatch.load(Ordering::SeqCst), 1);
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn generic_mux_udp_destinationless_keep_reuses_association_without_second_dispatch() {
    let dispatch = Arc::new(AtomicUsize::new(0));
    let route_env = test_route_env(freedom_router(), Some(Arc::clone(&dispatch)));
    let echo = bind_echo_udp().await;
    let destination = VlessDestination::Ip(echo.ip(), echo.port());
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(2, &destination, b"a"))
        .await
        .expect("new");
    let _ = read_mux_frame(&mut client).await.expect("first response");
    let keep = encode_mux_keep_data(2, b"b").expect("destination-less keep");
    assert_eq!(&keep[2..6], &[0x00, 0x02, 0x02, 0x01]);
    client.write_all(&keep).await.expect("keep");
    let _ = read_mux_frame(&mut client).await.expect("second response");
    assert_eq!(dispatch.load(Ordering::SeqCst), 1);
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn generic_mux_udp_multiple_async_downstream_responses() {
    let route_env = test_route_env(freedom_router(), None);
    let push = bind_push_udp(vec![b"r1", b"r2"]).await;
    let destination = VlessDestination::Ip(push.ip(), push.port());
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(3, &destination, b"trigger"))
        .await
        .expect("new");
    let first = read_mux_frame(&mut client).await.expect("first");
    client
        .write_all(&encode_mux_keep_udp(3, &destination, b"trigger2"))
        .await
        .expect("keep");
    let second = read_mux_frame(&mut client).await.expect("second");
    assert_eq!(first.id(), 3);
    assert_eq!(second.id(), 3);
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn generic_mux_udp_stats_count_payload_once_in_each_direction() {
    let registry = Arc::new(StatsRegistry::new());
    let stats = StatsSession::new(
        Arc::clone(&registry),
        StatsPolicy {
            user_uplink: false,
            user_downlink: false,
            user_online: false,
            inbound_uplink: true,
            inbound_downlink: true,
            outbound_uplink: false,
            outbound_downlink: false,
        },
        None,
        "vless-in".to_string(),
        "direct".to_string(),
        None,
        None,
        None,
    );
    let mut route_env = test_route_env(freedom_router(), None);
    route_env.stats = Some(stats);
    let echo = bind_echo_udp().await;
    let destination = VlessDestination::Ip(echo.ip(), echo.port());
    let payload = b"payload-only";
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });

    client
        .write_all(&encode_mux_new_udp(32, &destination, payload))
        .await
        .expect("new");
    read_mux_frame(&mut client).await.expect("response");

    assert_eq!(
        registry
            .get("inbound>>>vless-in>>>traffic>>>uplink", false)
            .expect("uplink stat"),
        payload.len() as i64
    );
    assert_eq!(
        registry
            .get("inbound>>>vless-in>>>traffic>>>downlink", false)
            .expect("downlink stat"),
        payload.len() as i64
    );

    drop(client);
    server_task.await.expect("join").expect("mux relay");
}

#[tokio::test]
async fn generic_mux_udp_domain_destination_works() {
    let route_env = test_route_env(freedom_router(), None);
    let echo = bind_echo_udp().await;
    let destination = VlessDestination::Domain("127.0.0.1".to_string(), echo.port());
    let route_ctx = route_context_from_vless(
        &route_env.inbound_tag,
        &route_env.auth,
        &destination,
        b"x",
        &route_env.socket_meta,
        false,
        NetworkKind::Udp,
    );
    assert_eq!(route_ctx.network, NetworkKind::Udp);
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(4, &destination, b"domain"))
        .await
        .expect("new");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client))
            .await
            .expect("timeout")
            .is_ok()
    );
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn generic_mux_udp_keep_with_per_packet_destination() {
    let route_env = test_route_env(freedom_router(), None);
    let echo_a = bind_echo_udp().await;
    let echo_b = bind_echo_udp().await;
    let dest_a = VlessDestination::Ip(echo_a.ip(), echo_a.port());
    let dest_b = VlessDestination::Ip(echo_b.ip(), echo_b.port());
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(5, &dest_a, b"aa"))
        .await
        .expect("new");
    let _ = read_mux_frame(&mut client).await.expect("resp a");
    client
        .write_all(&encode_mux_keep_udp(5, &dest_b, b"bb"))
        .await
        .expect("keep b");
    let _ = read_mux_frame(&mut client).await.expect("resp b");
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn generic_mux_udp_end_stops_responses() {
    let route_env = test_route_env(freedom_router(), None);
    let push = bind_push_udp(vec![b"r1"]).await;
    let destination = VlessDestination::Ip(push.ip(), push.port());
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(6, &destination, b"x"))
        .await
        .expect("new");
    let _ = read_mux_frame(&mut client).await.expect("response");
    client.write_all(&encode_mux_end(6)).await.expect("end");
    client
        .write_all(&encode_mux_keep_udp(6, &destination, b"late"))
        .await
        .expect("keep after end");
    let close = read_mux_frame(&mut client)
        .await
        .expect("orphan keep close");
    assert!(matches!(
        close.command,
        crate::mux::frame::MuxCommand::Close { .. }
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), read_mux_frame(&mut client))
            .await
            .is_err(),
        "closed session must not emit mux UDP responses"
    );
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn generic_mux_udp_duplicate_new_replaces_session_safely() {
    let dispatch = Arc::new(AtomicUsize::new(0));
    let route_env = test_route_env(freedom_router(), Some(Arc::clone(&dispatch)));
    let echo = bind_echo_udp().await;
    let destination = VlessDestination::Ip(echo.ip(), echo.port());
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(7, &destination, b"first"))
        .await
        .expect("new1");
    let _ = read_mux_frame(&mut client).await.expect("resp1");
    client
        .write_all(&encode_mux_new_udp(7, &destination, b"second"))
        .await
        .expect("new2");
    let _ = read_mux_frame(&mut client).await.expect("resp2");
    assert_eq!(dispatch.load(Ordering::SeqCst), 2);
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn generic_mux_udp_blackhole_does_not_hang() {
    let route_env = test_route_env(blackhole_router(), None);
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 9999);
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(8, &destination, b"drop"))
        .await
        .expect("new");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), read_mux_frame(&mut client))
            .await
            .is_err()
    );
    drop(client);
    let _ = server_task.await;
}

#[tokio::test]
async fn vision_mux_accepts_generic_udp() {
    let route_env = test_route_env(freedom_router(), None);
    let mut route_env = route_env;
    route_env.vision_mux_udp_only = true;
    let echo = bind_echo_udp().await;
    let destination = VlessDestination::Ip(echo.ip(), echo.port());
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(9, &destination, b"vision"))
        .await
        .expect("new");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client))
            .await
            .expect("timeout")
            .is_ok()
    );
    drop(client);
    assert!(server_task.await.expect("join").is_ok());
}

#[test]
fn vision_mux_rejects_tcp_with_generic_udp_unchanged() {
    block_on(async {
        let route_env = test_route_env(freedom_router(), None);
        let mut route_env = route_env;
        route_env.vision_mux_udp_only = true;
        let destination = VlessDestination::Domain("example.com".to_string(), 443);
        let frame = encode_mux_new_tcp(10, &destination, b"GET");
        let (mut client, mut server) = duplex(8192);
        let server = tokio::spawn(async move {
            handle_mux_cool_inbound_with_env(
                &mut server,
                DnsEngine::shared(),
                None,
                Some(route_env),
            )
            .await
        });
        client.write_all(&frame).await.expect("write tcp");
        drop(client);
        let err = server.await.expect("join").unwrap_err();
        assert!(err.to_string().contains("vision mux accepts only udp"));
    });
}

#[test]
fn generic_mux_udp_without_router_uses_direct_freedom() {
    block_on(async {
        let echo = bind_echo_udp().await;
        let destination = VlessDestination::Ip(echo.ip(), echo.port());
        let (mut client, mut server) = duplex(8192);
        let server = tokio::spawn(async move { handle_mux_cool_inbound(&mut server).await });
        client
            .write_all(&encode_mux_new_udp(11, &destination, b"direct"))
            .await
            .expect("new");
        assert!(
            tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client))
                .await
                .expect("timeout")
                .is_ok()
        );
        drop(client);
        server.await.expect("join").unwrap();
    });
}

#[test]
fn generic_mux_udp_domain_without_router_resolves() {
    block_on(async {
        let echo = bind_echo_udp().await;
        let destination = VlessDestination::Domain("127.0.0.1".to_string(), echo.port());
        let (mut client, mut server) = duplex(8192);
        let server = tokio::spawn(async move { handle_mux_cool_inbound(&mut server).await });
        client
            .write_all(&encode_mux_new_udp(12, &destination, b"domain-direct"))
            .await
            .expect("new");
        assert!(
            tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client))
                .await
                .expect("timeout")
                .is_ok()
        );
        drop(client);
        server.await.expect("join").unwrap();
    });
}

#[tokio::test]
async fn generic_mux_udp_ipv6_when_available() {
    if UdpSocket::bind("[::1]:0").await.is_err() {
        return;
    }
    let socket = UdpSocket::bind("[::1]:0").await.expect("bind v6");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..len], peer).await;
        }
    });
    let route_env = test_route_env(freedom_router(), None);
    let destination = VlessDestination::Ip(addr.ip(), addr.port());
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client
        .write_all(&encode_mux_new_udp(13, &destination, b"v6"))
        .await
        .expect("new");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client))
            .await
            .expect("timeout")
            .is_ok()
    );
    drop(client);
    let _ = server_task.await;
}

#[test]
fn generic_mux_udp_two_sessions_do_not_block_each_other() {
    block_on(async {
        let silent = UdpSocket::bind("127.0.0.1:0").await.expect("silent");
        let silent_port = silent.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = silent.recv_from(&mut buf).await;
        });

        let fast = bind_echo_udp().await;
        let slow_dest = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), silent_port);
        let fast_dest = VlessDestination::Ip(fast.ip(), fast.port());
        let (mut client, mut server) = duplex(8192);
        let server = tokio::spawn(async move { handle_mux_cool_inbound(&mut server).await });
        client
            .write_all(&encode_mux_new_udp(30, &slow_dest, b"slow"))
            .await
            .expect("slow new");
        client
            .write_all(&encode_mux_new_udp(31, &fast_dest, b"fast"))
            .await
            .expect("fast new");
        let frame = read_mux_frame(&mut client).await.expect("fast response");
        assert_eq!(frame.id(), 31);
        drop(client);
        server.await.expect("join").unwrap();
    });
}
