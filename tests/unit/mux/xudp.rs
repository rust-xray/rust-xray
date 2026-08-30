use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{duplex, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::xray::raw::OutboundObject;
use crate::dns::DnsEngine;
use crate::mux::encoder::{
    encode_mux_end, encode_mux_keep_udp, encode_mux_new_tcp, encode_mux_new_udp_xudp,
};
use crate::mux::frame::{XUDP_MAX_PACKET_LEN, XUDP_UPSTREAM_CLIENT_MAX_PAYLOAD};
use crate::mux::parser::read_mux_frame;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::session::handle_mux_cool_inbound_with_env;
use crate::mux::tcp;
use crate::mux::xudp::{XudpManager, XudpManagerConfig, XudpStatus};
use crate::routing::{route_context_from_vless, NetworkKind, RouteSocketMeta, RuntimeRouter};
use crate::runtime::RuntimeOutboundManager;
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
        email: Some("xudp@example.test".to_string()),
        flow: None,
        level: None,
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
    xudp: Arc<XudpManager>,
    vision_mux_udp_only: bool,
) -> MuxRouteEnv {
    MuxRouteEnv {
        router,
        inbound_tag: "vless-in".to_string(),
        auth: test_auth(),
        socket_meta: RouteSocketMeta::default(),
        sniffing_enabled: false,
        vision_mux_udp_only,
        stats: None,
        xudp,
        test_dispatch_counter: None,
    }
}

fn test_route_env_with_dispatch_counter(
    router: Arc<RuntimeRouter>,
    xudp: Arc<XudpManager>,
    dispatch_counter: Arc<AtomicUsize>,
) -> MuxRouteEnv {
    MuxRouteEnv {
        router,
        inbound_tag: "vless-in".to_string(),
        auth: test_auth(),
        socket_meta: RouteSocketMeta::default(),
        sniffing_enabled: false,
        vision_mux_udp_only: false,
        stats: None,
        xudp,
        test_dispatch_counter: Some(dispatch_counter),
    }
}

fn short_expiry_manager() -> Arc<XudpManager> {
    XudpManager::new_for_test(XudpManagerConfig {
        expiry: Duration::from_millis(20),
        sweep_interval: Duration::from_secs(3600),
    })
}

async fn bind_echo_udp() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo udp");
    let addr = socket.local_addr().expect("echo addr");
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

#[tokio::test]
async fn xudp_first_global_id_creates_one_association() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [9, 8, 7, 6, 5, 4, 3, 2];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            1,
            destination,
            b"one".to_vec(),
            &route_env,
            udp_tx,
        )
        .await
        .expect("handle new");
    assert_eq!(manager.association_count().await, 1);
    assert_eq!(manager.status_of(global_id).await, Some(XudpStatus::Active));
}

#[tokio::test]
async fn xudp_same_global_id_reuse_does_not_create_second_association() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [1, 1, 2, 2, 3, 3, 4, 4];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            1,
            destination.clone(),
            b"a".to_vec(),
            &route_env,
            udp_tx.clone(),
        )
        .await
        .expect("first new");
    manager
        .handle_new(global_id, 2, destination, b"b".to_vec(), &route_env, udp_tx)
        .await
        .expect("reattach new");
    assert_eq!(manager.association_count().await, 1);
}

#[tokio::test]
async fn xudp_different_global_ids_create_independent_associations() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(
            [1, 0, 0, 0, 0, 0, 0, 1],
            1,
            destination.clone(),
            b"a".to_vec(),
            &route_env,
            udp_tx.clone(),
        )
        .await
        .expect("first");
    manager
        .handle_new(
            [2, 0, 0, 0, 0, 0, 0, 2],
            2,
            destination,
            b"b".to_vec(),
            &route_env,
            udp_tx,
        )
        .await
        .expect("second");
    assert_eq!(manager.association_count().await, 2);
}

#[tokio::test]
async fn xudp_detach_marks_expiring_and_sweep_removes() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [4, 4, 4, 4, 4, 4, 4, 4];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(global_id, 7, destination, b"x".to_vec(), &route_env, udp_tx)
        .await
        .expect("new");
    manager.detach(global_id, 7).await;
    assert_eq!(
        manager.status_of(global_id).await,
        Some(XudpStatus::Expiring)
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    manager.sweep_expired_now().await;
    assert_eq!(manager.association_count().await, 0);
}

#[tokio::test]
async fn xudp_reattach_before_expiry_restores_active() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [5, 5, 5, 5, 5, 5, 5, 5];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            1,
            destination.clone(),
            b"a".to_vec(),
            &route_env,
            udp_tx.clone(),
        )
        .await
        .expect("new");
    manager.detach(global_id, 1).await;
    manager
        .handle_new(global_id, 2, destination, b"b".to_vec(), &route_env, udp_tx)
        .await
        .expect("reattach");
    assert_eq!(manager.status_of(global_id).await, Some(XudpStatus::Active));
}

#[tokio::test]
async fn xudp_blackhole_does_not_require_external_udp_peer() {
    let manager = short_expiry_manager();
    let router = blackhole_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let global_id = [6, 6, 6, 6, 6, 6, 6, 6];
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 53);
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            3,
            destination,
            b"drop".to_vec(),
            &route_env,
            udp_tx,
        )
        .await
        .expect("blackhole new");
    assert_eq!(manager.association_count().await, 1);
}

#[tokio::test]
async fn vision_mux_rejects_tcp_child_substream() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, manager, true);
    let destination = VlessDestination::Domain("example.com".to_string(), 443);
    let frame = encode_mux_new_tcp(1, &destination, b"GET");
    let (mut client_io, mut server_io) = duplex(8192);
    let server = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server_io, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client_io.write_all(&frame).await.expect("write tcp new");
    drop(client_io);
    let err = server.await.expect("server join").unwrap_err();
    assert!(err.to_string().contains("vision mux accepts only udp"));
}

#[tokio::test]
async fn vision_mux_accepts_xudp_udp_child() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), true);
    let target = bind_echo_udp().await;
    let global_id = [7, 7, 7, 7, 7, 7, 7, 7];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let frame = encode_mux_new_udp_xudp(8, &destination, &global_id, b"vision");
    let (mut client_io, mut server_io) = duplex(8192);
    let server = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server_io, DnsEngine::shared(), None, Some(route_env))
            .await
    });
    client_io.write_all(&frame).await.expect("write xudp new");
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(client_io);
    assert!(server.await.expect("server join").is_ok());
}

#[test]
fn normal_mux_tcp_allowed_without_vision_restriction() {
    block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tcp");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
        let raw = encode_mux_new_tcp(2, &destination, b"GET");
        let metadata_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        let frame = crate::mux::parser::parse_mux_frame(
            &raw[2..2 + metadata_len],
            &raw[2 + metadata_len..],
        )
        .expect("parse tcp frame");
        let mut active = None;
        let route_env = test_route_env(freedom_router(), short_expiry_manager(), false);
        match tcp::handle_mux_tcp_command(&mut active, frame, Some(&route_env)).await {
            Err(err) => panic!("normal mux tcp rejected unexpectedly: {err}"),
            Ok(_) => assert!(active.is_some()),
        }
    });
}

#[tokio::test]
async fn xudp_multiple_downstream_datagrams_emit_multiple_keep_frames() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let target = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_, peer) = socket.recv_from(&mut buf).await.expect("recv1");
        socket.send_to(b"one", peer).await.expect("send1");
        socket.send_to(b"two", peer).await.expect("send2");
    });
    let global_id = [8, 8, 8, 8, 8, 8, 8, 8];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            9,
            destination,
            b"probe".to_vec(),
            &route_env,
            udp_tx,
        )
        .await
        .expect("new");
    let mut responses = 0;
    for _ in 0..2 {
        if tokio::time::timeout(Duration::from_secs(1), udp_rx.recv())
            .await
            .ok()
            .flatten()
            .is_some()
        {
            responses += 1;
        }
    }
    assert_eq!(responses, 2);
}

#[tokio::test]
async fn xudp_keep_carries_per_packet_destination_metadata() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [9, 9, 9, 9, 9, 9, 9, 9];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            10,
            destination.clone(),
            b"first".to_vec(),
            &route_env,
            udp_tx,
        )
        .await
        .expect("new");
    let alt = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), target.port());
    manager
        .handle_keep(10, global_id, alt, b"second".to_vec())
        .await
        .expect("keep");
}

#[tokio::test]
async fn xudp_cross_parent_reattach_reuses_association() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env_a = test_route_env(Arc::clone(&router), Arc::clone(&manager), false);
    let route_env_b = test_route_env(router, Arc::clone(&manager), false);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let target = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..len], peer).await;
        }
    });
    let global_id = [10, 10, 10, 10, 10, 10, 10, 10];
    let destination = VlessDestination::Ip(target.ip(), target.port());

    let (mut client_a, mut server_a) = duplex(8192);
    let server_a_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(
            &mut server_a,
            DnsEngine::shared(),
            None,
            Some(route_env_a),
        )
        .await
    });
    client_a
        .write_all(&encode_mux_new_udp_xudp(1, &destination, &global_id, b"a"))
        .await
        .expect("write a");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client_a))
            .await
            .expect("response timeout")
            .is_ok()
    );
    client_a.write_all(&encode_mux_end(1)).await.expect("end a");
    drop(client_a);
    let _ = server_a_task.await;

    assert_eq!(manager.association_count().await, 1);
    assert_eq!(
        manager.status_of(global_id).await,
        Some(XudpStatus::Expiring)
    );

    let (mut client_b, mut server_b) = duplex(8192);
    let server_b_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(
            &mut server_b,
            DnsEngine::shared(),
            None,
            Some(route_env_b),
        )
        .await
    });
    client_b
        .write_all(&encode_mux_new_udp_xudp(2, &destination, &global_id, b"b"))
        .await
        .expect("write b");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client_b))
            .await
            .expect("response timeout b")
            .is_ok()
    );
    drop(client_b);
    let _ = server_b_task.await;
    assert_eq!(manager.status_of(global_id).await, Some(XudpStatus::Active));
}

#[tokio::test]
async fn xudp_initializing_collision_does_not_duplicate_association() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [3, 3, 3, 3, 3, 3, 3, 3];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            1,
            destination.clone(),
            b"a".to_vec(),
            &route_env,
            udp_tx.clone(),
        )
        .await
        .expect("first new");
    manager
        .force_status_for_test(global_id, XudpStatus::Initializing)
        .await;
    manager
        .handle_new(global_id, 2, destination, b"b".to_vec(), &route_env, udp_tx)
        .await
        .expect("collision new");
    assert_eq!(manager.association_count().await, 1);
}

#[test]
fn vision_mux_tcp_rejection_via_handle_mux_tcp_command() {
    block_on(async {
        let mut active = None;
        let frame = parse_test_tcp_frame();
        let route_env = test_route_env(freedom_router(), short_expiry_manager(), true);
        match tcp::handle_mux_tcp_command(&mut active, frame, Some(&route_env)).await {
            Err(err) => assert!(err.to_string().contains("vision mux accepts only udp")),
            Ok(_) => panic!("vision mux tcp child should be rejected"),
        }
    });
}

fn parse_test_tcp_frame() -> crate::mux::frame::MuxFrame {
    let destination = VlessDestination::Domain("example.com".to_string(), 443);
    let raw = encode_mux_new_tcp(1, &destination, b"hi");
    let metadata_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    crate::mux::parser::parse_mux_frame(&raw[2..2 + metadata_len], &raw[2 + metadata_len..])
        .expect("parse tcp frame")
}

#[tokio::test]
async fn xudp_broken_association_recreate_dispatches_twice() {
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env_with_dispatch_counter(
        router,
        Arc::clone(&manager),
        Arc::clone(&dispatch_count),
    );
    let target = bind_echo_udp().await;
    let global_id = [11, 11, 11, 11, 11, 11, 11, 11];
    let destination = VlessDestination::Ip(target.ip(), target.port());

    let (udp_tx_a, _udp_rx_a) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            1,
            destination.clone(),
            b"first".to_vec(),
            &route_env,
            udp_tx_a,
        )
        .await
        .expect("initial new");
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);

    let (udp_tx_b, _udp_rx_b) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            2,
            destination.clone(),
            b"reattach".to_vec(),
            &route_env,
            udp_tx_b,
        )
        .await
        .expect("healthy reattach");
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);

    manager.break_uplink_for_test(global_id).await;

    let (udp_tx_c, mut udp_rx_c) = mpsc::unbounded_channel();
    manager
        .handle_new(
            global_id,
            3,
            destination,
            b"after-break".to_vec(),
            &route_env,
            udp_tx_c,
        )
        .await
        .expect("broken reattach");
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 2);
    assert_eq!(manager.association_count().await, 1);

    assert!(
        tokio::time::timeout(Duration::from_secs(1), udp_rx_c.recv())
            .await
            .ok()
            .flatten()
            .is_some(),
        "replacement association emits downstream response on new attachment"
    );
}

#[tokio::test]
async fn xudp_domain_initial_destination_routes_and_reuses_association() {
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env_with_dispatch_counter(
        router,
        Arc::clone(&manager),
        Arc::clone(&dispatch_count),
    );
    let target = bind_echo_udp().await;
    let global_id = [12, 12, 12, 12, 12, 12, 12, 12];
    let destination = VlessDestination::Domain("127.0.0.1".to_string(), target.port());

    let route_ctx = route_context_from_vless(
        &route_env.inbound_tag,
        &route_env.auth,
        &destination,
        b"probe",
        &route_env.socket_meta,
        false,
        NetworkKind::Udp,
    );
    assert_eq!(route_ctx.network, NetworkKind::Udp);
    assert_eq!(route_ctx.target_domain, "127.0.0.1");

    let (mut client_io, mut server_io) = duplex(8192);
    let server = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server_io, DnsEngine::shared(), None, Some(route_env))
            .await
    });

    client_io
        .write_all(&encode_mux_new_udp_xudp(
            20,
            &destination,
            &global_id,
            b"domain-probe",
        ))
        .await
        .expect("write domain xudp new");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client_io))
            .await
            .expect("response timeout")
            .is_ok()
    );
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    assert_eq!(manager.association_count().await, 1);

    client_io
        .write_all(&encode_mux_keep_udp(20, &destination, b"second"))
        .await
        .expect("write keep");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read_mux_frame(&mut client_io))
            .await
            .expect("keep response timeout")
            .is_ok()
    );
    assert_eq!(
        dispatch_count.load(Ordering::SeqCst),
        1,
        "keep reuse must not re-dispatch"
    );

    drop(client_io);
    let _ = server.await;
}

#[test]
fn xudp_packet_size_semantics_document_upstream_client_and_server_bounds() {
    assert_eq!(XUDP_MAX_PACKET_LEN, 8192);
    assert_eq!(XUDP_UPSTREAM_CLIENT_MAX_PAYLOAD, 7526);
    assert!(7526 <= XUDP_MAX_PACKET_LEN);
}

#[tokio::test]
async fn xudp_server_accepts_packet_at_server_capacity() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [13, 13, 13, 13, 13, 13, 13, 13];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let payload = vec![0xAB; XUDP_MAX_PACKET_LEN];
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    manager
        .handle_new(global_id, 21, destination, payload, &route_env, udp_tx)
        .await
        .expect("max-size packet accepted");
}

#[tokio::test]
async fn xudp_server_rejects_packet_larger_than_server_capacity() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [14, 14, 14, 14, 14, 14, 14, 14];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let payload = vec![0u8; XUDP_MAX_PACKET_LEN + 1];
    let (udp_tx, _udp_rx) = mpsc::unbounded_channel();
    let result = manager
        .handle_new(global_id, 22, destination, payload, &route_env, udp_tx)
        .await;
    match result {
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput),
        Ok(_) => panic!("oversize packet rejected"),
    }
}
