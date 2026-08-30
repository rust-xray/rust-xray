use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{duplex, AsyncRead, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::xray::raw::OutboundObject;
use crate::dns::DnsEngine;
use crate::mux::encoder::{
    encode_mux_end, encode_mux_keep_data, encode_mux_keep_udp, encode_mux_new_tcp,
    encode_mux_new_udp_xudp,
};
use crate::mux::frame::{MuxCommand, XUDP_MAX_PACKET_LEN, XUDP_UPSTREAM_CLIENT_MAX_PAYLOAD};
use crate::mux::parser::read_mux_frame;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::session::handle_mux_cool_inbound_with_env;
use crate::mux::tcp;
use crate::mux::xudp::{XudpManager, XudpManagerConfig, XudpStatus};
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

fn router_without_outbound() -> Arc<RuntimeRouter> {
    RuntimeRouter::new(
        None,
        RuntimeOutboundManager::new(),
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

async fn bind_tagged_echo_udp(tag: u8) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind tagged echo udp");
    let addr = socket.local_addr().expect("tagged echo addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let mut response = Vec::with_capacity(len + 1);
            response.push(tag);
            response.extend_from_slice(&buf[..len]);
            let _ = socket.send_to(&response, peer).await;
        }
    });
    addr
}

async fn read_udp_response<R>(reader: &mut R) -> Vec<u8>
where
    R: AsyncRead + Unpin,
{
    let frame = tokio::time::timeout(Duration::from_secs(1), read_mux_frame(reader))
        .await
        .expect("mux response timeout")
        .expect("mux response");
    match frame.command {
        MuxCommand::Udp { packet, .. } => packet,
        other => panic!("expected mux UDP response, got {other:?}"),
    }
}

#[tokio::test]
async fn xudp_first_global_id_creates_one_association() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [9, 8, 7, 6, 5, 4, 3, 2];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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
async fn xudp_stale_expiry_candidate_cannot_remove_reactivated_association() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [15, 15, 15, 15, 15, 15, 15, 15];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::channel(64);

    manager
        .handle_new(
            global_id,
            1,
            destination.clone(),
            b"first".to_vec(),
            &route_env,
            udp_tx.clone(),
        )
        .await
        .expect("new");
    manager.detach(global_id, 1).await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    manager
        .handle_new(
            global_id,
            2,
            destination,
            b"reattach".to_vec(),
            &route_env,
            udp_tx,
        )
        .await
        .expect("reattach");
    manager.remove_expired_candidate_for_test(global_id).await;

    assert_eq!(manager.association_count().await, 1);
    assert_eq!(manager.status_of(global_id).await, Some(XudpStatus::Active));
}

#[tokio::test]
async fn xudp_failed_initial_route_does_not_leave_initializing_association() {
    let manager = short_expiry_manager();
    let route_env = test_route_env(router_without_outbound(), Arc::clone(&manager), false);
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let (udp_tx, _udp_rx) = mpsc::channel(64);

    let result = manager
        .handle_new(
            [16, 16, 16, 16, 16, 16, 16, 16],
            1,
            destination,
            b"fail".to_vec(),
            &route_env,
            udp_tx,
        )
        .await;

    assert!(result.is_err());
    assert_eq!(manager.association_count().await, 0);
}

#[tokio::test]
async fn xudp_blackhole_does_not_require_external_udp_peer() {
    let manager = short_expiry_manager();
    let router = blackhole_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let global_id = [6, 6, 6, 6, 6, 6, 6, 6];
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 53);
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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
    let (udp_tx, mut udp_rx) = mpsc::channel(64);
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
async fn xudp_stats_count_payload_once_in_each_direction() {
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
    let manager = short_expiry_manager();
    let mut route_env = test_route_env(freedom_router(), Arc::clone(&manager), false);
    route_env.stats = Some(stats);
    let target = bind_echo_udp().await;
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let payload = b"xudp-payload";
    let (udp_tx, mut udp_rx) = mpsc::channel(64);

    manager
        .handle_new(
            [19, 19, 19, 19, 19, 19, 19, 19],
            19,
            destination,
            payload.to_vec(),
            &route_env,
            udp_tx,
        )
        .await
        .expect("new");
    tokio::time::timeout(Duration::from_secs(1), udp_rx.recv())
        .await
        .expect("response timeout")
        .expect("response");

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
}

#[tokio::test]
async fn xudp_keep_carries_per_packet_destination_metadata() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [9, 9, 9, 9, 9, 9, 9, 9];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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
        .handle_keep(10, global_id, Some(&alt), b"second")
        .await
        .expect("keep");
}

#[tokio::test]
async fn xudp_live_destinationless_keep_frames_reuse_association() {
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let manager = short_expiry_manager();
    let route_env = test_route_env_with_dispatch_counter(
        freedom_router(),
        Arc::clone(&manager),
        Arc::clone(&dispatch_count),
    );
    let target = bind_echo_udp().await;
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let global_id = [21, 22, 23, 24, 25, 26, 27, 28];
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });

    client
        .write_all(&encode_mux_new_udp_xudp(
            0,
            &destination,
            &global_id,
            b"first",
        ))
        .await
        .expect("xudp new");
    assert_eq!(read_udp_response(&mut client).await, b"first");
    assert_eq!(manager.status_of(global_id).await, Some(XudpStatus::Active));
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);

    for payload_len in [8, 28, 60] {
        let payload = vec![payload_len as u8; payload_len];
        let raw = encode_mux_keep_data(0, &payload).expect("destination-less keep");
        assert_eq!(u16::from_be_bytes([raw[0], raw[1]]), 4);
        assert_eq!(&raw[2..6], &[0x00, 0x00, 0x02, 0x01]);
        client.write_all(&raw).await.expect("write live keep");
        assert_eq!(read_udp_response(&mut client).await, payload);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    }

    assert_eq!(manager.association_count().await, 1);
    drop(client);
    server_task.await.expect("join").expect("mux relay");
}

#[tokio::test]
async fn xudp_destinationless_keep_uses_initial_target_after_explicit_override() {
    let dispatch_count = Arc::new(AtomicUsize::new(0));
    let manager = short_expiry_manager();
    let route_env = test_route_env_with_dispatch_counter(
        freedom_router(),
        Arc::clone(&manager),
        Arc::clone(&dispatch_count),
    );
    let target_a = bind_tagged_echo_udp(b'A').await;
    let target_b = bind_tagged_echo_udp(b'B').await;
    let destination_a = VlessDestination::Ip(target_a.ip(), target_a.port());
    let destination_b = VlessDestination::Ip(target_b.ip(), target_b.port());
    let global_id = [31, 32, 33, 34, 35, 36, 37, 38];
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });

    client
        .write_all(&encode_mux_new_udp_xudp(
            40,
            &destination_a,
            &global_id,
            b"new-a",
        ))
        .await
        .expect("xudp new");
    assert_eq!(read_udp_response(&mut client).await, b"Anew-a");

    client
        .write_all(&encode_mux_keep_udp(40, &destination_b, b"override-b"))
        .await
        .expect("explicit destination keep");
    assert_eq!(read_udp_response(&mut client).await, b"Boverride-b");

    client
        .write_all(&encode_mux_keep_data(40, b"default-a").expect("destination-less keep"))
        .await
        .expect("destination-less keep");
    assert_eq!(read_udp_response(&mut client).await, b"Adefault-a");
    assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    assert_eq!(manager.association_count().await, 1);

    drop(client);
    server_task.await.expect("join").expect("mux relay");
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
    client_b
        .write_all(&encode_mux_keep_data(2, b"destination-less after reattach").unwrap())
        .await
        .expect("destination-less keep after reattach");
    assert_eq!(
        read_udp_response(&mut client_b).await,
        b"destination-less after reattach"
    );
    drop(client_b);
    let _ = server_b_task.await;
    assert_eq!(
        manager.status_of(global_id).await,
        Some(XudpStatus::Expiring),
        "implicit parent shutdown detaches the reattached association"
    );
}

#[tokio::test]
async fn xudp_reused_mux_id_detaches_previous_global_id() {
    let manager = short_expiry_manager();
    let route_env = test_route_env(freedom_router(), Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let global_a = [17, 17, 17, 17, 17, 17, 17, 17];
    let global_b = [18, 18, 18, 18, 18, 18, 18, 18];
    let (mut client, mut server) = duplex(8192);
    let server_task = tokio::spawn(async move {
        handle_mux_cool_inbound_with_env(&mut server, DnsEngine::shared(), None, Some(route_env))
            .await
    });

    client
        .write_all(&encode_mux_new_udp_xudp(17, &destination, &global_a, b"a"))
        .await
        .expect("first new");
    read_mux_frame(&mut client).await.expect("first response");
    client
        .write_all(&encode_mux_new_udp_xudp(17, &destination, &global_b, b"b"))
        .await
        .expect("replacement new");
    read_mux_frame(&mut client)
        .await
        .expect("replacement response");

    assert_eq!(
        manager.status_of(global_a).await,
        Some(XudpStatus::Expiring)
    );
    assert_eq!(manager.status_of(global_b).await, Some(XudpStatus::Active));

    drop(client);
    server_task.await.expect("join").expect("mux relay");
}

#[tokio::test]
async fn xudp_initializing_collision_does_not_duplicate_association() {
    let manager = short_expiry_manager();
    let router = freedom_router();
    let route_env = test_route_env(router, Arc::clone(&manager), false);
    let target = bind_echo_udp().await;
    let global_id = [3, 3, 3, 3, 3, 3, 3, 3];
    let destination = VlessDestination::Ip(target.ip(), target.port());
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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

    let (udp_tx_a, _udp_rx_a) = mpsc::channel(64);
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

    let (udp_tx_b, _udp_rx_b) = mpsc::channel(64);
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

    let (udp_tx_c, mut udp_rx_c) = mpsc::channel(64);
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
    let (udp_tx, _udp_rx) = mpsc::channel(64);
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
    let (udp_tx, _udp_rx) = mpsc::channel(64);
    let result = manager
        .handle_new(global_id, 22, destination, payload, &route_env, udp_tx)
        .await;
    match result {
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput),
        Ok(_) => panic!("oversize packet rejected"),
    }
}
