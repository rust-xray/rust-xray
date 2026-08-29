//! Transport routing E2E + TestRoute parity across REALITY/XHTTP/Vision/Mux.

#[path = "routing_e2e_harness.rs"]
mod harness;

use std::sync::Arc;

use harness::*;
use rust_xray::api::proto::app::router::command::RoutingContext;
use rust_xray::api::proto::common::net::Network;
use rust_xray::config::normalized::XHttpRuntimeConfig;
use rust_xray::config::XHttpSettings;
use rust_xray::mux::{encode_mux_new_tcp, read_mux_frame, MuxCommand};
use rust_xray::reality::tls13::{
    tls13_cipher_suite, RealityTls13ApplicationStream, Tls13RecordDecryptor, Tls13RecordEncryptor,
    Tls13TrafficKeys, TLS_AES_128_GCM_SHA256,
};
use rust_xray::routing::RouteSocketMeta;
use rust_xray::transport::xhttp::serve_xhttp_stream_one_with_socket_meta;
use rust_xray::transport::{run_inbound_transport, AcceptedTransport, VlessHandler};
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::encode_vless_response_header;
use rust_xray::vless::handle_vless_tcp_inbound_with_socket_meta;
use rust_xray::vless::protocol::VlessDestination;
use rust_xray::vless::user_manager::VlessUserManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

fn vision_flow_addons() -> Vec<u8> {
    let flow = b"xtls-rprx-vision";
    let mut addons = Vec::with_capacity(2 + flow.len());
    addons.push(0x0a);
    addons.push(flow.len() as u8);
    addons.extend_from_slice(flow);
    addons
}

fn aes128_keys(seed: u8) -> Tls13TrafficKeys {
    Tls13TrafficKeys {
        key: (seed..seed + 16).collect(),
        iv: (0x01..0x0d).collect(),
    }
}

fn client_to_server_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let keys = aes128_keys(0x10);
    (
        Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor"),
        Tls13RecordDecryptor::new(suite, keys).expect("decryptor"),
    )
}

fn server_to_client_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let keys = aes128_keys(0x20);
    (
        Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor"),
        Tls13RecordDecryptor::new(suite, keys).expect("decryptor"),
    )
}

fn http1_stream_one_request(path: &str, host: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn build_vless_ip_with_vision_flow(user_id: &[u8; 16], port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    let addons = vision_flow_addons();
    buf.push(addons.len() as u8);
    buf.extend_from_slice(&addons);
    buf.push(0x01);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.push(0x01);
    buf.extend_from_slice(&[127, 0, 0, 1]);
    buf
}

async fn spawn_echo_target(port_hint: u16) -> (u16, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = tx.send(());
            let mut buf = [0u8; 4];
            if socket.read_exact(&mut buf).await.is_ok() && &buf == b"PING" {
                let _ = socket.write_all(b"PONG").await;
            }
        }
        let _ = port_hint;
    });
    (port, rx)
}

async fn spawn_vless_listener(
    _inbound_tag: &str,
    users: Arc<VlessUserManager>,
    router: Arc<rust_xray::routing::RuntimeRouter>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let socket_meta = RouteSocketMeta::from_tcp_stream(&stream);
            let users = Arc::clone(&users);
            let router = Arc::clone(&router);
            tokio::spawn(async move {
                let _ = handle_vless_tcp_inbound_with_socket_meta(
                    stream,
                    users.as_ref(),
                    None,
                    &socket_meta,
                    Some(&router),
                )
                .await;
            });
        }
    });
    addr
}

async fn run_reality_raw_transport_session(
    handler: &VlessHandler,
    vless_request: Vec<u8>,
) -> std::io::Result<()> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (mut client_encryptor, _) = client_to_server_keys();
    let encrypted = client_encryptor
        .encrypt_application_data(&vless_request)
        .map_err(|err| std::io::Error::other(err.to_string()))?;

    tokio::spawn(async move {
        let mut client_io = client_io;
        if client_io.write_all(&encrypted).await.is_err() {
            return;
        }
        let mut buf = [0u8; 4096];
        let _ = client_io.read(&mut buf).await;
    });

    let (_, server_decryptor) = client_to_server_keys();
    let (server_encryptor, _) = server_to_client_keys();
    let app_stream =
        RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
    tokio::spawn({
        let handler = handler.clone();
        async move {
            let _ = run_inbound_transport(AcceptedTransport::RawTcp, app_stream, &handler).await;
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    Ok(())
}

async fn dial_xhttp_stream_one(
    xhttp_addr: std::net::SocketAddr,
    domain: &str,
    target_port: u16,
) -> std::io::Result<()> {
    let body = build_vless_domain_request(&DEFAULT_USER_ID, domain, target_port);
    let request = http1_stream_one_request("/xhttp", "example.com", &body);
    let mut stream = tokio::net::TcpStream::connect(xhttp_addr).await?;
    stream.write_all(&request).await?;
    let mut response = [0u8; 64];
    let _ = stream.read(&mut response).await?;
    stream.shutdown().await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Ok(())
}

async fn dial_xhttp_ip(xhttp_addr: std::net::SocketAddr, target_port: u16) -> std::io::Result<()> {
    let body = build_vless_ip_request(&DEFAULT_USER_ID, target_port);
    let request = http1_stream_one_request("/xhttp", "example.com", &body);
    let mut stream = tokio::net::TcpStream::connect(xhttp_addr).await?;
    stream.write_all(&request).await?;
    let mut response = [0u8; 64];
    let _ = stream.read(&mut response).await?;
    stream.shutdown().await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Ok(())
}

#[tokio::test]
async fn reality_accepted_raw_transport_routes_via_tonic_add_and_remove() {
    const INBOUND: &str = "reality-raw-route-in";
    const EMAIL: &str = "reality-route@example.test";

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        INBOUND,
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some(EMAIL.to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let handler = VlessHandler::new_with_socket_meta(
        Arc::clone(&users),
        None,
        None,
        RouteSocketMeta::default(),
        Some(Arc::clone(&router)),
    );

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_handler_client, mut routing_client) = connect_routing_clients(grpc_addr).await;

    let (port_a, hit_a) = spawn_target_listener().await;
    run_reality_raw_transport_session(&handler, build_vless_ip_request(&DEFAULT_USER_ID, port_a))
        .await
        .expect("baseline reality raw route");
    assert!(
        target_hit_within(hit_a, 2000).await,
        "baseline must reach direct-a via freedom"
    );

    tonic_add_rule(
        &mut routing_client,
        user_rule_message(EMAIL, "direct-b", "reality-user-rule"),
    )
    .await;

    let (port_b, hit_b) = spawn_target_listener().await;
    run_reality_raw_transport_session(&handler, build_vless_ip_request(&DEFAULT_USER_ID, port_b))
        .await
        .expect("routed reality raw");
    assert!(
        !target_hit_within(hit_b, 400).await,
        "user rule must select blackhole outbound"
    );

    assert_test_route_outbound(
        &mut routing_client,
        routing_context_for_vless_tcp(
            INBOUND,
            EMAIL,
            &Uuid::from_bytes(DEFAULT_USER_ID),
            "",
            port_b,
            "",
        ),
        "direct-b",
    )
    .await;

    tonic_remove_rule(&mut routing_client, "reality-user-rule").await;

    let (port_a2, hit_a2) = spawn_target_listener().await;
    run_reality_raw_transport_session(&handler, build_vless_ip_request(&DEFAULT_USER_ID, port_a2))
        .await
        .expect("restored reality raw");
    assert!(
        target_hit_within(hit_a2, 2000).await,
        "removed rule must restore default outbound"
    );
}

#[tokio::test]
async fn reality_dynamic_user_routes_via_handler_and_routing_services() {
    const INBOUND: &str = "reality-dynamic-in";
    const DYNAMIC_ID: &str = "66666666-6666-6666-6666-666666666666";
    const EMAIL: &str = "reality-dynamic@example.test";

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(INBOUND, vec![]));
    runtime.inbound.user_managers().register(Arc::clone(&users));
    let router = Arc::clone(&runtime.router);
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler_client, mut routing_client) = connect_routing_clients(grpc_addr).await;

    handler_client
        .alter_inbound(add_user_request(INBOUND, EMAIL, DYNAMIC_ID))
        .await
        .expect("add user");

    tonic_add_rule(
        &mut routing_client,
        user_rule_message(EMAIL, "direct-b", "reality-dynamic-rule"),
    )
    .await;

    let dynamic_uuid = Uuid::parse_str(DYNAMIC_ID).expect("uuid");
    let handler = VlessHandler::new_with_socket_meta(
        Arc::clone(&users),
        None,
        None,
        RouteSocketMeta::default(),
        Some(Arc::clone(&router)),
    );

    let (port, hit) = spawn_target_listener().await;
    run_reality_raw_transport_session(
        &handler,
        build_vless_ip_request(dynamic_uuid.as_bytes(), port),
    )
    .await
    .expect("dynamic user reality route");
    assert!(
        !target_hit_within(hit, 400).await,
        "HandlerService user must route through RuntimeRouter"
    );

    assert_test_route_outbound(
        &mut routing_client,
        routing_context_for_vless_tcp(INBOUND, EMAIL, &dynamic_uuid, "", port, ""),
        "direct-b",
    )
    .await;
}

#[tokio::test]
async fn xhttp_stream_one_routes_via_tonic_domain_rule() {
    const INBOUND: &str = "xhttp-route-in";
    const EMAIL: &str = "xhttp-route@example.test";
    const DOMAIN: &str = "localhost";

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        INBOUND,
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some(EMAIL.to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-one".to_string()),
        ..XHttpSettings::default()
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind xhttp");
    let xhttp_addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let socket_meta = RouteSocketMeta::from_tcp_stream(&stream);
            let users = Arc::clone(&users);
            let router = Arc::clone(&router);
            let settings = settings.clone();
            tokio::spawn(async move {
                let _ = serve_xhttp_stream_one_with_socket_meta(
                    stream,
                    &settings,
                    users,
                    None,
                    socket_meta,
                    Some(router),
                )
                .await;
            });
        }
    });

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing_client) = connect_routing_clients(grpc_addr).await;

    let (port_a, hit_a) = spawn_target_listener().await;
    dial_xhttp_stream_one(xhttp_addr, DOMAIN, port_a)
        .await
        .expect("baseline xhttp session");
    assert!(
        target_hit_within(hit_a, 2000).await,
        "baseline xhttp session must reach target-a"
    );

    tonic_add_rule(
        &mut routing_client,
        domain_rule_message(DOMAIN, "direct-b", "xhttp-domain-rule"),
    )
    .await;

    let picks = count_routing_publishes(&runtime, async {
        let (port_b, hit_b) = spawn_target_listener().await;
        dial_xhttp_stream_one(xhttp_addr, DOMAIN, port_b)
            .await
            .expect("routed xhttp session");
        assert!(
            !target_hit_within(hit_b, 400).await,
            "domain rule must route xhttp session to blackhole"
        );
    })
    .await;
    assert_eq!(picks, 1, "one logical xhttp session must pick route once");

    assert_test_route_outbound(
        &mut routing_client,
        routing_context_for_vless_tcp(
            INBOUND,
            EMAIL,
            &Uuid::from_bytes(DEFAULT_USER_ID),
            DOMAIN,
            port_a,
            "",
        ),
        "direct-b",
    )
    .await;

    tonic_remove_rule(&mut routing_client, "xhttp-domain-rule").await;

    let (port_a2, hit_a2) = spawn_target_listener().await;
    dial_xhttp_stream_one(xhttp_addr, DOMAIN, port_a2)
        .await
        .expect("restored xhttp session");
    assert!(
        target_hit_within(hit_a2, 2000).await,
        "removed rule must restore default xhttp route"
    );
}

#[tokio::test]
async fn vision_flow_routes_before_relay_via_tonic_user_rule() {
    const INBOUND: &str = "vision-route-in";
    const EMAIL: &str = "vision-route@example.test";

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        INBOUND,
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some(EMAIL.to_string()),
            flow: Some("xtls-rprx-vision".to_string()),
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let vless_addr = spawn_vless_listener(INBOUND, Arc::clone(&users), Arc::clone(&router)).await;

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing_client) = connect_routing_clients(grpc_addr).await;

    let (port_a, hit_a) = spawn_target_listener().await;
    let request = build_vless_ip_with_vision_flow(&DEFAULT_USER_ID, port_a);
    let mut stream = tokio::net::TcpStream::connect(vless_addr)
        .await
        .expect("connect");
    stream.write_all(&request).await.expect("write baseline");
    let mut response = [0u8; 2];
    let _ = stream.read(&mut response).await;
    assert!(
        target_hit_within(hit_a, 2000).await,
        "vision baseline must reach freedom target"
    );

    tonic_add_rule(
        &mut routing_client,
        user_rule_message(EMAIL, "direct-b", "vision-user-rule"),
    )
    .await;

    let (port_b, hit_b) = spawn_target_listener().await;
    let request = build_vless_ip_with_vision_flow(&DEFAULT_USER_ID, port_b);
    let mut stream = tokio::net::TcpStream::connect(vless_addr)
        .await
        .expect("connect routed");
    stream.write_all(&request).await.expect("write routed");
    let _ = stream.read(&mut response).await;
    assert!(
        !target_hit_within(hit_b, 400).await,
        "vision user rule must select blackhole before relay"
    );

    assert_test_route_outbound(
        &mut routing_client,
        routing_context_for_vless_tcp(
            INBOUND,
            EMAIL,
            &Uuid::from_bytes(DEFAULT_USER_ID),
            "",
            port_b,
            "",
        ),
        "direct-b",
    )
    .await;

    tonic_remove_rule(&mut routing_client, "vision-user-rule").await;

    let (port_a2, hit_a2) = spawn_target_listener().await;
    let request = build_vless_ip_with_vision_flow(&DEFAULT_USER_ID, port_a2);
    let mut stream = tokio::net::TcpStream::connect(vless_addr)
        .await
        .expect("connect restored");
    stream.write_all(&request).await.expect("write restored");
    let _ = stream.read(&mut response).await;
    assert!(
        target_hit_within(hit_a2, 2000).await,
        "removed vision rule must restore default outbound"
    );
}

#[tokio::test]
async fn mux_two_domains_route_independently_within_one_session() {
    const INBOUND: &str = "mux-route-in";
    const EMAIL: &str = "mux-user@example.test";
    const DOMAIN_X: &str = "mux-blackhole.example";
    const DOMAIN_Y: &str = "localhost";

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        INBOUND,
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some(EMAIL.to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let vless_addr = spawn_vless_listener(INBOUND, Arc::clone(&users), Arc::clone(&router)).await;

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing_client) = connect_routing_clients(grpc_addr).await;

    tonic_add_rule(
        &mut routing_client,
        domain_rule_message(DOMAIN_X, "direct-b", "mux-domain-x"),
    )
    .await;

    let (port_y, hit_y) = spawn_echo_target(0).await;
    let dest_y = VlessDestination::Domain(DOMAIN_Y.to_string(), port_y);
    let open_y = encode_mux_new_tcp(1, &dest_y, b"PING");
    let request = build_vless_mux_request(&DEFAULT_USER_ID, &open_y);

    let mut client = tokio::net::TcpStream::connect(vless_addr)
        .await
        .expect("connect mux");
    client.write_all(&request).await.expect("write mux open");
    let mut header = [0u8; 2];
    client
        .read_exact(&mut header)
        .await
        .expect("vless response");
    assert_eq!(
        header,
        encode_vless_response_header(0, None).as_slice()[..2]
    );

    let frame = read_mux_frame(&mut client).await.expect("mux data");
    assert_eq!(frame.mux_id, 1);
    if let MuxCommand::Data { payload } = frame.command {
        assert_eq!(payload, b"PONG");
    } else {
        panic!("expected mux data response");
    }
    let _ = read_mux_frame(&mut client).await.expect("mux end child 1");
    assert!(
        target_hit_within(hit_y, 2000).await,
        "child to DOMAIN_Y must use default freedom outbound"
    );

    let (port_x, hit_x) = spawn_echo_target(0).await;
    let dest_x = VlessDestination::Domain(DOMAIN_X.to_string(), port_x);
    let open_x = encode_mux_new_tcp(2, &dest_x, b"PING");
    client.write_all(&open_x).await.expect("write child 2");
    let frame = read_mux_frame(&mut client).await.expect("child2 end");
    assert_eq!(frame.mux_id, 2);
    assert!(
        matches!(frame.command, MuxCommand::Close { .. }),
        "blackhole child must close substream without killing mux session"
    );
    assert!(
        !target_hit_within(hit_x, 400).await,
        "child to DOMAIN_X must route to blackhole"
    );

    tonic_remove_rule(&mut routing_client, "mux-domain-x").await;

    let (port_x2, hit_x2) = spawn_echo_target(0).await;
    let dest_x2 = VlessDestination::Domain(DOMAIN_Y.to_string(), port_x2);
    let open_x2 = encode_mux_new_tcp(3, &dest_x2, b"PING");
    client.write_all(&open_x2).await.expect("write child 3");
    let frame = read_mux_frame(&mut client).await.expect("child3 data");
    if let MuxCommand::Data { payload } = frame.command {
        assert_eq!(payload, b"PONG");
    } else {
        panic!("expected mux data response for restored route");
    }
    let _ = read_mux_frame(&mut client).await.expect("child3 end");
    assert!(
        target_hit_within(hit_x2, 2000).await,
        "removed mux domain rule must restore default outbound on new child"
    );

    tonic_add_rule(
        &mut routing_client,
        domain_rule_message(DOMAIN_X, "direct-b", "mux-domain-x"),
    )
    .await;
    assert_test_route_outbound(
        &mut routing_client,
        routing_context_for_vless_tcp(
            INBOUND,
            EMAIL,
            &Uuid::from_bytes(DEFAULT_USER_ID),
            DOMAIN_X,
            port_x,
            "",
        ),
        "direct-b",
    )
    .await;

    tonic_add_rule(
        &mut routing_client,
        user_rule_message(EMAIL, "direct-b", "mux-user-rule"),
    )
    .await;
    assert_test_route_outbound(
        &mut routing_client,
        routing_context_for_vless_tcp(
            INBOUND,
            EMAIL,
            &Uuid::from_bytes(DEFAULT_USER_ID),
            DOMAIN_Y,
            port_y,
            "",
        ),
        "direct-b",
    )
    .await;

    tonic_add_rule(
        &mut routing_client,
        vless_route_rule_message(
            rust_xray::routing::vless_route_from_uuid(&Uuid::from_bytes(DEFAULT_USER_ID)),
            "direct-b",
            "mux-vless-route",
        ),
    )
    .await;
    let route = rust_xray::routing::vless_route_from_uuid(&Uuid::from_bytes(DEFAULT_USER_ID));
    assert_test_route_outbound(
        &mut routing_client,
        RoutingContext {
            inbound_tag: INBOUND.to_string(),
            network: Network::Tcp as i32,
            user: EMAIL.to_string(),
            vless_route: u32::from(route),
            ..Default::default()
        },
        "direct-b",
    )
    .await;

    client.shutdown().await.ok();
}

#[tokio::test]
async fn dynamic_outbound_is_routable_from_xhttp_and_test_route() {
    const INBOUND: &str = "dynamic-out-xhttp";
    const EMAIL: &str = "dyn-out@example.test";

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        INBOUND,
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some(EMAIL.to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let xhttp_addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let socket_meta = RouteSocketMeta::from_tcp_stream(&stream);
            let users = Arc::clone(&users);
            let router = Arc::clone(&router);
            let settings = settings.clone();
            tokio::spawn(async move {
                let _ = serve_xhttp_stream_one_with_socket_meta(
                    stream,
                    &settings,
                    users,
                    None,
                    socket_meta,
                    Some(router),
                )
                .await;
            });
        }
    });

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler_client, mut routing_client) = connect_routing_clients(grpc_addr).await;
    tonic_add_outbound(&mut handler_client, "dynamic-out", false).await;
    tonic_add_rule(
        &mut routing_client,
        user_rule_message(EMAIL, "dynamic-out", "dynamic-out-rule"),
    )
    .await;

    let (port, hit) = spawn_target_listener().await;
    dial_xhttp_ip(xhttp_addr, port)
        .await
        .expect("dynamic outbound xhttp session");
    assert!(
        target_hit_within(hit, 2000).await,
        "dynamic freedom outbound must reach target via live xhttp routing"
    );

    assert_test_route_outbound(
        &mut routing_client,
        routing_context_for_vless_tcp(
            INBOUND,
            EMAIL,
            &Uuid::from_bytes(DEFAULT_USER_ID),
            "",
            port,
            "",
        ),
        "dynamic-out",
    )
    .await;
}

#[tokio::test]
async fn blackhole_route_terminates_vless_connection_without_panic() {
    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        "blackhole-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("blackhole@example.test".to_string()),
            flow: None,
            level: None,
        }],
    ));
    runtime
        .router
        .add_rule(
            &user_rule_message("blackhole@example.test", "direct-b", "always-blackhole"),
            true,
        )
        .expect("add");

    let router = Arc::clone(&runtime.router);
    let addr = spawn_vless_listener("blackhole-in", Arc::clone(&users), router).await;
    let (port, hit) = spawn_target_listener().await;
    dial_vless_ip(addr, port).await.expect("dial blackhole");
    assert!(!target_hit_within(hit, 300).await);
}

#[tokio::test]
async fn raw_vless_test_route_parity_matrix_covers_required_fields() {
    const INBOUND: &str = "parity-raw-in";
    const EMAIL: &str = "parity@example.test";
    const DOMAIN: &str = "parity.example";

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new_with_sniffing(
        INBOUND,
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some(EMAIL.to_string()),
            flow: None,
            level: None,
        }],
        true,
    ));
    let router = Arc::clone(&runtime.router);
    let addr = spawn_vless_listener(INBOUND, Arc::clone(&users), router).await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing_client) = connect_routing_clients(grpc_addr).await;

    runtime
        .router
        .add_rule(
            &domain_rule_message(DOMAIN, "direct-b", "parity-domain"),
            true,
        )
        .expect("domain");
    runtime
        .router
        .add_rule(
            &inbound_rule_message(INBOUND, "direct-b", "parity-inbound"),
            true,
        )
        .expect("inbound");
    runtime
        .router
        .add_rule(
            &vless_route_rule_message(
                rust_xray::routing::vless_route_from_uuid(&Uuid::from_bytes(DEFAULT_USER_ID)),
                "direct-b",
                "parity-vless-route",
            ),
            true,
        )
        .expect("vless route");
    runtime
        .router
        .add_rule(
            &protocol_rule_message("tls", "direct-b", "parity-protocol"),
            true,
        )
        .expect("protocol");

    let (port, hit) = spawn_target_listener().await;
    let mut request = build_vless_domain_request(&DEFAULT_USER_ID, DOMAIN, port);
    request.extend_from_slice(&[0x16, 0x03, 0x01, 0x00]);
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream.write_all(&request).await.expect("write");
    stream.shutdown().await.ok();
    let _ = stream.read_u8().await;
    assert!(!target_hit_within(hit, 400).await);

    for ctx in [
        routing_context_for_vless_tcp(
            INBOUND,
            EMAIL,
            &Uuid::from_bytes(DEFAULT_USER_ID),
            DOMAIN,
            port,
            "tls",
        ),
        RoutingContext {
            inbound_tag: INBOUND.to_string(),
            network: Network::Tcp as i32,
            user: EMAIL.to_string(),
            ..Default::default()
        },
        RoutingContext {
            inbound_tag: INBOUND.to_string(),
            network: Network::Tcp as i32,
            vless_route: u32::from(rust_xray::routing::vless_route_from_uuid(
                &Uuid::from_bytes(DEFAULT_USER_ID),
            )),
            ..Default::default()
        },
        RoutingContext {
            inbound_tag: INBOUND.to_string(),
            network: Network::Tcp as i32,
            protocol: "tls".to_string(),
            ..Default::default()
        },
    ] {
        assert_test_route_outbound(&mut routing_client, ctx, "direct-b").await;
    }
}

#[tokio::test]
async fn xhttp_reality_transport_entry_uses_same_router_as_run_inbound_transport() {
    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        "xhttp-reality-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("xhttp-reality@example.test".to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let handler = VlessHandler::new_with_socket_meta(
        Arc::clone(&users),
        None,
        None,
        RouteSocketMeta::default(),
        Some(Arc::clone(&router)),
    );
    let config = XHttpRuntimeConfig::from_settings(&XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    });

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (port, hit) = spawn_target_listener().await;
    let body = build_vless_ip_request(&DEFAULT_USER_ID, port);
    let request = http1_stream_one_request("/xhttp", "example.com", &body);
    let (mut client_encryptor, _) = client_to_server_keys();
    let encrypted = client_encryptor
        .encrypt_application_data(&request)
        .expect("encrypt xhttp request");
    let client_task = tokio::spawn(async move {
        let mut client_io = client_io;
        if client_io.write_all(&encrypted).await.is_err() {
            return;
        }
        let mut buf = [0u8; 4096];
        let _ = client_io.read(&mut buf).await;
    });

    let (_, server_decryptor) = client_to_server_keys();
    let (server_encryptor, _) = server_to_client_keys();
    let app_stream =
        RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
    assert!(Arc::ptr_eq(
        handler.router().expect("router"),
        &runtime.router
    ));
    let handler_for_task = handler.clone();
    tokio::spawn(async move {
        let _ = run_inbound_transport(
            AcceptedTransport::XHttp(config),
            app_stream,
            &handler_for_task,
        )
        .await;
    });
    let _ = client_task.await;
    assert!(
        target_hit_within(hit, 2000).await,
        "run_inbound_transport xhttp path must route through handler RuntimeRouter"
    );
}

#[tokio::test]
async fn remove_dynamic_outbound_referenced_by_rule_fails_connection_safely() {
    const INBOUND: &str = "remove-out-vless";
    const EMAIL: &str = "remove-out@example.test";

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        INBOUND,
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some(EMAIL.to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let vless_addr = spawn_vless_listener(INBOUND, Arc::clone(&users), router).await;

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler_client, mut routing_client) = connect_routing_clients(grpc_addr).await;
    tonic_add_outbound(&mut handler_client, "dynamic-out", false).await;
    tonic_add_rule(
        &mut routing_client,
        user_rule_message(EMAIL, "dynamic-out", "remove-out-rule"),
    )
    .await;

    let (port, hit) = spawn_target_listener().await;
    dial_vless_ip(vless_addr, port)
        .await
        .expect("baseline dynamic outbound route");
    assert!(
        target_hit_within(hit, 2000).await,
        "dynamic outbound must route before removal"
    );

    tonic_remove_outbound(&mut handler_client, "dynamic-out").await;

    let (port_after, hit_after) = spawn_target_listener().await;
    let dial_result = dial_vless_ip(vless_addr, port_after).await;
    assert!(
        dial_result.is_ok(),
        "connection must fail safely without panic, got: {dial_result:?}"
    );
    assert!(
        !target_hit_within(hit_after, 400).await,
        "removed outbound must not reach target"
    );
}
