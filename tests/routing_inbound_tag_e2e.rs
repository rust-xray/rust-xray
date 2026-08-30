//! Stage 8E2-F4A inbound-tag routing E2E: dynamic AddInbound + merged REALITY auth.

#[path = "routing_e2e_harness.rs"]
mod harness;

use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;

use harness::*;
use rust_xray::api::proto::app::proxyman::command::{AddInboundRequest, RemoveInboundRequest};
use rust_xray::api::proto::app::router::command::RoutingContext;
use rust_xray::api::proto::common::net::Network;
use rust_xray::config::VlessRealityInbound;
use rust_xray::reality::tls13::{
    tls13_cipher_suite, RealityTls13ApplicationStream, Tls13RecordDecryptor, Tls13RecordEncryptor,
    Tls13TrafficKeys, TLS_AES_128_GCM_SHA256,
};
use rust_xray::routing::RouteSocketMeta;
use rust_xray::runtime::{encode_plain_vless_inbound_handler_config, VlessInboundAuthContext};
use rust_xray::transport::{run_inbound_transport, AcceptedTransport, VlessHandler};
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::user_manager::ManagedUser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

fn pick_free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn plain_vless_inbound(
    tag: &str,
    port: u16,
    user: ManagedUser,
) -> rust_xray::api::proto::core::InboundHandlerConfig {
    let inbound = VlessRealityInbound {
        tag: Some(tag.to_string()),
        listen_addr: format!("127.0.0.1:{port}"),
        users: vec![VlessClient {
            id: user.id,
            email: Some(user.email.clone()),
            flow: user.flow.clone(),
            level: user.level,
        }],
        transport: rust_xray::config::InboundTransportConfig::RawTcp,
        reality: rust_xray::config::RealityServerConfig {
            dest_addr: "127.0.0.1:1".to_string(),
            private_key: String::new(),
            server_names: Vec::new(),
            short_ids: Vec::new(),
            max_time_diff: 0,
            min_client_ver: None,
            max_client_ver: None,
            show: false,
            mldsa65_seed: None,
            decryption: "none".to_string(),
            dest_xver: 0,
            dest_transport: rust_xray::reality::RealityDestTransport::Tcp,
            limit_fallback_upload: Default::default(),
            limit_fallback_download: Default::default(),
        },
        fallbacks: vec![],
        sniffing_enabled: false,
    };
    encode_plain_vless_inbound_handler_config(&inbound, std::slice::from_ref(&user))
        .expect("encode")
}

fn reality_inbound_config(
    tag: &str,
    port: u16,
    user: ManagedUser,
) -> rust_xray::api::proto::core::InboundHandlerConfig {
    let inbound = rust_xray::config::VlessRealityInbound {
        tag: Some(tag.to_string()),
        listen_addr: format!("127.0.0.1:{port}"),
        users: vec![VlessClient {
            id: user.id,
            email: Some(user.email.clone()),
            flow: user.flow.clone(),
            level: user.level,
        }],
        transport: rust_xray::config::InboundTransportConfig::RawTcp,
        reality: rust_xray::config::RealityServerConfig {
            dest_addr: "www.microsoft.com:443".to_string(),
            private_key: "MKVGVTTvyEyI7hpl7vP7WKtRXLhH0JieCMHgFdn6A3s".to_string(),
            server_names: vec!["www.microsoft.com".to_string()],
            short_ids: vec![vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]],
            max_time_diff: 0,
            min_client_ver: None,
            max_client_ver: None,
            show: false,
            mldsa65_seed: None,
            decryption: "none".to_string(),
            dest_xver: 0,
            dest_transport: rust_xray::reality::RealityDestTransport::Tcp,
            limit_fallback_upload: Default::default(),
            limit_fallback_download: Default::default(),
        },
        fallbacks: vec![],
        sniffing_enabled: false,
    };
    rust_xray::runtime::encode_inbound_handler_config(&inbound, std::slice::from_ref(&user))
        .expect("encode")
}

fn tls_keys(seed: u8) -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let keys = Tls13TrafficKeys {
        key: (seed..seed + 16).collect(),
        iv: (0x01..0x0d).collect(),
    };
    (
        Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
        Tls13RecordDecryptor::new(suite, keys).expect("dec"),
    )
}

fn vision_flow_addons() -> Vec<u8> {
    let flow = b"xtls-rprx-vision";
    let mut addons = Vec::with_capacity(2 + flow.len());
    addons.push(0x0a);
    addons.push(flow.len() as u8);
    addons.extend_from_slice(flow);
    addons
}

fn build_vless_ip_request_with_vision(user_id: &[u8; 16], port: u16) -> Vec<u8> {
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

async fn dial_vless_user(
    vless_addr: std::net::SocketAddr,
    user_id: &[u8; 16],
    target_port: u16,
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(vless_addr).await?;
    stream
        .write_all(&build_vless_ip_request(user_id, target_port))
        .await?;
    let mut buf = [0u8; 64];
    let _ = stream.read(&mut buf).await?;
    stream.shutdown().await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Ok(())
}

async fn run_merged_reality_session(
    auth: VlessInboundAuthContext,
    router: Arc<rust_xray::routing::RuntimeRouter>,
    vless_request: Vec<u8>,
) -> std::io::Result<()> {
    let handler =
        VlessHandler::new_with_auth_context(auth, None, RouteSocketMeta::default(), Some(router));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (mut client_encryptor, _) = tls_keys(0x10);
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
    let (_, server_decryptor) = tls_keys(0x10);
    let (server_encryptor, _) = tls_keys(0x20);
    let app_stream =
        RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
    run_inbound_transport(AcceptedTransport::RawTcp, app_stream, &handler).await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    Ok(())
}

#[tokio::test]
async fn dynamic_add_inbound_routing_e2e_without_restart() {
    let dynamic_user = Uuid::from_bytes([
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44,
    ]);
    let user_bytes = *dynamic_user.as_bytes();
    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler, mut routing) = connect_routing_clients(grpc_addr).await;

    let port = pick_free_port();
    let inbound = plain_vless_inbound(
        "dynamic-route-in",
        port,
        ManagedUser {
            id: dynamic_user,
            email: "dynamic-route@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        },
    );
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(inbound),
        })
        .await
        .expect("add inbound")
        .into_inner();

    let vless_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    assert!(runtime
        .inbound
        .user_managers()
        .get("dynamic-route-in")
        .is_ok());

    let (target_a, hit_a) = spawn_target_listener().await;
    dial_vless_user(vless_addr, &user_bytes, target_a)
        .await
        .expect("baseline dial");
    assert!(
        target_hit_within(hit_a, 2000).await,
        "default freedom outbound"
    );

    tonic_add_rule(
        &mut routing,
        inbound_rule_message("dynamic-route-in", "direct-b", "dynamic-route-rule"),
    )
    .await;

    let (target_b, hit_b) = spawn_target_listener().await;
    dial_vless_user(vless_addr, &user_bytes, target_b)
        .await
        .expect("routed dial");
    assert!(
        !target_hit_within(hit_b, 500).await,
        "blackhole outbound must not reach target"
    );

    assert_test_route_outbound(
        &mut routing,
        RoutingContext {
            inbound_tag: "dynamic-route-in".to_string(),
            network: Network::Tcp as i32,
            user: "dynamic-route@example.test".to_string(),
            target_domain: String::new(),
            target_port: u32::from(target_b),
            vless_route: u32::from(rust_xray::routing::vless_route_from_uuid(&dynamic_user)),
            ..Default::default()
        },
        "direct-b",
    )
    .await;

    tonic_remove_rule(&mut routing, "dynamic-route-rule").await;

    let (target_a2, hit_a2) = spawn_target_listener().await;
    dial_vless_user(vless_addr, &user_bytes, target_a2)
        .await
        .expect("restored dial");
    assert!(
        target_hit_within(hit_a2, 2000).await,
        "removed rule restores default"
    );

    handler
        .remove_inbound(RemoveInboundRequest {
            tag: "dynamic-route-in".to_string(),
        })
        .await
        .expect("remove inbound")
        .into_inner();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        StdTcpListener::bind(format!("127.0.0.1:{port}")).is_ok(),
        "port must be reusable after RemoveInbound"
    );
}

#[tokio::test]
async fn dynamic_add_inbound_add_user_authenticates_on_data_plane() {
    const INBOUND: &str = "dynamic-adduser-in";
    const STATIC_ID: &str = "11111111-1111-1111-1111-111111111111";
    const DYNAMIC_ID: &str = "22222222-2222-2222-2222-222222222222";

    let static_user = ManagedUser {
        id: Uuid::parse_str(STATIC_ID).expect("static uuid"),
        email: "static@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };
    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler, _routing) = connect_routing_clients(grpc_addr).await;

    let port = pick_free_port();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound(INBOUND, port, static_user)),
        })
        .await
        .expect("add inbound")
        .into_inner();

    handler
        .alter_inbound(add_user_request(
            INBOUND,
            "dynamic@example.test",
            DYNAMIC_ID,
        ))
        .await
        .expect("add user")
        .into_inner();

    let vless_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let dynamic_bytes = *Uuid::parse_str(DYNAMIC_ID)
        .expect("dynamic uuid")
        .as_bytes();
    let (target_port, hit) = spawn_target_listener().await;
    dial_vless_user(vless_addr, &dynamic_bytes, target_port)
        .await
        .expect("dynamic user auth");
    assert!(
        target_hit_within(hit, 2000).await,
        "HandlerService AddUser must update live auth context"
    );
}

#[tokio::test]
async fn merged_reality_logical_inbound_tag_routing_e2e() {
    let id_a = Uuid::from_bytes([0x0a; 16]);
    let id_b = Uuid::from_bytes([0x0b; 16]);
    let user_a = ManagedUser {
        id: id_a,
        email: "user-a@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };
    let user_b = ManagedUser {
        id: id_b,
        email: "user-b@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };

    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler, mut routing) = connect_routing_clients(grpc_addr).await;

    let port = pick_free_port();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound("merged-in-a", port, user_a.clone())),
        })
        .await
        .expect("add inbound a")
        .into_inner();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound("merged-in-b", port, user_b.clone())),
        })
        .await
        .expect("add inbound b")
        .into_inner();

    assert_eq!(runtime.inbound.physical_listener_count(), 1);
    let merge_key = runtime
        .inbound
        .merge_key_for_tag("merged-in-a")
        .expect("merge key");
    assert_eq!(
        runtime.inbound.logical_tags_for_merge_key(&merge_key),
        vec!["merged-in-a", "merged-in-b"]
    );

    let vless_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");

    let (target_a, hit_a) = spawn_target_listener().await;
    dial_vless_user(vless_addr, id_a.as_bytes(), target_a)
        .await
        .expect("user a baseline dial");
    assert!(
        target_hit_within(hit_a, 2000).await,
        "baseline must reach freedom outbound"
    );

    tonic_add_rule(
        &mut routing,
        inbound_rule_message("merged-in-a", "direct-a", "merged-a-rule"),
    )
    .await;
    tonic_add_rule(
        &mut routing,
        inbound_rule_message("merged-in-b", "direct-b", "merged-b-rule"),
    )
    .await;

    let (target_b, hit_b) = spawn_target_listener().await;
    dial_vless_user(vless_addr, id_b.as_bytes(), target_b)
        .await
        .expect("user b routed dial");
    assert!(
        !target_hit_within(hit_b, 500).await,
        "tag B routes to blackhole"
    );

    let (target_a2, hit_a2) = spawn_target_listener().await;
    dial_vless_user(vless_addr, id_a.as_bytes(), target_a2)
        .await
        .expect("user a routed dial");
    assert!(
        target_hit_within(hit_a2, 2000).await,
        "tag A routes to freedom"
    );

    assert_test_route_outbound(
        &mut routing,
        RoutingContext {
            inbound_tag: "merged-in-a".to_string(),
            network: Network::Tcp as i32,
            user: user_a.email.clone(),
            target_port: u32::from(target_a),
            vless_route: u32::from(rust_xray::routing::vless_route_from_uuid(&id_a)),
            ..Default::default()
        },
        "direct-a",
    )
    .await;
    assert_test_route_outbound(
        &mut routing,
        RoutingContext {
            inbound_tag: "merged-in-b".to_string(),
            network: Network::Tcp as i32,
            user: user_b.email.clone(),
            target_port: u32::from(target_b),
            vless_route: u32::from(rust_xray::routing::vless_route_from_uuid(&id_b)),
            ..Default::default()
        },
        "direct-b",
    )
    .await;

    handler
        .remove_inbound(RemoveInboundRequest {
            tag: "merged-in-a".to_string(),
        })
        .await
        .expect("remove a")
        .into_inner();
    assert_eq!(runtime.inbound.physical_listener_count(), 1);

    handler
        .remove_inbound(RemoveInboundRequest {
            tag: "merged-in-b".to_string(),
        })
        .await
        .expect("remove b")
        .into_inner();
    assert_eq!(runtime.inbound.physical_listener_count(), 0);
    assert!(
        StdTcpListener::bind(format!("127.0.0.1:{port}")).is_ok(),
        "port reusable after last merged inbound removed"
    );
}

#[tokio::test]
async fn independent_listeners_allow_same_vless_uuid() {
    let shared_id = Uuid::from_bytes([0x55; 16]);
    let user = ManagedUser {
        id: shared_id,
        email: "shared-uuid@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };

    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler, _routing) = connect_routing_clients(grpc_addr).await;

    let port_a = pick_free_port();
    let port_b = pick_free_port();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound("independent-a", port_a, user.clone())),
        })
        .await
        .expect("add inbound a")
        .into_inner();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound("independent-b", port_b, user.clone())),
        })
        .await
        .expect("add inbound b")
        .into_inner();

    assert_eq!(runtime.inbound.physical_listener_count(), 2);

    let addr_a: std::net::SocketAddr = format!("127.0.0.1:{port_a}").parse().expect("addr");
    let addr_b: std::net::SocketAddr = format!("127.0.0.1:{port_b}").parse().expect("addr");
    let (target_a, hit_a) = spawn_target_listener().await;
    let (target_b, hit_b) = spawn_target_listener().await;
    dial_vless_user(addr_a, shared_id.as_bytes(), target_a)
        .await
        .expect("dial a");
    dial_vless_user(addr_b, shared_id.as_bytes(), target_b)
        .await
        .expect("dial b");
    assert!(target_hit_within(hit_a, 2000).await);
    assert!(target_hit_within(hit_b, 2000).await);
}

#[tokio::test]
async fn merged_listener_rejects_duplicate_uuid_on_second_add_inbound() {
    let shared_id = Uuid::from_bytes([0x66; 16]);
    let user_a = ManagedUser {
        id: shared_id,
        email: "dup-a@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };
    let user_b = ManagedUser {
        id: shared_id,
        email: "dup-b@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };

    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler, _routing) = connect_routing_clients(grpc_addr).await;

    let port = pick_free_port();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound("dup-merge-a", port, user_a)),
        })
        .await
        .expect("add inbound a")
        .into_inner();

    let err = handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound("dup-merge-b", port, user_b)),
        })
        .await
        .expect_err("duplicate uuid on merged listener must fail");
    assert!(
        err.message().contains("duplicate vless user id"),
        "unexpected error: {}",
        err.message()
    );
    assert_eq!(runtime.inbound.physical_listener_count(), 1);
}

#[tokio::test]
async fn merged_listener_add_user_duplicate_uuid_is_rejected() {
    let id_a = Uuid::from_bytes([0x77; 16]);
    let id_b = Uuid::from_bytes([0x78; 16]);
    let user_a = ManagedUser {
        id: id_a,
        email: "adduser-a@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };
    let user_b = ManagedUser {
        id: id_b,
        email: "adduser-b@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };

    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler, _routing) = connect_routing_clients(grpc_addr).await;

    let port = pick_free_port();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound("adduser-merge-a", port, user_a.clone())),
        })
        .await
        .expect("add inbound a")
        .into_inner();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(plain_vless_inbound("adduser-merge-b", port, user_b)),
        })
        .await
        .expect("add inbound b")
        .into_inner();

    let err = handler
        .alter_inbound(add_user_request(
            "adduser-merge-b",
            "collision@example.test",
            &id_a.to_string(),
        ))
        .await
        .expect_err("AddUser duplicate uuid must fail");
    assert!(
        err.message().contains("duplicate vless user id"),
        "unexpected error: {}",
        err.message()
    );
    assert!(
        !runtime
            .inbound
            .user_managers()
            .get("adduser-merge-b")
            .expect("manager b")
            .contains_id(id_a),
        "collision user must not be registered"
    );
}

#[tokio::test]
async fn merged_reality_shared_auth_set_routes_by_logical_inbound_tag() {
    let id_a = Uuid::from_bytes([0x1a; 16]);
    let id_b = Uuid::from_bytes([0x1b; 16]);
    let user_a = ManagedUser {
        id: id_a,
        email: "reality-a@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };
    let user_b = ManagedUser {
        id: id_b,
        email: "reality-b@example.test".to_string(),
        flow: None,
        level: None,
        expiry_secs: None,
    };

    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler, mut routing) = connect_routing_clients(grpc_addr).await;

    let port = pick_free_port();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(reality_inbound_config(
                "merged-reality-a",
                port,
                user_a.clone(),
            )),
        })
        .await
        .expect("add reality a")
        .into_inner();
    handler
        .add_inbound(AddInboundRequest {
            inbound: Some(reality_inbound_config(
                "merged-reality-b",
                port,
                user_b.clone(),
            )),
        })
        .await
        .expect("add reality b")
        .into_inner();

    assert_eq!(runtime.inbound.physical_listener_count(), 1);
    assert_eq!(
        runtime
            .inbound
            .physical_listen_addr_for_tag("merged-reality-a")
            .expect("listen addr"),
        format!("127.0.0.1:{port}")
    );

    let shared_config = runtime
        .inbound
        .listener_config_for_tag("merged-reality-a")
        .expect("shared listener config");
    assert_eq!(shared_config.auth.auth_set().manager_count(), 2);

    let auth = shared_config.auth.clone();
    let router = Arc::clone(&runtime.router);

    tonic_add_rule(
        &mut routing,
        inbound_rule_message("merged-reality-a", "direct-a", "merged-reality-a-rule"),
    )
    .await;
    tonic_add_rule(
        &mut routing,
        inbound_rule_message("merged-reality-b", "direct-b", "merged-reality-b-rule"),
    )
    .await;

    let (target_b, hit_b) = spawn_target_listener().await;
    run_merged_reality_session(
        auth.clone(),
        Arc::clone(&router),
        build_vless_ip_request_with_vision(id_b.as_bytes(), target_b),
    )
    .await
    .expect("reality session user b");
    assert!(
        !target_hit_within(hit_b, 500).await,
        "logical tag B must route to blackhole"
    );

    assert_test_route_outbound(
        &mut routing,
        RoutingContext {
            inbound_tag: "merged-reality-a".to_string(),
            network: Network::Tcp as i32,
            user: user_a.email.clone(),
            target_port: u32::from(target_b),
            vless_route: u32::from(rust_xray::routing::vless_route_from_uuid(&id_a)),
            ..Default::default()
        },
        "direct-a",
    )
    .await;
    assert_test_route_outbound(
        &mut routing,
        RoutingContext {
            inbound_tag: "merged-reality-b".to_string(),
            network: Network::Tcp as i32,
            user: user_b.email.clone(),
            target_port: u32::from(target_b),
            vless_route: u32::from(rust_xray::routing::vless_route_from_uuid(&id_b)),
            ..Default::default()
        },
        "direct-b",
    )
    .await;
}
