use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;

use rust_xray::api::proto::app::proxyman::command::handler_service_client::HandlerServiceClient;
use rust_xray::api::proto::app::proxyman::command::{
    AddInboundRequest, AddOutboundRequest, AlterOutboundRequest, ListInboundsRequest,
    ListOutboundsRequest, RemoveInboundRequest, RemoveOutboundRequest,
};
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::config::XrayConfig;
use rust_xray::runtime::{encode_freedom_outbound, encode_inbound_handler_config, HandlerRuntime};
use rust_xray::stats::StatsRegistry;
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::encryption::VlessDecryption;
use tokio::net::TcpListener;
use tonic::transport::Endpoint;
use tonic::Code;

fn reality_inbound_config(tag: &str, port: u16) -> rust_xray::config::VlessRealityInbound {
    rust_xray::config::VlessRealityInbound {
        tag: Some(tag.to_string()),
        listen_addr: format!("127.0.0.1:{port}"),
        users: vec![VlessClient {
            id: uuid::Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap(),
            email: Some("dynamic-inbound@example.test".to_string()),
            flow: None,
            level: None,
            testseed: rust_xray::vless::UPSTREAM_DEFAULT_TESTSEED,
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
            decryption: VlessDecryption::None,
            dest_xver: 0,
            dest_transport: rust_xray::reality::RealityDestTransport::Tcp,
            limit_fallback_upload: Default::default(),
            limit_fallback_download: Default::default(),
        },
        fallbacks: vec![],
        sniffing_enabled: false,
    }
}

async fn spawn_crud_server() -> (
    std::net::SocketAddr,
    Arc<HandlerRuntime>,
    Arc<StatsRegistry>,
) {
    let config: XrayConfig =
        serde_json::from_str(include_str!("fixtures/remna/reality_vless_api_config.json"))
            .expect("parse fixture");
    let stats_state = rust_xray::stats::StatsState::from_xray_config(&config, None);
    let registry = Arc::clone(&stats_state.registry);
    let handler_runtime = Arc::new(
        HandlerRuntime::new(Arc::new(config), Arc::clone(&registry), None, false)
            .expect("handler runtime"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let runtime = Arc::clone(&handler_runtime);
    let stats = Arc::clone(&registry);
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Handler],
            stats,
            runtime,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    (addr, handler_runtime, registry)
}

fn pick_free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

#[tokio::test]
async fn add_and_list_outbound_freedom() {
    let (addr, runtime, _registry) = spawn_crud_server().await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );

    client
        .add_outbound(AddOutboundRequest {
            outbound: Some(encode_freedom_outbound("dynamic-direct")),
        })
        .await
        .expect("add outbound")
        .into_inner();

    let listed = client
        .list_outbounds(ListOutboundsRequest {})
        .await
        .expect("list outbounds")
        .into_inner();
    let tags: Vec<_> = listed.outbounds.iter().map(|o| o.tag.as_str()).collect();
    assert!(tags.contains(&"dynamic-direct"));
    assert!(runtime.outbound.contains("dynamic-direct"));
}

#[tokio::test]
async fn remove_outbound_hides_from_list() {
    let (addr, runtime, _registry) = spawn_crud_server().await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .add_outbound(AddOutboundRequest {
            outbound: Some(encode_freedom_outbound("temp-out")),
        })
        .await
        .expect("add")
        .into_inner();
    client
        .remove_outbound(RemoveOutboundRequest {
            tag: "temp-out".to_string(),
        })
        .await
        .expect("remove")
        .into_inner();
    assert!(!runtime.outbound.contains("temp-out"));
    let listed = client
        .list_outbounds(ListOutboundsRequest {})
        .await
        .expect("list")
        .into_inner();
    assert!(!listed
        .outbounds
        .iter()
        .any(|outbound| outbound.tag == "temp-out"));
}

#[tokio::test]
async fn add_inbound_starts_listener_and_lists_full_config() {
    let port = pick_free_port();
    let (addr, _runtime, _registry) = spawn_crud_server().await;
    let inbound = reality_inbound_config("dynamic-reality-in", port);
    let handler_config = encode_inbound_handler_config(&inbound, &[]).expect("encode");

    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .add_inbound(AddInboundRequest {
            inbound: Some(handler_config),
        })
        .await
        .expect("add inbound")
        .into_inner();

    let listed = client
        .list_inbounds(ListInboundsRequest {
            is_only_tags: false,
        })
        .await
        .expect("list")
        .into_inner();
    assert!(listed
        .inbounds
        .iter()
        .any(|entry| entry.tag == "dynamic-reality-in"));
    assert!(listed.inbounds.iter().any(|entry| {
        entry
            .proxy_settings
            .as_ref()
            .is_some_and(|proxy| proxy.r#type == "xray.proxy.vless.inbound.Config")
    }));

    let probe = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")),
    )
    .await
    .expect("connect timeout")
    .expect("connect");
    drop(probe);
}

#[tokio::test]
async fn remove_inbound_closes_listener_and_frees_port() {
    let port = pick_free_port();
    let (addr, _runtime, _registry) = spawn_crud_server().await;
    let inbound = reality_inbound_config("remove-me-in", port);
    let handler_config = encode_inbound_handler_config(&inbound, &[]).expect("encode");
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .add_inbound(AddInboundRequest {
            inbound: Some(handler_config),
        })
        .await
        .expect("add")
        .into_inner();
    client
        .remove_inbound(RemoveInboundRequest {
            tag: "remove-me-in".to_string(),
        })
        .await
        .expect("remove")
        .into_inner();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let rebound = StdTcpListener::bind(format!("127.0.0.1:{port}"));
    assert!(
        rebound.is_ok(),
        "port should be reusable after RemoveInbound"
    );
}

#[tokio::test]
async fn add_inbound_bind_failure_leaves_registry_unchanged() {
    let port = pick_free_port();
    let blocker = StdTcpListener::bind(format!("127.0.0.1:{port}")).expect("block port");
    let (addr, runtime, _registry) = spawn_crud_server().await;
    let inbound = reality_inbound_config("failed-in", port);
    let handler_config = encode_inbound_handler_config(&inbound, &[]).expect("encode");
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    let err = client
        .add_inbound(AddInboundRequest {
            inbound: Some(handler_config),
        })
        .await
        .expect_err("bind should fail");
    assert_eq!(err.code(), Code::Unavailable);
    assert!(!runtime
        .inbound
        .list_tags()
        .iter()
        .any(|tag| tag == "failed-in"));
    drop(blocker);
}

#[tokio::test]
async fn alter_outbound_unknown_operation_matches_upstream_failure() {
    let (addr, _runtime, _registry) = spawn_crud_server().await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .add_outbound(AddOutboundRequest {
            outbound: Some(encode_freedom_outbound("alter-target")),
        })
        .await
        .expect("add outbound")
        .into_inner();
    let err = client
        .alter_outbound(AlterOutboundRequest {
            tag: "alter-target".to_string(),
            operation: Some(TypedMessage {
                r#type: "xray.app.proxyman.command.NoSuchOperation".to_string(),
                value: vec![],
            }),
        })
        .await
        .expect_err("alter outbound");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn dynamic_inbound_supports_alter_inbound_add_user() {
    let port = pick_free_port();
    let (addr, _runtime, _registry) = spawn_crud_server().await;
    let inbound = reality_inbound_config("users-in", port);
    let users = vec![rust_xray::vless::user_manager::ManagedUser {
        id: uuid::Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap(),
        email: "dynamic-inbound@example.test".to_string(),
        flow: None,
        level: None,
        testseed: rust_xray::vless::UPSTREAM_DEFAULT_TESTSEED,
        expiry_secs: None,
    }];
    let handler_config = encode_inbound_handler_config(&inbound, &users).expect("encode");
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .add_inbound(AddInboundRequest {
            inbound: Some(handler_config),
        })
        .await
        .expect("add inbound")
        .into_inner();

    let count = client
        .get_inbound_users_count(
            rust_xray::api::proto::app::proxyman::command::GetInboundUserRequest {
                tag: "users-in".to_string(),
                email: String::new(),
            },
        )
        .await
        .expect("count")
        .into_inner()
        .count;
    assert_eq!(count, 1);
}
