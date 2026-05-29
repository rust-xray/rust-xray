use rust_xray::api::proto::app::proxyman::command::handler_service_client::HandlerServiceClient;
use rust_xray::api::proto::app::proxyman::command::AlterInboundRequest;
use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::{GetStatsRequest, SysStatsRequest};
use rust_xray::api::server::{parse_enabled_services, serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::runtime::InboundUserManagers;
use rust_xray::stats::StatsRegistry;
use tokio::net::TcpListener;
use tonic::transport::Endpoint;
use tonic::Code;

#[tokio::test]
async fn grpc_stats_get_stats_returns_not_found_for_missing_counter() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let services = vec![ApiService::Stats];
    let registry = std::sync::Arc::new(StatsRegistry::new());
    let inbound_users = std::sync::Arc::new(InboundUserManagers::new());
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            services,
            registry,
            inbound_users,
            ApiTransportMode::Plaintext,
        )
        .await;
    });

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut client = StatsServiceClient::new(channel);
    let err = client
        .get_stats(GetStatsRequest {
            name: "inbound>>>x>>>traffic>>>uplink".to_string(),
            reset: false,
        })
        .await
        .expect_err("expected NOT_FOUND");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn grpc_stats_get_sys_stats_returns_minimal_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let services = vec![ApiService::Stats];
    let registry = std::sync::Arc::new(StatsRegistry::new());
    let inbound_users = std::sync::Arc::new(InboundUserManagers::new());
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            services,
            registry,
            inbound_users,
            ApiTransportMode::Plaintext,
        )
        .await;
    });

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut client = StatsServiceClient::new(channel);
    let resp = client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("get_sys_stats")
        .into_inner();
    assert!(resp.uptime <= 5);
}

#[test]
fn parse_enabled_services_rejects_unknown() {
    let err = parse_enabled_services(&["ExampleService".to_string()]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn parse_enabled_services_accepts_remna_services() {
    let services =
        parse_enabled_services(&["HandlerService".to_string(), "StatsService".to_string()])
            .expect("parse");
    assert_eq!(services.len(), 2);
    assert!(services.contains(&ApiService::Handler));
    assert!(services.contains(&ApiService::Stats));
}

#[tokio::test]
async fn grpc_api_server_mounts_reflection_stats_and_handler() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let services = vec![
        ApiService::Reflection,
        ApiService::Stats,
        ApiService::Handler,
    ];
    let registry = std::sync::Arc::new(StatsRegistry::new());
    let inbound_users = std::sync::Arc::new(InboundUserManagers::new());
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            services,
            registry,
            inbound_users,
            ApiTransportMode::Plaintext,
        )
        .await;
    });

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");

    let mut stats = StatsServiceClient::new(channel.clone());
    stats
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("stats service mounted");

    let mut handler = HandlerServiceClient::new(channel);
    let err = handler
        .alter_inbound(AlterInboundRequest {
            tag: "missing-inbound".to_string(),
            operation: None,
        })
        .await
        .expect_err("handler service mounted");
    assert_eq!(err.code(), Code::NotFound);
}
