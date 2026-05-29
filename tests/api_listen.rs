use std::sync::Arc;
use std::time::Duration;

use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::SysStatsRequest;
use rust_xray::api::server::{
    bind_api_listener, parse_api_grpc_listen_addr, parse_enabled_services, serve_grpc_on,
};
use rust_xray::config::{api_listen_addr, load_xray_config_from_file};
use rust_xray::runtime::InboundUserManagers;
use rust_xray::stats::StatsRegistry;
use tokio::net::TcpListener;
use tonic::transport::Endpoint;

#[tokio::test]
async fn remna_api_61000_fixture_listen_is_literal() {
    let path = std::path::Path::new("tests/fixtures/remna/reality_vless_api_61000_config.json");
    let config = load_xray_config_from_file(path).expect("load 61000 fixture");
    let listen = api_listen_addr(&config)
        .expect("api listen")
        .expect("listen present");
    assert_eq!(listen, "127.0.0.1:61000");
    let addr = parse_api_grpc_listen_addr(&listen).expect("parse listen");
    assert_eq!(addr.port(), 61000);
    assert!(addr.ip().is_loopback());
}

#[tokio::test]
async fn remna_fixture_api_listen_binds_configured_port() {
    let path = std::path::Path::new("tests/fixtures/remna/reality_vless_api_config.json");
    let config = load_xray_config_from_file(path).expect("load remna fixture");
    let listen = api_listen_addr(&config)
        .expect("api listen")
        .expect("listen present");
    assert_eq!(listen, "127.0.0.1:10085");
    let addr = parse_api_grpc_listen_addr(&listen).expect("parse listen");
    assert_eq!(addr.port(), 10085);
    assert!(addr.ip().is_loopback());
}

#[tokio::test]
async fn get_sys_stats_on_plaintext_api_listen() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let services = parse_enabled_services(&["StatsService".to_string()]).expect("services");
    let registry = Arc::new(StatsRegistry::new());
    let inbound_users = Arc::new(InboundUserManagers::new());
    tokio::spawn(async move {
        let _ = serve_grpc_on(listener, services, registry, inbound_users).await;
    });

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(2))
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

#[tokio::test]
async fn bind_api_listener_uses_explicit_host_port() {
    let (listener, bound) = bind_api_listener("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    drop(listener);
    assert!(bound.ip().is_loopback());
    assert_ne!(bound.port(), 0);
}
