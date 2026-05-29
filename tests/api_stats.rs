use std::sync::Arc;
use std::time::Duration;

use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::stats_service_server::StatsServiceServer;
use rust_xray::api::proto::app::stats::command::{
    GetStatsRequest, QueryStatsRequest, SysStatsRequest,
};
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::api::stats::StatsServiceImpl;
use rust_xray::config::{PolicyConfig, PolicyLevel, SystemPolicy, XrayConfig};
use rust_xray::runtime::InboundUserManagers;
use rust_xray::stats::StatsPolicy;
use rust_xray::stats::{inbound_traffic_uplink, StatsRegistry, StatsSession, StatsState};
use tokio::net::TcpListener;
use tonic::server::NamedService;
use tonic::transport::Endpoint;
use tonic::Code;

#[test]
fn stats_service_grpc_path_matches_upstream_xray() {
    assert_eq!(
        StatsServiceServer::<StatsServiceImpl>::NAME,
        "xray.app.stats.command.StatsService"
    );
    assert_eq!(
        format!(
            "/{}/GetSysStats",
            StatsServiceServer::<StatsServiceImpl>::NAME
        ),
        "/xray.app.stats.command.StatsService/GetSysStats"
    );
}

fn test_stats_state() -> StatsState {
    let config: XrayConfig =
        serde_json::from_str(include_str!("fixtures/remna/reality_vless_api_config.json"))
            .expect("parse remna fixture");
    StatsState::from_xray_config(&config, Some("vless-reality-in".to_string()))
}

#[tokio::test]
async fn get_sys_stats_returns_ok_via_tonic_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let registry = Arc::new(StatsRegistry::new());
    tokio::spawn(async move {
        let inbound_users = Arc::new(InboundUserManagers::new());
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Stats],
            registry,
            inbound_users,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut client = StatsServiceClient::new(channel);
    let resp = client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("xray.app.stats.command.StatsService/GetSysStats")
        .into_inner();
    assert!(resp.uptime <= 5);
}

#[tokio::test]
async fn get_stats_returns_value_and_reset_clears_counter() {
    let registry = Arc::new(StatsRegistry::new());
    let name = inbound_traffic_uplink("vless-reality-in");
    registry.add(&name, 128);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let services = vec![ApiService::Stats];
    let registry_for_server = Arc::clone(&registry);
    tokio::spawn(async move {
        let inbound_users = Arc::new(InboundUserManagers::new());
        let _ = serve_grpc_on(
            listener,
            services,
            registry_for_server,
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
        .get_stats(GetStatsRequest {
            name: name.clone(),
            reset: false,
        })
        .await
        .expect("get_stats")
        .into_inner();
    assert_eq!(resp.stat.as_ref().expect("stat").value, 128);

    let resp = client
        .get_stats(GetStatsRequest {
            name: name.clone(),
            reset: true,
        })
        .await
        .expect("get_stats reset")
        .into_inner();
    assert_eq!(resp.stat.as_ref().expect("stat").value, 128);
    assert_eq!(registry.get(&name, false).unwrap(), 0);
}

#[tokio::test]
async fn get_stats_missing_name_returns_not_found() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let registry = Arc::new(StatsRegistry::new());
    tokio::spawn(async move {
        let inbound_users = Arc::new(InboundUserManagers::new());
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Stats],
            registry,
            inbound_users,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = StatsServiceClient::new(channel);
    let err = client
        .get_stats(GetStatsRequest {
            name: "inbound>>>missing>>>traffic>>>uplink".to_string(),
            reset: false,
        })
        .await
        .expect_err("not found");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn query_stats_filters_by_pattern() {
    let registry = Arc::new(StatsRegistry::new());
    registry.add("inbound>>>in>>>traffic>>>uplink", 10);
    registry.add("outbound>>>direct>>>traffic>>>downlink", 20);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let registry_for_server = Arc::clone(&registry);
    tokio::spawn(async move {
        let inbound_users = Arc::new(InboundUserManagers::new());
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Stats],
            registry_for_server,
            inbound_users,
            ApiTransportMode::Plaintext,
        )
        .await;
    });

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = StatsServiceClient::new(channel);
    let resp = client
        .query_stats(QueryStatsRequest {
            pattern: "inbound>>>".to_string(),
            reset: false,
        })
        .await
        .expect("query")
        .into_inner();
    assert_eq!(resp.stat.len(), 1);
    assert_eq!(resp.stat[0].name, "inbound>>>in>>>traffic>>>uplink");
    assert_eq!(resp.stat[0].value, 10);
}

#[test]
fn session_records_relay_bytes_with_policy() {
    let state = test_stats_state();
    let session = state
        .session(Some("remna-user@example.test".to_string()), Some(0))
        .expect("session");
    session.record_relay(100, 200);

    let registry = &state.registry;
    assert_eq!(
        registry
            .get("user>>>remna-user@example.test>>>traffic>>>uplink", false)
            .unwrap(),
        100
    );
    assert_eq!(
        registry
            .get("inbound>>>vless-reality-in>>>traffic>>>downlink", false)
            .unwrap(),
        200
    );
}

#[test]
fn policy_disables_user_uplink_counter() {
    let registry = Arc::new(StatsRegistry::new());
    let mut levels = std::collections::BTreeMap::new();
    levels.insert(
        "0".to_string(),
        PolicyLevel {
            stats_user_uplink: false,
            stats_user_downlink: true,
            stats_user_online: false,
            extra: Default::default(),
        },
    );
    let policy_config = PolicyConfig {
        levels,
        system: Some(SystemPolicy::default()),
        extra: Default::default(),
    };
    let session = StatsSession::new(
        registry.clone(),
        StatsPolicy::all_enabled(),
        Some(&policy_config),
        "in".to_string(),
        "direct".to_string(),
        Some("user@example.com".to_string()),
        Some(0),
    );
    session.record_relay(50, 60);
    assert_eq!(
        registry
            .get("user>>>user@example.com>>>traffic>>>uplink", false)
            .unwrap_err(),
        rust_xray::stats::GetStatError::NotFound
    );
    assert_eq!(
        registry
            .get("user>>>user@example.com>>>traffic>>>downlink", false)
            .unwrap(),
        60
    );
}
