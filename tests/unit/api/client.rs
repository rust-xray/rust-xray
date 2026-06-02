use super::*;
use crate::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use crate::runtime::InboundUserManagers;
use tokio::net::TcpListener;

#[tokio::test]
async fn stats_requires_name() {
    let err = get_stats(StatsApiOptions::default()).await.unwrap_err();
    assert!(err.message.contains("missing required -name"));
}

#[tokio::test]
async fn query_stats_returns_value_from_server() {
    use std::sync::Arc;

    use crate::stats::StatsRegistry;

    let registry = Arc::new(StatsRegistry::new());
    registry.add("inbound>>>in>>>traffic>>>uplink", 7);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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

    let opts = StatsApiOptions {
        server: addr.to_string(),
        timeout_secs: 3,
        ..StatsApiOptions::default()
    };
    let value = query_stats_async(opts).await.expect("query stats");
    assert_eq!(value["stat"][0]["value"], 7);
}

#[tokio::test]
async fn dial_fails_when_nothing_listens() {
    let opts = StatsApiOptions {
        server: "127.0.0.1:1".to_string(),
        timeout_secs: 1,
        ..StatsApiOptions::default()
    };
    let err = connect(&opts).await.unwrap_err();
    assert!(err.message.contains("failed to dial"));
}
