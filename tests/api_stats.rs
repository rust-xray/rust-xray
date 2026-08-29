use std::sync::Arc;
use std::time::Duration;

use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::stats_service_server::StatsServiceServer;
use rust_xray::api::proto::app::stats::command::{
    GetAllOnlineUsersRequest, GetStatsRequest, GetUsersStatsRequest, QueryStatsRequest,
    SysStatsRequest,
};
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::api::stats::StatsServiceImpl;
use rust_xray::config::{PolicyConfig, PolicyLevel, SystemPolicy, XrayConfig};
use rust_xray::runtime::HandlerRuntime;
use rust_xray::stats::StatsPolicy;
use rust_xray::stats::{
    inbound_traffic_uplink, user_online, user_traffic_downlink, user_traffic_uplink, StatsRegistry,
    StatsSession, StatsState,
};
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::handle_vless_tcp_inbound;
use rust_xray::vless::user_manager::VlessUserManager;
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
        let inbound_users =
            HandlerRuntime::for_handler_tests(Arc::new(rust_xray::stats::StatsRegistry::new()));
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
        let inbound_users =
            HandlerRuntime::for_handler_tests(Arc::new(rust_xray::stats::StatsRegistry::new()));
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
        let inbound_users =
            HandlerRuntime::for_handler_tests(Arc::new(rust_xray::stats::StatsRegistry::new()));
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
        let inbound_users =
            HandlerRuntime::for_handler_tests(Arc::new(rust_xray::stats::StatsRegistry::new()));
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
        .session(Some("remna-user@example.test".to_string()), Some(0), None)
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
        StatsPolicy {
            user_uplink: true,
            user_downlink: true,
            user_online: true,
            inbound_uplink: false,
            inbound_downlink: false,
            outbound_uplink: false,
            outbound_downlink: false,
        },
        Some(&policy_config),
        "in".to_string(),
        "direct".to_string(),
        Some("user@example.com".to_string()),
        Some(0),
        None,
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

async fn spawn_stats_grpc_server(registry: Arc<StatsRegistry>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let inbound_users =
            HandlerRuntime::for_handler_tests(Arc::new(rust_xray::stats::StatsRegistry::new()));
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
    addr
}

async fn stats_client(addr: std::net::SocketAddr) -> StatsServiceClient<tonic::transport::Channel> {
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    StatsServiceClient::new(channel)
}

#[tokio::test]
async fn get_stats_online_via_tonic_client() {
    let registry = Arc::new(StatsRegistry::new());
    let name = user_online("user@example.com");
    registry
        .get_or_register_online_map(&name)
        .add_ip("1.2.3.4", 100);
    registry
        .get_or_register_online_map(&name)
        .add_ip("1.2.3.4", 101);

    let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
    let mut client = stats_client(addr).await;

    let resp = client
        .get_stats_online(GetStatsRequest {
            name: name.clone(),
            reset: false,
        })
        .await
        .expect("get_stats_online")
        .into_inner();
    assert_eq!(resp.stat.expect("stat").value, 1);
}

#[tokio::test]
async fn get_stats_online_reset_leaves_state_unchanged_via_tonic() {
    let registry = Arc::new(StatsRegistry::new());
    let name = user_online("user@example.com");
    registry
        .get_or_register_online_map(&name)
        .add_ip("1.2.3.4", 100);

    let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
    let mut client = stats_client(addr).await;

    client
        .get_stats_online(GetStatsRequest {
            name: name.clone(),
            reset: true,
        })
        .await
        .expect("reset ignored");
    assert_eq!(registry.get_online_map(&name).expect("map").count(), 1);
}

#[tokio::test]
async fn get_stats_online_ip_list_via_tonic_client() {
    let registry = Arc::new(StatsRegistry::new());
    let name = user_online("user@example.com");
    registry
        .get_or_register_online_map(&name)
        .add_ip("1.2.3.4", 100);
    registry
        .get_or_register_online_map(&name)
        .add_ip("5.6.7.8", 101);

    let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
    let mut client = stats_client(addr).await;

    let resp = client
        .get_stats_online_ip_list(GetStatsRequest {
            name: name.clone(),
            reset: false,
        })
        .await
        .expect("ip list")
        .into_inner();
    assert_eq!(resp.ips.len(), 2);
    assert!(resp.ips.contains_key("1.2.3.4"));
    assert!(resp.ips.contains_key("5.6.7.8"));
}

#[tokio::test]
async fn get_all_online_users_via_tonic_client() {
    let registry = Arc::new(StatsRegistry::new());
    let name = user_online("user@example.com");
    registry
        .get_or_register_online_map(&name)
        .add_ip("1.2.3.4", 100);

    let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
    let mut client = stats_client(addr).await;

    let resp = client
        .get_all_online_users(GetAllOnlineUsersRequest {})
        .await
        .expect("all online")
        .into_inner();
    assert_eq!(resp.users, vec![name]);
}

#[tokio::test]
async fn get_users_stats_reset_traffic_via_tonic_client() {
    let registry = Arc::new(StatsRegistry::new());
    let email = "user@example.com";
    registry
        .get_or_register_online_map(&user_online(email))
        .add_ip("1.2.3.4", 100);
    registry.add(&user_traffic_uplink(email), 100);
    registry.add(&user_traffic_downlink(email), 50);

    let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
    let mut client = stats_client(addr).await;

    let resp = client
        .get_users_stats(GetUsersStatsRequest {
            reset: true,
            include_traffic: true,
        })
        .await
        .expect("users stats")
        .into_inner();
    let traffic = resp.users[0].traffic.as_ref().expect("traffic");
    assert_eq!(traffic.uplink, 100);
    assert_eq!(traffic.downlink, 50);

    let resp = client
        .get_users_stats(GetUsersStatsRequest {
            reset: false,
            include_traffic: true,
        })
        .await
        .expect("users stats again")
        .into_inner();
    let traffic = resp.users[0].traffic.as_ref().expect("traffic");
    assert_eq!(traffic.uplink, 0);
    assert_eq!(traffic.downlink, 0);
    assert_eq!(
        registry
            .get_online_map(&user_online(email))
            .expect("map")
            .count(),
        1
    );
}

#[tokio::test]
async fn get_sys_stats_uptime_is_monotonic() {
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_stats_grpc_server(registry).await;
    let mut client = stats_client(addr).await;

    let first = client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("sys stats")
        .into_inner()
        .uptime;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("sys stats again")
        .into_inner()
        .uptime;
    assert!(second >= first);
}

#[tokio::test]
async fn authenticated_vless_tcp_session_records_stats_and_online() {
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    const USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    fn build_vless_tcp_request(user_id: &[u8; 16], port: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(user_id);
        buf.push(0);
        buf.push(0x01);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&[0x01, 127, 0, 0, 1]);
        buf
    }

    let state = test_stats_state();
    let registry = Arc::clone(&state.registry);
    let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
    let mut grpc = stats_client(addr).await;

    let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind outbound");
    let outbound_port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let _ = hold_rx.await;
        let _ = socket.shutdown().await;
    });

    let users = VlessUserManager::new(
        "vless-reality-in",
        vec![VlessClient {
            id: uuid::Uuid::from_bytes(USER_ID),
            email: Some("remna-user@example.test".to_string()),
            flow: None,
            level: Some(0),
        }],
    );

    let request = build_vless_tcp_request(&USER_ID, outbound_port);
    let (mut client_io, server_io) = duplex(8192);
    client_io.write_all(&request).await.expect("write request");

    let stats_state = state.clone();
    let source_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let relay = tokio::spawn(async move {
        handle_vless_tcp_inbound(server_io, &users, Some(&stats_state), Some(source_ip), None).await
    });

    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), client_io.read_exact(&mut header))
        .await
        .expect("response header timeout")
        .expect("response header");

    let online_name = user_online("remna-user@example.test");
    let online = grpc
        .get_stats_online(GetStatsRequest {
            name: online_name.clone(),
            reset: false,
        })
        .await
        .expect("online")
        .into_inner()
        .stat
        .expect("stat")
        .value;
    assert_eq!(online, 1);

    let users_resp = grpc
        .get_users_stats(GetUsersStatsRequest {
            reset: false,
            include_traffic: true,
        })
        .await
        .expect("users stats")
        .into_inner();
    assert_eq!(users_resp.users.len(), 1);
    assert_eq!(users_resp.users[0].email, "remna-user@example.test");
    assert!(users_resp.users[0]
        .ips
        .iter()
        .any(|entry| entry.ip == "203.0.113.10"));

    drop(hold_tx);
    client_io.shutdown().await.expect("shutdown client");
    tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay timeout")
        .expect("relay join")
        .expect("relay ok");

    let online = grpc
        .get_stats_online(GetStatsRequest {
            name: online_name,
            reset: false,
        })
        .await
        .expect("online after close")
        .into_inner()
        .stat
        .expect("stat")
        .value;
    assert_eq!(online, 0);
}

mod xhttp_stats {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use rust_xray::config::XHttpSettings;
    use rust_xray::transport::xhttp::serve_xhttp_stream_one;
    use rust_xray::vless::config::VlessClient;
    use rust_xray::vless::VlessUserManager;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    const USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    const TEST_SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

    fn xhttp_settings() -> XHttpSettings {
        XHttpSettings {
            path: "/xhttp".to_string(),
            host: Some("example.com".to_string()),
            ..XHttpSettings::default()
        }
    }

    fn test_users() -> Arc<VlessUserManager> {
        Arc::new(VlessUserManager::new(
            "vless-reality-in",
            vec![VlessClient {
                id: uuid::Uuid::from_bytes(USER_ID),
                email: Some("remna-user@example.test".to_string()),
                flow: None,
                level: Some(0),
            }],
        ))
    }

    fn build_vless_tcp_request(user_id: &[u8; 16], port: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(user_id);
        buf.push(0);
        buf.push(0x01);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&[0x01, 127, 0, 0, 1]);
        buf.extend_from_slice(payload);
        buf
    }

    fn http1_post_request(path: &str, host: &str, body: &[u8]) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect()
    }

    async fn spawn_outbound_hold() -> (tokio::sync::oneshot::Sender<()>, u16) {
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind outbound");
        let outbound_port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = hold_rx.await;
                let _ = socket.shutdown().await;
            }
        });
        (hold_tx, outbound_port)
    }

    async fn start_xhttp_session(
        state: &StatsState,
        source_ip: Option<IpAddr>,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<std::io::Result<()>>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (hold_tx, outbound_port) = spawn_outbound_hold().await;
        let vless_body = build_vless_tcp_request(&USER_ID, outbound_port, b"ping");
        let request = http1_post_request("/xhttp", "example.com", &vless_body);
        let (mut client_io, server_io) = duplex(8192);
        client_io.write_all(&request).await.expect("write request");

        let settings = xhttp_settings();
        let users = test_users();
        let stats_state = state.clone();
        let relay = tokio::spawn(async move {
            serve_xhttp_stream_one(
                server_io,
                &settings,
                users,
                Some(&stats_state),
                source_ip,
                None,
            )
            .await
        });

        let mut header = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), client_io.read_exact(&mut header))
            .await
            .expect("response header timeout")
            .expect("response header");

        (client_io, relay, hold_tx)
    }

    #[tokio::test]
    async fn xhttp_authenticated_session_tracks_online_ip() {
        let state = test_stats_state();
        let registry = Arc::clone(&state.registry);
        let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
        let mut grpc = stats_client(addr).await;

        let (mut client_io, relay, hold_tx) =
            start_xhttp_session(&state, Some(TEST_SOURCE_IP)).await;

        let online_name = user_online("remna-user@example.test");
        let online = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name.clone(),
                reset: false,
            })
            .await
            .expect("online")
            .into_inner()
            .stat
            .expect("stat")
            .value;
        assert_eq!(online, 1);

        let ips = grpc
            .get_stats_online_ip_list(GetStatsRequest {
                name: online_name.clone(),
                reset: false,
            })
            .await
            .expect("ip list")
            .into_inner()
            .ips;
        assert!(ips.contains_key("203.0.113.10"));

        let uplink = registry
            .get("user>>>remna-user@example.test>>>traffic>>>uplink", false)
            .unwrap_or(0);
        let downlink = registry
            .get("user>>>remna-user@example.test>>>traffic>>>downlink", false)
            .unwrap_or(0);
        assert!(uplink >= 0);
        assert!(downlink >= 0);

        drop(hold_tx);
        client_io.shutdown().await.expect("shutdown client");
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("relay timeout")
            .expect("relay join")
            .expect("relay ok");

        let online = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name,
                reset: false,
            })
            .await
            .expect("online after close")
            .into_inner()
            .stat
            .expect("stat")
            .value;
        assert_eq!(online, 0);
    }

    #[tokio::test]
    async fn xhttp_online_disabled_does_not_create_map() {
        let config: XrayConfig = serde_json::from_str(
            r#"{
                "stats": {},
                "policy": {
                    "levels": {
                        "0": {
                            "statsUserUplink": true,
                            "statsUserDownlink": true,
                            "statsUserOnline": false
                        }
                    }
                },
                "inbounds": []
            }"#,
        )
        .expect("parse config");
        let state = StatsState::from_xray_config(&config, Some("vless-reality-in".to_string()));
        let registry = Arc::clone(&state.registry);
        let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
        let mut grpc = stats_client(addr).await;

        let (mut client_io, relay, hold_tx) =
            start_xhttp_session(&state, Some(TEST_SOURCE_IP)).await;

        let online_name = user_online("remna-user@example.test");
        let err = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name.clone(),
                reset: false,
            })
            .await
            .expect_err("online map must not exist");
        assert_eq!(err.code(), Code::NotFound);
        assert!(registry.get_online_map(&online_name).is_none());

        assert!(
            registry
                .get("user>>>remna-user@example.test>>>traffic>>>uplink", false)
                .is_ok(),
            "traffic counters may exist independently of online tracking"
        );

        drop(hold_tx);
        client_io.shutdown().await.expect("shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
    }

    #[tokio::test]
    async fn xhttp_same_ip_refcount() {
        let state = test_stats_state();
        let registry = Arc::clone(&state.registry);
        let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
        let mut grpc = stats_client(addr).await;

        let (mut client_a, relay_a, hold_a) =
            start_xhttp_session(&state, Some(TEST_SOURCE_IP)).await;
        let (mut client_b, relay_b, hold_b) =
            start_xhttp_session(&state, Some(TEST_SOURCE_IP)).await;

        let online_name = user_online("remna-user@example.test");
        let online = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name.clone(),
                reset: false,
            })
            .await
            .expect("online")
            .into_inner()
            .stat
            .expect("stat")
            .value;
        assert_eq!(online, 1);

        drop(hold_a);
        client_a.shutdown().await.expect("shutdown a");
        let _ = tokio::time::timeout(Duration::from_secs(5), relay_a)
            .await
            .expect("relay a");

        let online = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name.clone(),
                reset: false,
            })
            .await
            .expect("online after first close")
            .into_inner()
            .stat
            .expect("stat")
            .value;
        assert_eq!(online, 1);

        drop(hold_b);
        client_b.shutdown().await.expect("shutdown b");
        let _ = tokio::time::timeout(Duration::from_secs(5), relay_b)
            .await
            .expect("relay b");

        let online = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name,
                reset: false,
            })
            .await
            .expect("online after both close")
            .into_inner()
            .stat
            .expect("stat")
            .value;
        assert_eq!(online, 0);
    }

    #[tokio::test]
    async fn xhttp_online_cleanup_on_client_abort() {
        let state = test_stats_state();
        let registry = Arc::clone(&state.registry);
        let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
        let mut grpc = stats_client(addr).await;

        let (hold_tx, outbound_port) = spawn_outbound_hold().await;
        let vless_body = build_vless_tcp_request(&USER_ID, outbound_port, b"abort");
        let request = http1_post_request("/xhttp", "example.com", &vless_body);
        let (client_io, server_io) = duplex(8192);
        let settings = xhttp_settings();
        let users = test_users();
        let stats_state = state.clone();
        let relay = tokio::spawn(async move {
            serve_xhttp_stream_one(
                server_io,
                &settings,
                users,
                Some(&stats_state),
                Some(TEST_SOURCE_IP),
                None,
            )
            .await
        });

        let write_task = tokio::spawn(async move {
            let mut client_io = client_io;
            client_io.write_all(&request).await.expect("write");
            let mut header = [0u8; 2];
            client_io.read_exact(&mut header).await.expect("header");
            client_io
        });

        let online_name = user_online("remna-user@example.test");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let online = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name.clone(),
                reset: false,
            })
            .await
            .expect("online")
            .into_inner()
            .stat
            .expect("stat")
            .value;
        assert_eq!(online, 1);

        drop(hold_tx);
        drop(write_task.await.expect("write task"));
        let _ = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("relay timeout");

        let online = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name,
                reset: false,
            })
            .await
            .expect("online after abort")
            .into_inner()
            .stat
            .expect("stat")
            .value;
        assert_eq!(online, 0);
    }

    #[tokio::test]
    async fn xhttp_stats_app_absent_does_not_collect() {
        let config: XrayConfig = serde_json::from_str(
            r#"{
                "policy": {
                    "levels": {
                        "0": {
                            "statsUserOnline": true,
                            "statsUserUplink": true
                        }
                    }
                },
                "inbounds": []
            }"#,
        )
        .expect("parse config");
        assert!(!StatsState::from_xray_config(&config, Some("in".to_string())).enabled());

        let state = StatsState::from_xray_config(&config, Some("vless-reality-in".to_string()));
        let registry = Arc::clone(&state.registry);
        let addr = spawn_stats_grpc_server(Arc::clone(&registry)).await;
        let mut grpc = stats_client(addr).await;

        let (mut client_io, relay, hold_tx) =
            start_xhttp_session(&state, Some(TEST_SOURCE_IP)).await;

        let online_name = user_online("remna-user@example.test");
        let err = grpc
            .get_stats_online(GetStatsRequest {
                name: online_name.clone(),
                reset: false,
            })
            .await
            .expect_err("stats manager absent");
        assert_eq!(err.code(), Code::NotFound);
        assert!(registry.get_online_map(&online_name).is_none());

        drop(hold_tx);
        client_io.shutdown().await.expect("shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
    }
}
