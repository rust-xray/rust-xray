use std::sync::Arc;

use prost::Message;
use rust_xray::api::proto::app::proxyman::command::handler_service_client::HandlerServiceClient;
use rust_xray::api::proto::app::proxyman::command::{
    AddUserOperation, AlterInboundRequest, GetInboundUserRequest, ListInboundsRequest,
    RemoveUserOperation,
};
use rust_xray::api::proto::common::protocol::User;
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::api::proto::proxy::vless::Account;
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::config::XrayConfig;
use rust_xray::runtime::HandlerRuntime;
use rust_xray::stats::{user_traffic_uplink, StatsRegistry, StatsState};
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::protocol::{VlessCommand, VlessDestination, VlessRequest};
use rust_xray::vless::user_manager::VlessUserManager;
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tonic::transport::Endpoint;
use tonic::Code;

const INBOUND_TAG: &str = "vless-reality-in";
const STATIC_ID: &str = "11111111-1111-1111-1111-111111111111";
const DYNAMIC_ID: &str = "22222222-2222-2222-2222-222222222222";

fn test_stats_state(registry: Arc<StatsRegistry>) -> StatsState {
    let config: XrayConfig =
        serde_json::from_str(include_str!("fixtures/remna/reality_vless_api_config.json"))
            .expect("parse remna fixture");
    let mut state = StatsState::from_xray_config(&config, Some(INBOUND_TAG.to_string()));
    state.registry = registry;
    state
}

async fn spawn_handler_server(
    manager: Arc<VlessUserManager>,
    stats_registry: Arc<StatsRegistry>,
) -> std::net::SocketAddr {
    let handler_runtime = HandlerRuntime::for_handler_tests(Arc::clone(&stats_registry));
    handler_runtime
        .inbound
        .user_managers()
        .register(Arc::clone(&manager));
    spawn_handler_server_with(handler_runtime, stats_registry).await
}

async fn spawn_handler_server_with(
    handler_runtime: Arc<HandlerRuntime>,
    stats_registry: Arc<StatsRegistry>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Handler],
            stats_registry,
            handler_runtime,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    addr
}

fn add_user_request(email: &str, id: &str, flow: &str) -> AlterInboundRequest {
    add_user_request_with(email, id, flow, 0, "none")
}

fn add_user_request_with(
    email: &str,
    id: &str,
    flow: &str,
    level: u32,
    encryption: &str,
) -> AlterInboundRequest {
    let account = Account {
        id: id.to_string(),
        flow: flow.to_string(),
        encryption: encryption.to_string(),
        ..Default::default()
    };
    let account_msg = TypedMessage {
        r#type: "xray.proxy.vless.Account".to_string(),
        value: account.encode_to_vec(),
    };
    let user = User {
        level,
        email: email.to_string(),
        account: Some(account_msg),
    };
    let add = AddUserOperation { user: Some(user) };
    AlterInboundRequest {
        tag: INBOUND_TAG.to_string(),
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
            value: add.encode_to_vec(),
        }),
    }
}

fn remove_user_request(email: &str) -> AlterInboundRequest {
    let remove = RemoveUserOperation {
        email: email.to_string(),
    };
    AlterInboundRequest {
        tag: INBOUND_TAG.to_string(),
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.RemoveUserOperation".to_string(),
            value: remove.encode_to_vec(),
        }),
    }
}

fn vless_request_for(id: uuid::Uuid) -> VlessRequest {
    VlessRequest {
        version: 0,
        user_id: id,
        command: VlessCommand::Tcp,
        destination: VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        additional_info: Vec::new(),
    }
}

#[tokio::test]
async fn alter_inbound_add_user_enables_vless_authentication() {
    let manager = Arc::new(VlessUserManager::new(
        INBOUND_TAG,
        vec![VlessClient {
            id: uuid::Uuid::parse_str(STATIC_ID).unwrap(),
            email: Some("static@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), Arc::clone(&registry)).await;

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);
    client
        .alter_inbound(add_user_request("dynamic@example.test", DYNAMIC_ID, ""))
        .await
        .expect("add user")
        .into_inner();

    let dynamic_uuid = uuid::Uuid::parse_str(DYNAMIC_ID).unwrap();
    let auth = manager
        .authenticate(&vless_request_for(dynamic_uuid))
        .expect("dynamic auth");
    assert_eq!(auth.email.as_deref(), Some("dynamic@example.test"));
}

#[tokio::test]
async fn alter_inbound_remove_user_disables_authentication() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    manager
        .add_user(rust_xray::vless::user_manager::ManagedUser {
            id: uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
            email: "dynamic@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        })
        .expect("seed user");

    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), Arc::clone(&registry)).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);
    client
        .alter_inbound(remove_user_request("dynamic@example.test"))
        .await
        .expect("remove user");

    let err = manager
        .authenticate(&vless_request_for(
            uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
        ))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn alter_inbound_duplicate_user_is_rejected() {
    let manager = Arc::new(VlessUserManager::new(
        INBOUND_TAG,
        vec![VlessClient {
            id: uuid::Uuid::parse_str(STATIC_ID).unwrap(),
            email: Some("static@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), registry).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);

    let err = client
        .alter_inbound(add_user_request("static@example.test", DYNAMIC_ID, ""))
        .await
        .expect_err("duplicate email");
    assert_eq!(err.code(), Code::AlreadyExists);
}

#[tokio::test]
async fn alter_inbound_unknown_tag_returns_not_found() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(manager, registry).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);

    let mut request = add_user_request("dynamic@example.test", DYNAMIC_ID, "");
    request.tag = "missing-inbound".to_string();
    let err = client.alter_inbound(request).await.expect_err("not found");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn alter_inbound_vmess_account_returns_unimplemented() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(manager, registry).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);

    let user = User {
        level: 0,
        email: "vmess@example.test".to_string(),
        account: Some(TypedMessage {
            r#type: "xray.proxy.vmess.Account".to_string(),
            value: b"not-a-real-vmess-account".to_vec(),
        }),
    };
    let add = AddUserOperation { user: Some(user) };
    let err = client
        .alter_inbound(AlterInboundRequest {
            tag: INBOUND_TAG.to_string(),
            operation: Some(TypedMessage {
                r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
                value: add.encode_to_vec(),
            }),
        })
        .await
        .expect_err("vmess unimplemented");
    assert_eq!(err.code(), Code::Unimplemented);
}

#[tokio::test]
async fn list_inbounds_returns_registered_vless_inbound_tag() {
    let manager = Arc::new(VlessUserManager::new(
        INBOUND_TAG,
        vec![VlessClient {
            id: uuid::Uuid::parse_str(STATIC_ID).unwrap(),
            email: Some("static@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(manager, registry).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);

    let resp = client
        .list_inbounds(ListInboundsRequest { is_only_tags: true })
        .await
        .expect("list inbounds")
        .into_inner();

    let tags: Vec<_> = resp
        .inbounds
        .iter()
        .map(|inbound| inbound.tag.as_str())
        .collect();
    assert_eq!(tags, vec![INBOUND_TAG]);
}

#[tokio::test]
async fn get_inbound_users_returns_static_and_dynamic_users() {
    let manager = Arc::new(VlessUserManager::new(
        INBOUND_TAG,
        vec![VlessClient {
            id: uuid::Uuid::parse_str(STATIC_ID).unwrap(),
            email: Some("static@example.test".to_string()),
            flow: Some("xtls-rprx-vision".to_string()),
            level: Some(0),
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    manager
        .add_user(rust_xray::vless::user_manager::ManagedUser {
            id: uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
            email: "dynamic@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        })
        .expect("seed dynamic user");

    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), registry).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);

    let resp = client
        .get_inbound_users(GetInboundUserRequest {
            tag: INBOUND_TAG.to_string(),
            email: String::new(),
        })
        .await
        .expect("get inbound users")
        .into_inner();

    assert_eq!(resp.users.len(), 2);
    let emails: Vec<_> = resp.users.iter().map(|user| user.email.as_str()).collect();
    assert!(emails.contains(&"static@example.test"));
    assert!(emails.contains(&"dynamic@example.test"));

    for user in &resp.users {
        let account = user.account.as_ref().expect("vless account");
        assert_eq!(account.r#type, "xray.proxy.vless.Account");
        let decoded = Account::decode(account.value.as_slice()).expect("decode account");
        assert!(!decoded.id.is_empty());
    }
}

#[tokio::test]
async fn get_inbound_users_count_tracks_add_and_remove() {
    let manager = Arc::new(VlessUserManager::new(
        INBOUND_TAG,
        vec![VlessClient {
            id: uuid::Uuid::parse_str(STATIC_ID).unwrap(),
            email: Some("static@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), registry).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);

    async fn user_count(client: &mut HandlerServiceClient<tonic::transport::Channel>) -> i64 {
        client
            .get_inbound_users_count(GetInboundUserRequest {
                tag: INBOUND_TAG.to_string(),
                email: String::new(),
            })
            .await
            .expect("get inbound users count")
            .into_inner()
            .count
    }

    assert_eq!(user_count(&mut client).await, 1);

    client
        .alter_inbound(add_user_request("dynamic@example.test", DYNAMIC_ID, ""))
        .await
        .expect("add user");
    assert_eq!(user_count(&mut client).await, 2);

    client
        .alter_inbound(remove_user_request("dynamic@example.test"))
        .await
        .expect("remove user");
    assert_eq!(user_count(&mut client).await, 1);
}

#[tokio::test]
async fn get_inbound_users_unknown_tag_returns_not_found() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(manager, registry).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);

    let err = client
        .get_inbound_users(GetInboundUserRequest {
            tag: "missing-inbound".to_string(),
            email: String::new(),
        })
        .await
        .expect_err("not found");
    assert_eq!(err.code(), Code::NotFound);

    let err = client
        .get_inbound_users_count(GetInboundUserRequest {
            tag: "missing-inbound".to_string(),
            email: String::new(),
        })
        .await
        .expect_err("not found");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn added_user_email_is_used_for_stats_counters() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let registry = Arc::new(StatsRegistry::new());
    let stats_state = test_stats_state(Arc::clone(&registry));
    let addr = spawn_handler_server(Arc::clone(&manager), Arc::clone(&registry)).await;

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = HandlerServiceClient::new(channel);
    client
        .alter_inbound(add_user_request("dynamic@example.test", DYNAMIC_ID, ""))
        .await
        .expect("add user");

    let auth = manager
        .authenticate(&vless_request_for(
            uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
        ))
        .expect("auth");
    let session = stats_state
        .session(auth.email, auth.level, None)
        .expect("stats session");
    session.record_uplink(42);

    let counter = user_traffic_uplink("dynamic@example.test");
    assert_eq!(registry.get(&counter, false).unwrap(), 42);
}

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

async fn vless_tcp_auth_succeeds(manager: Arc<VlessUserManager>, user_id: uuid::Uuid) -> bool {
    vless_tcp_auth_result(manager, user_id).await.is_ok()
}

async fn vless_tcp_auth_result(
    manager: Arc<VlessUserManager>,
    user_id: uuid::Uuid,
) -> std::io::Result<()> {
    use rust_xray::vless::handle_vless_tcp_inbound;
    use tokio::io::duplex;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let outbound_port = listener.local_addr()?.port();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
        }
    });

    let request = build_vless_tcp_request(user_id.as_bytes(), outbound_port);
    let (mut client_io, server_io) = duplex(8192);
    client_io.write_all(&request).await?;
    let relay = tokio::spawn(async move {
        handle_vless_tcp_inbound(server_io, manager.as_ref(), None, None, None).await
    });
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let _ = client_io.read(&mut buf).await;
        let _ = client_io.shutdown().await;
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), relay)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "relay timeout"))?
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "relay join failed"))?
}

#[tokio::test]
async fn add_user_via_wire_enables_immediate_vless_tcp_auth() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let dynamic_uuid = uuid::Uuid::parse_str(DYNAMIC_ID).unwrap();
    assert!(
        !vless_tcp_auth_succeeds(Arc::clone(&manager), dynamic_uuid).await,
        "auth must fail before AddUser"
    );

    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), Arc::clone(&registry)).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .alter_inbound(add_user_request("dynamic@example.test", DYNAMIC_ID, ""))
        .await
        .expect("add user");

    assert!(
        vless_tcp_auth_succeeds(Arc::clone(&manager), dynamic_uuid).await,
        "auth must succeed immediately after AddUser"
    );
}

#[tokio::test]
async fn remove_user_via_wire_disables_new_vless_tcp_auth() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    manager
        .add_user(rust_xray::vless::user_manager::ManagedUser {
            id: uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
            email: "dynamic@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        })
        .expect("seed");

    let dynamic_uuid = uuid::Uuid::parse_str(DYNAMIC_ID).unwrap();
    assert!(vless_tcp_auth_succeeds(Arc::clone(&manager), dynamic_uuid).await);

    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), registry).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .alter_inbound(remove_user_request("dynamic@example.test"))
        .await
        .expect("remove user");

    assert!(
        !vless_tcp_auth_succeeds(Arc::clone(&manager), dynamic_uuid).await,
        "new auth must fail after RemoveUser"
    );
}

#[tokio::test]
async fn alter_inbound_remove_missing_user_returns_not_found() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(manager, registry).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    let err = client
        .alter_inbound(remove_user_request("missing@example.test"))
        .await
        .expect_err("missing user");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn alter_inbound_duplicate_uuid_is_rejected() {
    let manager = Arc::new(VlessUserManager::new(
        INBOUND_TAG,
        vec![VlessClient {
            id: uuid::Uuid::parse_str(STATIC_ID).unwrap(),
            email: Some("static@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(manager, registry).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    let err = client
        .alter_inbound(add_user_request("other@example.test", STATIC_ID, ""))
        .await
        .expect_err("duplicate uuid");
    assert_eq!(err.code(), Code::AlreadyExists);
}

#[tokio::test]
async fn get_inbound_users_round_trip_preserves_vision_flow_and_level() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), registry).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .alter_inbound(add_user_request_with(
            "stage8c@example.com",
            DYNAMIC_ID,
            "xtls-rprx-vision",
            1,
            "none",
        ))
        .await
        .expect("add user");

    let resp = client
        .get_inbound_users(GetInboundUserRequest {
            tag: INBOUND_TAG.to_string(),
            email: "stage8c@example.com".to_string(),
        })
        .await
        .expect("get user")
        .into_inner();
    assert_eq!(resp.users.len(), 1);
    assert_eq!(resp.users[0].email, "stage8c@example.com");
    assert_eq!(resp.users[0].level, 1);
    let account = resp.users[0].account.as_ref().expect("account");
    assert_eq!(account.r#type, "xray.proxy.vless.Account");
    let decoded = Account::decode(account.value.as_slice()).expect("decode");
    assert_eq!(decoded.id, DYNAMIC_ID);
    assert_eq!(decoded.flow, "xtls-rprx-vision");
    assert_eq!(decoded.encryption, "none");
}

#[tokio::test]
async fn add_custom_string_vless_id_via_wire_authenticates() {
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let custom_id = "remna-custom-id";
    let expected_uuid = rust_xray::vless::config::parse_vless_user_id(custom_id).expect("uuid");
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), registry).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .alter_inbound(add_user_request("custom@example.test", custom_id, ""))
        .await
        .expect("add user");
    assert!(
        vless_tcp_auth_succeeds(Arc::clone(&manager), expected_uuid).await,
        "custom-string id must authenticate"
    );
}

#[tokio::test]
async fn remove_static_user_via_api() {
    let manager = Arc::new(VlessUserManager::new(
        INBOUND_TAG,
        vec![VlessClient {
            id: uuid::Uuid::parse_str(STATIC_ID).unwrap(),
            email: Some("static@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), registry).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .alter_inbound(remove_user_request("static@example.test"))
        .await
        .expect("remove static");

    let resp = client
        .get_inbound_users(GetInboundUserRequest {
            tag: INBOUND_TAG.to_string(),
            email: String::new(),
        })
        .await
        .expect("get users")
        .into_inner();
    assert!(resp.users.is_empty());
    assert!(
        !vless_tcp_auth_succeeds(
            Arc::clone(&manager),
            uuid::Uuid::parse_str(STATIC_ID).unwrap(),
        )
        .await
    );
}

#[tokio::test]
async fn tag_isolation_remove_does_not_affect_other_inbound() {
    let manager_a = Arc::new(VlessUserManager::new(
        "inbound-a",
        vec![VlessClient {
            id: uuid::Uuid::parse_str(STATIC_ID).unwrap(),
            email: Some("shared@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let manager_b = Arc::new(VlessUserManager::new(
        "inbound-b",
        vec![VlessClient {
            id: uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
            email: Some("shared@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let registry = Arc::new(StatsRegistry::new());
    let handler_runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    handler_runtime
        .inbound
        .user_managers()
        .register(Arc::clone(&manager_a));
    handler_runtime
        .inbound
        .user_managers()
        .register(Arc::clone(&manager_b));

    let addr = spawn_handler_server_with(handler_runtime, registry).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );

    let mut remove = remove_user_request("shared@example.test");
    remove.tag = "inbound-a".to_string();
    client.alter_inbound(remove).await.expect("remove from a");

    assert!(
        !vless_tcp_auth_succeeds(
            Arc::clone(&manager_a),
            uuid::Uuid::parse_str(STATIC_ID).unwrap(),
        )
        .await
    );
    assert!(
        vless_tcp_auth_succeeds(
            Arc::clone(&manager_b),
            uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
        )
        .await
    );
}

#[tokio::test]
async fn dynamic_user_level_applies_stats_online_policy() {
    use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
    use rust_xray::api::proto::app::stats::command::GetStatsRequest;
    use rust_xray::api::server::ApiService;
    use rust_xray::stats::user_online;

    let config: XrayConfig = serde_json::from_str(
        r#"{
            "stats": {},
            "policy": {
                "levels": {
                    "0": {},
                    "1": {
                        "statsUserOnline": true,
                        "statsUserUplink": true
                    }
                }
            },
            "inbounds": []
        }"#,
    )
    .expect("parse");
    let stats_state = StatsState::from_xray_config(&config, Some(INBOUND_TAG.to_string()));
    let registry = Arc::clone(&stats_state.registry);

    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let handler_runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    handler_runtime
        .inbound
        .user_managers()
        .register(Arc::clone(&manager));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Handler, ApiService::Stats],
            registry,
            handler_runtime,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut handler = HandlerServiceClient::new(channel.clone());
    let mut stats = StatsServiceClient::new(channel);

    handler
        .alter_inbound(add_user_request_with(
            "level1@example.test",
            DYNAMIC_ID,
            "",
            1,
            "none",
        ))
        .await
        .expect("add user");

    let auth = manager
        .authenticate(&vless_request_for(
            uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
        ))
        .expect("auth");
    let session = stats_state
        .session(
            auth.email,
            auth.level,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        )
        .expect("session");
    let _guard = session.begin_session().expect("online");

    let online = stats
        .get_stats_online(GetStatsRequest {
            name: user_online("level1@example.test"),
            reset: false,
        })
        .await
        .expect("online")
        .into_inner()
        .stat
        .expect("stat")
        .value;
    assert_eq!(online, 1);
}

#[tokio::test]
async fn remove_user_while_connected_preserves_online_until_session_end() {
    use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
    use rust_xray::api::proto::app::stats::command::GetStatsRequest;
    use rust_xray::api::server::ApiService;
    use rust_xray::stats::user_online;

    let stats_state = test_stats_state(Arc::new(StatsRegistry::new()));
    let registry = Arc::clone(&stats_state.registry);
    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let handler_runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    handler_runtime
        .inbound
        .user_managers()
        .register(Arc::clone(&manager));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Handler, ApiService::Stats],
            registry,
            handler_runtime,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut handler = HandlerServiceClient::new(channel.clone());
    let mut stats = StatsServiceClient::new(channel);

    handler
        .alter_inbound(add_user_request("online@example.test", DYNAMIC_ID, ""))
        .await
        .expect("add user");

    let auth = manager
        .authenticate(&vless_request_for(
            uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
        ))
        .expect("auth");
    let session = stats_state
        .session(
            auth.email,
            auth.level,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        )
        .expect("session");
    let guard = session.begin_session().expect("online");

    handler
        .alter_inbound(remove_user_request("online@example.test"))
        .await
        .expect("remove user");

    let online_name = user_online("online@example.test");
    let online = stats
        .get_stats_online(GetStatsRequest {
            name: online_name.clone(),
            reset: false,
        })
        .await
        .expect("online while session alive")
        .into_inner()
        .stat
        .expect("stat")
        .value;
    assert_eq!(online, 1);

    assert!(
        !vless_tcp_auth_succeeds(
            Arc::clone(&manager),
            uuid::Uuid::parse_str(DYNAMIC_ID).unwrap(),
        )
        .await
    );

    drop(guard);
    let online = stats
        .get_stats_online(GetStatsRequest {
            name: online_name,
            reset: false,
        })
        .await
        .expect("online after session end")
        .into_inner()
        .stat
        .expect("stat")
        .value;
    assert_eq!(online, 0);
}

#[tokio::test]
async fn dynamic_user_authenticates_over_xhttp_production_path() {
    use rust_xray::config::XHttpSettings;
    use rust_xray::transport::xhttp::serve_xhttp_stream_one;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    let manager = Arc::new(VlessUserManager::new(INBOUND_TAG, vec![]));
    let registry = Arc::new(StatsRegistry::new());
    let addr = spawn_handler_server(Arc::clone(&manager), registry).await;
    let mut client = HandlerServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    client
        .alter_inbound(add_user_request(
            "xhttp-dynamic@example.test",
            DYNAMIC_ID,
            "",
        ))
        .await
        .expect("add user");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind outbound");
    let outbound_port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
        }
    });

    let user_id = uuid::Uuid::parse_str(DYNAMIC_ID).unwrap();
    let mut vless_body = build_vless_tcp_request(user_id.as_bytes(), outbound_port);
    let request = format!(
        "POST /xhttp HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
        vless_body.len()
    );
    let mut request_bytes = request.into_bytes();
    request_bytes.append(&mut vless_body);

    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        host: Some("example.com".to_string()),
        ..XHttpSettings::default()
    };
    let (mut client_io, server_io) = duplex(8192);
    let users = Arc::clone(&manager);
    let bridge = tokio::spawn(async move {
        serve_xhttp_stream_one(
            server_io,
            &settings,
            users,
            None,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            None,
        )
        .await
    });
    client_io.write_all(&request_bytes).await.expect("write");
    let mut header = [0u8; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client_io.read_exact(&mut header),
    )
    .await
    .expect("xhttp response timeout")
    .expect("xhttp response header");
    client_io.shutdown().await.ok();
    bridge.await.expect("join").expect("xhttp bridge ok");
}
