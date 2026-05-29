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
use rust_xray::api::server::{serve_grpc_on, ApiService};
use rust_xray::config::XrayConfig;
use rust_xray::runtime::InboundUserManagers;
use rust_xray::stats::{user_traffic_uplink, StatsRegistry, StatsState};
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::protocol::{VlessCommand, VlessDestination, VlessRequest};
use rust_xray::vless::user_manager::VlessUserManager;
use std::net::{IpAddr, Ipv4Addr};
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
    let inbound_users = Arc::new(InboundUserManagers::new());
    inbound_users.register(Arc::clone(&manager));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Handler],
            stats_registry,
            inbound_users,
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    addr
}

fn add_user_request(email: &str, id: &str, flow: &str) -> AlterInboundRequest {
    let account = Account {
        id: id.to_string(),
        flow: flow.to_string(),
        ..Default::default()
    };
    let account_msg = TypedMessage {
        r#type: "xray.proxy.vless.Account".to_string(),
        value: account.encode_to_vec(),
    };
    let user = User {
        level: 0,
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
        .session(auth.email, auth.level)
        .expect("stats session");
    session.record_uplink(42);

    let counter = user_traffic_uplink("dynamic@example.test");
    assert_eq!(registry.get(&counter, false).unwrap(), 42);
}
