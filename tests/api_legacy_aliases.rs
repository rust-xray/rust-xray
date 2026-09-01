//! Stage 8E5-B legacy v2ray.core gRPC service alias and reflection parity tests.

#[path = "routing_e2e_harness.rs"]
mod harness;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use harness::{
    build_vless_ip_request, connect_routing_clients, inbound_rule_message,
    routing_context_for_vless_tcp, setup_routing_runtime, spawn_routing_server, tonic_add_rule,
    DEFAULT_USER_ID,
};
use http::uri::PathAndQuery;
use prost::Message;
use prost_types::FileDescriptorSet;
use rust_xray::api::legacy_alias::{
    CANONICAL_HANDLER_SERVICE, CANONICAL_LOGGER_SERVICE, CANONICAL_OBSERVATORY_SERVICE,
    CANONICAL_ROUTING_SERVICE, CANONICAL_STATS_SERVICE, LEGACY_HANDLER_SERVICE,
    LEGACY_LOGGER_SERVICE, LEGACY_OBSERVATORY_SERVICE, LEGACY_ROUTING_SERVICE,
    LEGACY_STATS_SERVICE,
};
use rust_xray::api::proto::app::log::command::{RestartLoggerRequest, RestartLoggerResponse};
use rust_xray::api::proto::app::observatory::command::{
    GetOutboundStatusRequest, GetOutboundStatusResponse,
};
use rust_xray::api::proto::app::proxyman::command::handler_service_client::HandlerServiceClient;
use rust_xray::api::proto::app::proxyman::command::{
    AddUserOperation, AlterInboundRequest, GetInboundUserRequest, ListInboundsRequest,
    ListInboundsResponse,
};
use rust_xray::api::proto::app::router::command::routing_service_client::RoutingServiceClient;
use rust_xray::api::proto::app::router::command::{
    RoutingContext, SubscribeRoutingStatsRequest, TestRouteRequest,
};
use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::{
    GetStatsRequest, GetStatsResponse, SysStatsRequest, SysStatsResponse,
};
use rust_xray::api::proto::common::protocol::User;
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::api::proto::proxy::vless::Account;
use rust_xray::api::proto::FILE_DESCRIPTOR_SET;
use rust_xray::api::reflection::descriptor_set_contains_legacy_api_symbols;
use rust_xray::api::server::{
    parse_enabled_services, serve_grpc_incoming, serve_grpc_on, start_configured_api_server,
    ApiService, ApiTransportMode,
};
use rust_xray::cli::{Command, RunOptions};
use rust_xray::config::xray::raw::{ApiConfig, OutboundObject, XrayConfig};
use rust_xray::logging::{init_logging_with_config, LogOutputSpec, LoggerRuntimeConfig};
use rust_xray::observatory::ObservatoryRuntimeConfig;
use rust_xray::routing::RouteSocketMeta;
use rust_xray::runtime::{encode_freedom_outbound, CommanderOutboundListener, HandlerRuntime};
use rust_xray::stats::StatsRegistry;
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::handle_vless_tcp_inbound_with_socket_meta;
use rust_xray::vless::user_manager::VlessUserManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tonic::client::Grpc;
use tonic::codec::ProstCodec;
use tonic::transport::Endpoint;
use tonic::{Code, Request, Response, Status};
use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1::ServerReflectionRequest;
use tower::service_fn;

const HANDLER_INBOUND_TAG: &str = "vless-reality-in";

static LEGACY_LOGGER_INIT: OnceLock<()> = OnceLock::new();

fn ensure_test_logging() {
    LEGACY_LOGGER_INIT.get_or_init(|| {
        let guard = init_logging_with_config(
            &Command::Run(RunOptions {
                config: "test.json".into(),
                format: None,
            }),
            LoggerRuntimeConfig {
                error: LogOutputSpec::console(),
                access: LogOutputSpec::none(),
                dns_log: false,
            },
        )
        .expect("init logging");
        std::mem::forget(guard);
    });
}

async fn spawn_api_with(
    services: Vec<ApiService>,
    registry: Arc<StatsRegistry>,
    runtime: Arc<HandlerRuntime>,
) -> (SocketAddr, tokio::task::JoinHandle<std::io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(serve_grpc_on(
        listener,
        services,
        registry,
        runtime,
        ApiTransportMode::Plaintext,
    ));
    sleep(Duration::from_millis(40)).await;
    (addr, task)
}

async fn spawn_api(
    services: Vec<ApiService>,
) -> (SocketAddr, tokio::task::JoinHandle<std::io::Result<()>>) {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    spawn_api_with(services, registry, runtime).await
}

fn build_observatory_runtime(registry: Arc<StatsRegistry>) -> Arc<HandlerRuntime> {
    HandlerRuntime::for_observatory_tests(
        registry,
        ObservatoryRuntimeConfig::for_test(
            vec!["direct".to_string()],
            "http://127.0.0.1:1/",
            Duration::from_millis(50),
            false,
        ),
        vec![encode_freedom_outbound("direct")],
    )
}

async fn connect_tcp(addr: SocketAddr) -> tonic::transport::Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(2))
        .connect()
        .await
        .expect("connect")
}

async fn legacy_unary<Req, Resp>(
    channel: tonic::transport::Channel,
    path: &str,
    request: Req,
) -> Result<Response<Resp>, Status>
where
    Req: prost::Message + 'static,
    Resp: prost::Message + Default + 'static,
{
    let path = PathAndQuery::from_str(path).expect("path");
    let mut grpc = Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|err| Status::unknown(format!("grpc client not ready: {err}")))?;
    grpc.unary(Request::new(request), path, ProstCodec::default())
        .await
}

async fn legacy_server_stream<Req, Resp>(
    channel: tonic::transport::Channel,
    path: &str,
    request: Req,
) -> Result<tonic::Streaming<Resp>, Status>
where
    Req: prost::Message + 'static,
    Resp: prost::Message + Default + 'static,
{
    let path = PathAndQuery::from_str(path).expect("path");
    let mut grpc = Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|err| Status::unknown(format!("grpc client not ready: {err}")))?;
    grpc.server_streaming(Request::new(request), path, ProstCodec::default())
        .await
        .map(|response| response.into_inner())
}

async fn reflection_list_services(channel: tonic::transport::Channel) -> Vec<String> {
    let mut client = ServerReflectionClient::new(channel);
    let request = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    };
    let mut stream = client
        .server_reflection_info(tokio_stream::once(request))
        .await
        .expect("reflection")
        .into_inner();
    let mut listed = Vec::new();
    while let Some(message) = stream.next().await {
        let message = message.expect("message");
        if let Some(tonic_reflection::pb::v1::server_reflection_response::MessageResponse::ListServicesResponse(
            list,
        )) = message.message_response
        {
            listed.extend(list.service.into_iter().map(|service| service.name));
        }
    }
    listed
}

async fn reflection_file_for_symbol(
    channel: tonic::transport::Channel,
    symbol: &str,
) -> Result<(), Status> {
    let mut client = ServerReflectionClient::new(channel);
    let request = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::FileContainingSymbol(symbol.to_string())),
    };
    let mut stream = client
        .server_reflection_info(tokio_stream::once(request))
        .await?
        .into_inner();
    while let Some(message) = stream.next().await {
        message?;
    }
    Ok(())
}

#[tokio::test]
async fn legacy_handler_rpc_works() {
    let (addr, task) = spawn_api(vec![ApiService::Handler]).await;
    let channel = connect_tcp(addr).await;
    let _: ListInboundsResponse = legacy_unary(
        channel,
        "/v2ray.core.app.proxyman.command.HandlerService/ListInbounds",
        ListInboundsRequest::default(),
    )
    .await
    .expect("legacy ListInbounds")
    .into_inner();
    task.abort();
}

#[tokio::test]
async fn legacy_stats_rpc_works() {
    let (addr, task) = spawn_api(vec![ApiService::Stats]).await;
    let channel = connect_tcp(addr).await;
    let _: SysStatsResponse = legacy_unary(
        channel,
        "/v2ray.core.app.stats.command.StatsService/GetSysStats",
        SysStatsRequest {},
    )
    .await
    .expect("legacy GetSysStats")
    .into_inner();
    task.abort();
}

#[tokio::test]
async fn legacy_routing_rpc_works() {
    let runtime = setup_routing_runtime().await;
    let addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut _handler, mut routing) = connect_routing_clients(addr).await;
    tonic_add_rule(
        &mut routing,
        inbound_rule_message("vless-in", "direct-b", "legacy-test-rule"),
    )
    .await;
    let channel = connect_tcp(addr).await;
    let ctx = routing_context_for_vless_tcp(
        "vless-in",
        "user@example.test",
        &uuid::Uuid::from_bytes(DEFAULT_USER_ID),
        "example.com",
        443,
        "http",
    );
    let _: RoutingContext = legacy_unary(
        channel,
        "/v2ray.core.app.router.command.RoutingService/TestRoute",
        TestRouteRequest {
            routing_context: Some(ctx),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        },
    )
    .await
    .expect("legacy TestRoute")
    .into_inner();
}

#[tokio::test]
async fn legacy_routing_stream_rpc_works() {
    let (addr, task) = spawn_api(vec![ApiService::Routing]).await;
    let channel = connect_tcp(addr).await;
    let err = legacy_server_stream::<_, RoutingContext>(
        channel,
        "/v2ray.core.app.router.command.RoutingService/SubscribeRoutingStats",
        SubscribeRoutingStatsRequest {
            field_selectors: vec![],
        },
    )
    .await
    .expect_err("legacy subscribe with routing stats disabled");
    assert_eq!(err.code(), Code::Internal);
    assert!(err.message().contains("Routing statistics not enabled"));
    task.abort();
}

#[tokio::test]
async fn legacy_logger_rpc_works() {
    ensure_test_logging();
    let (addr, task) = spawn_api(vec![ApiService::Logger]).await;
    let channel = connect_tcp(addr).await;
    let _: RestartLoggerResponse = legacy_unary(
        channel,
        "/v2ray.core.app.log.command.LoggerService/RestartLogger",
        RestartLoggerRequest {},
    )
    .await
    .expect("legacy RestartLogger")
    .into_inner();
    task.abort();
}

#[tokio::test]
async fn observatory_has_no_legacy_alias() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = build_observatory_runtime(Arc::clone(&registry));
    let (addr, task) = spawn_api_with(vec![ApiService::Observatory], registry, runtime).await;
    let channel = connect_tcp(addr).await;
    let _: GetOutboundStatusResponse = legacy_unary(
        channel.clone(),
        "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus",
        GetOutboundStatusRequest {},
    )
    .await
    .expect("canonical observatory")
    .into_inner();
    let err = legacy_unary::<_, GetOutboundStatusResponse>(
        channel,
        "/v2ray.core.app.observatory.command.ObservatoryService/GetOutboundStatus",
        GetOutboundStatusRequest {},
    )
    .await
    .expect_err("legacy observatory alias must be absent");
    assert_eq!(err.code(), Code::Unimplemented);
    task.abort();
}

#[tokio::test]
async fn canonical_and_legacy_handler_share_state() {
    let manager = Arc::new(VlessUserManager::new(HANDLER_INBOUND_TAG, vec![]));
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    runtime
        .inbound
        .user_managers()
        .register(Arc::clone(&manager));
    let (addr, task) = spawn_api_with(vec![ApiService::Handler], registry, runtime).await;
    let channel = connect_tcp(addr).await;
    let mut canonical = HandlerServiceClient::new(channel.clone());
    let account = Account {
        id: "11111111-1111-1111-1111-111111111111".to_string(),
        ..Default::default()
    };
    let user = User {
        email: "legacy-alias@example.test".to_string(),
        account: Some(TypedMessage {
            r#type: "xray.proxy.vless.Account".to_string(),
            value: account.encode_to_vec(),
        }),
        ..Default::default()
    };
    canonical
        .alter_inbound(AlterInboundRequest {
            tag: HANDLER_INBOUND_TAG.to_string(),
            operation: Some(TypedMessage {
                r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
                value: AddUserOperation {
                    user: Some(user.clone()),
                }
                .encode_to_vec(),
            }),
        })
        .await
        .expect("canonical add user");

    let legacy_users =
        legacy_unary::<_, rust_xray::api::proto::app::proxyman::command::GetInboundUserResponse>(
            channel,
            "/v2ray.core.app.proxyman.command.HandlerService/GetInboundUsers",
            GetInboundUserRequest {
                tag: HANDLER_INBOUND_TAG.to_string(),
                email: "legacy-alias@example.test".to_string(),
            },
        )
        .await
        .expect("legacy get users")
        .into_inner();
    assert_eq!(legacy_users.users.len(), 1);
    assert_eq!(legacy_users.users[0].email, "legacy-alias@example.test");
    task.abort();
}

#[tokio::test]
async fn canonical_and_legacy_stats_share_state() {
    let registry = Arc::new(StatsRegistry::new());
    let counter_name = "user>>>alias@example.test>>>traffic>>>uplink";
    registry.ensure(counter_name);
    registry.add(counter_name, 7);
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let (addr, task) = spawn_api_with(vec![ApiService::Stats], registry, runtime).await;
    let channel = connect_tcp(addr).await;
    let mut canonical = StatsServiceClient::new(channel.clone());
    let legacy_before: GetStatsResponse = legacy_unary(
        channel.clone(),
        "/v2ray.core.app.stats.command.StatsService/GetStats",
        GetStatsRequest {
            name: "user>>>alias@example.test>>>traffic>>>uplink".to_string(),
            reset: false,
        },
    )
    .await
    .expect("legacy get")
    .into_inner();
    assert_eq!(legacy_before.stat.unwrap().value, 7);
    let canonical_reset = canonical
        .get_stats(GetStatsRequest {
            name: "user>>>alias@example.test>>>traffic>>>uplink".to_string(),
            reset: true,
        })
        .await
        .expect("canonical reset get")
        .into_inner();
    assert_eq!(canonical_reset.stat.unwrap().value, 7);
    let legacy_after: GetStatsResponse = legacy_unary(
        channel,
        "/v2ray.core.app.stats.command.StatsService/GetStats",
        GetStatsRequest {
            name: "user>>>alias@example.test>>>traffic>>>uplink".to_string(),
            reset: false,
        },
    )
    .await
    .expect("legacy get after reset")
    .into_inner();
    assert_eq!(legacy_after.stat.unwrap().value, 0);
    task.abort();
}

#[tokio::test]
async fn canonical_and_legacy_routing_share_state() {
    let runtime = setup_routing_runtime().await;
    let addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut _handler, mut routing) = connect_routing_clients(addr).await;
    tonic_add_rule(
        &mut routing,
        inbound_rule_message("vless-in", "direct-b", "legacy-alias-rule"),
    )
    .await;
    let channel = connect_tcp(addr).await;
    let ctx = routing_context_for_vless_tcp(
        "vless-in",
        "user@example.test",
        &uuid::Uuid::from_bytes(DEFAULT_USER_ID),
        "legacy-alias.example",
        443,
        "http",
    );
    let mut canonical = RoutingServiceClient::new(channel.clone());
    let canonical_route = canonical
        .test_route(TestRouteRequest {
            routing_context: Some(ctx.clone()),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("canonical route")
        .into_inner();
    let legacy_route = legacy_unary::<_, RoutingContext>(
        channel,
        "/v2ray.core.app.router.command.RoutingService/TestRoute",
        TestRouteRequest {
            routing_context: Some(ctx),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        },
    )
    .await
    .expect("legacy route")
    .into_inner();
    assert_eq!(legacy_route.outbound_tag, canonical_route.outbound_tag);
}

#[tokio::test]
async fn reflection_lists_legacy_aliases() {
    ensure_test_logging();
    let registry = Arc::new(StatsRegistry::new());
    let runtime = build_observatory_runtime(Arc::clone(&registry));
    let (addr, task) = spawn_api_with(
        vec![
            ApiService::Reflection,
            ApiService::Handler,
            ApiService::Stats,
            ApiService::Routing,
            ApiService::Logger,
            ApiService::Observatory,
        ],
        registry,
        runtime,
    )
    .await;
    let channel = connect_tcp(addr).await;
    let listed = reflection_list_services(channel).await;
    let set: HashSet<_> = listed.into_iter().collect();
    for required in [
        CANONICAL_HANDLER_SERVICE,
        LEGACY_HANDLER_SERVICE,
        CANONICAL_STATS_SERVICE,
        LEGACY_STATS_SERVICE,
        CANONICAL_ROUTING_SERVICE,
        LEGACY_ROUTING_SERVICE,
        CANONICAL_LOGGER_SERVICE,
        LEGACY_LOGGER_SERVICE,
        CANONICAL_OBSERVATORY_SERVICE,
        "grpc.reflection.v1.ServerReflection",
        "grpc.reflection.v1alpha.ServerReflection",
    ] {
        assert!(
            set.contains(required),
            "missing reflection service {required}"
        );
    }
    assert!(!set.contains(LEGACY_OBSERVATORY_SERVICE));
    task.abort();
}

#[tokio::test]
async fn reflection_canonical_symbol_resolves() {
    let (addr, task) = spawn_api(vec![ApiService::Reflection, ApiService::Stats]).await;
    let channel = connect_tcp(addr).await;
    reflection_file_for_symbol(channel.clone(), CANONICAL_STATS_SERVICE)
        .await
        .expect("canonical service symbol");
    reflection_file_for_symbol(channel, "xray.app.stats.command.StatsService.GetSysStats")
        .await
        .expect("canonical method symbol");
    task.abort();
}

#[tokio::test]
async fn reflection_legacy_symbol_does_not_resolve() {
    let (addr, task) = spawn_api(vec![ApiService::Reflection, ApiService::Stats]).await;
    let channel = connect_tcp(addr).await;
    let err = reflection_file_for_symbol(channel.clone(), LEGACY_STATS_SERVICE)
        .await
        .expect_err("legacy service symbol");
    assert_eq!(err.code(), Code::NotFound);
    let err = reflection_file_for_symbol(
        channel,
        "v2ray.core.app.stats.command.StatsService.GetSysStats",
    )
    .await
    .expect_err("legacy method symbol");
    assert_eq!(err.code(), Code::NotFound);
    task.abort();
}

#[tokio::test]
async fn reflection_grpcurl_paradox_legacy_listed_but_symbol_not_found() {
    let (addr, task) = spawn_api(vec![ApiService::Reflection, ApiService::Stats]).await;
    let channel = connect_tcp(addr).await;
    let listed = reflection_list_services(channel.clone()).await;
    assert!(listed.iter().any(|name| name == LEGACY_STATS_SERVICE));
    let err = reflection_file_for_symbol(channel, LEGACY_STATS_SERVICE)
        .await
        .expect_err("legacy symbol paradox");
    assert_eq!(err.code(), Code::NotFound);
    task.abort();
}

#[test]
fn descriptor_set_has_no_legacy_api_symbols() {
    assert!(!descriptor_set_contains_legacy_api_symbols());
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("decode");
    let packages: Vec<_> = set
        .file
        .iter()
        .filter_map(|file| file.package.clone())
        .collect();
    assert!(!packages
        .iter()
        .any(|package| package.starts_with("v2ray.core")));
}

#[test]
fn legacy_full_service_name_in_api_services_is_ignored() {
    let enabled = parse_enabled_services(&[
        "v2ray.core.app.stats.command.StatsService".to_string(),
        "StatsService".to_string(),
    ])
    .expect("parse");
    assert_eq!(enabled, vec![ApiService::Stats]);
}

#[tokio::test]
async fn legacy_alias_direct_tcp() {
    let (addr, task) = spawn_api(vec![ApiService::Stats]).await;
    let channel = connect_tcp(addr).await;
    let _: SysStatsResponse = legacy_unary(
        channel,
        "/v2ray.core.app.stats.command.StatsService/GetSysStats",
        SysStatsRequest {},
    )
    .await
    .expect("legacy GetSysStats over direct TCP")
    .into_inner();
    task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn legacy_alias_filesystem_unix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("legacy-api.sock");
    let path_str = path.to_str().expect("utf8");
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let config = XrayConfig {
        log: None,
        api: Some(ApiConfig {
            tag: "api".to_string(),
            listen: Some(path_str.to_string()),
            services: vec!["StatsService".to_string()],
        }),
        dns: None,
        stats: None,
        policy: None,
        routing: None,
        observatory: None,
        burst_observatory: None,
        outbounds: vec![OutboundObject {
            tag: Some("api".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        }],
        inbounds: Vec::new(),
        extra: Default::default(),
    };
    let startup = start_configured_api_server("", &config, runtime, registry)
        .await
        .expect("start")
        .expect("startup");
    sleep(Duration::from_millis(40)).await;
    let path_owned = path_str.to_string();
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let path_owned = path_owned.clone();
            async move {
                UnixStream::connect(path_owned)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .expect("unix connect");
    let _: SysStatsResponse = legacy_unary(
        channel,
        "/v2ray.core.app.stats.command.StatsService/GetSysStats",
        SysStatsRequest {},
    )
    .await
    .expect("legacy unix GetSysStats")
    .into_inner();
    startup.task.abort();
}

#[tokio::test]
async fn legacy_alias_internal_commander() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_handler, mut routing) = connect_routing_clients(grpc_addr).await;
    tonic_add_rule(
        &mut routing,
        inbound_rule_message("route-api-in", "api", "legacy-commander-rule"),
    )
    .await;

    let (listener, incoming) = CommanderOutboundListener::pair();
    runtime
        .outbound
        .install_commander_outbound("api", Arc::clone(&listener))
        .expect("commander");
    tokio::spawn(serve_grpc_incoming(
        incoming,
        vec![ApiService::Stats],
        Arc::clone(&registry),
        runtime.clone(),
        ApiTransportMode::Plaintext,
    ));

    let users = Arc::new(VlessUserManager::new(
        "route-api-in",
        vec![VlessClient {
            id: uuid::Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("legacy-commander@example.test".to_string()),
            flow: None,
            level: None,
            testseed: rust_xray::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    runtime.inbound.user_managers().register(Arc::clone(&users));
    let vless_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let vless_addr = vless_listener.local_addr().expect("addr");
    let router = Arc::clone(&runtime.router);
    tokio::spawn(async move {
        while let Ok((stream, _)) = vless_listener.accept().await {
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
    sleep(Duration::from_millis(40)).await;

    let mut stream = TcpStream::connect(vless_addr).await.expect("connect");
    stream
        .write_all(&build_vless_ip_request(&DEFAULT_USER_ID, 1))
        .await
        .expect("vless");
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.expect("vless resp");
    let stream = Arc::new(std::sync::Mutex::new(Some(stream)));
    let stream_for_conn = Arc::clone(&stream);
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let stream_for_conn = Arc::clone(&stream_for_conn);
            async move {
                let stream = stream_for_conn
                    .lock()
                    .expect("lock")
                    .take()
                    .expect("stream");
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("commander channel");
    let _: SysStatsResponse = legacy_unary(
        channel,
        "/v2ray.core.app.stats.command.StatsService/GetSysStats",
        SysStatsRequest {},
    )
    .await
    .expect("legacy commander GetSysStats")
    .into_inner();
}

#[tokio::test]
async fn legacy_aliases_not_mounted_without_service_config() {
    let (addr, task) = spawn_api(vec![]).await;
    let channel = connect_tcp(addr).await;
    let err = legacy_unary::<_, SysStatsResponse>(
        channel,
        "/v2ray.core.app.stats.command.StatsService/GetSysStats",
        SysStatsRequest {},
    )
    .await
    .expect_err("stats not mounted");
    assert_ne!(err.code(), Code::Ok);
    task.abort();
}

#[cfg(all(unix, target_os = "linux"))]
async fn connect_tonic_linux_abstract(name: &str) -> tonic::transport::Channel {
    use std::os::unix::io::FromRawFd;

    let abstract_name = name.trim_start_matches('@').to_string();
    Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let abstract_name = abstract_name.clone();
            async move {
                let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                let path_len = abstract_name
                    .len()
                    .min(addr.sun_path.len().saturating_sub(1));
                addr.sun_path[0] = 0;
                for (idx, byte) in abstract_name.as_bytes().iter().take(path_len).enumerate() {
                    addr.sun_path[idx + 1] = *byte as libc::c_char;
                }
                let addr_len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + path_len;
                let connect_result = unsafe {
                    libc::connect(fd, (&raw const addr).cast(), addr_len as libc::socklen_t)
                };
                if connect_result != 0 {
                    let err = std::io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    return Err(err);
                }
                let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                stream.set_nonblocking(true)?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                    tokio::net::UnixStream::from_std(stream)?,
                ))
            }
        }))
        .await
        .expect("connect abstract unix")
}

/// Linux-only: legacy StatsService over `@abstract-api-name` direct listen (not run on Darwin).
#[cfg(all(unix, target_os = "linux"))]
#[tokio::test]
async fn legacy_alias_linux_abstract_unix() {
    let name = format!("@rust-xray-legacy-alias-{}", std::process::id());
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let config = XrayConfig {
        log: None,
        api: Some(ApiConfig {
            tag: "api".to_string(),
            listen: Some(name.clone()),
            services: vec!["StatsService".to_string()],
        }),
        dns: None,
        stats: None,
        policy: None,
        routing: None,
        observatory: None,
        burst_observatory: None,
        outbounds: vec![OutboundObject {
            tag: Some("api".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        }],
        inbounds: Vec::new(),
        extra: Default::default(),
    };
    let startup = start_configured_api_server("", &config, runtime, registry)
        .await
        .expect("start")
        .expect("startup");
    sleep(Duration::from_millis(50)).await;
    let channel = connect_tonic_linux_abstract(&name).await;
    let _: SysStatsResponse = legacy_unary(
        channel,
        "/v2ray.core.app.stats.command.StatsService/GetSysStats",
        SysStatsRequest {},
    )
    .await
    .expect("legacy GetSysStats over linux abstract unix")
    .into_inner();
    startup.task.abort();
}
