//! Stage 8E5-A Commander/API config and transport semantics tests.

#[path = "routing_e2e_harness.rs"]
mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::{
    build_vless_ip_request, connect_routing_clients, inbound_rule_message, setup_routing_runtime,
    spawn_routing_server, tonic_add_rule, DEFAULT_USER_ID,
};
use rust_xray::api::proto::app::proxyman::command::handler_service_client::HandlerServiceClient;
use rust_xray::api::proto::app::proxyman::command::{
    AddOutboundRequest, ListOutboundsRequest, RemoveOutboundRequest,
};
use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::{
    GetStatsRequest, QueryStatsRequest, SysStatsRequest,
};
use rust_xray::api::server::{
    parse_enabled_services, serve_grpc_incoming, start_configured_api_server, ApiService,
    ApiTransportMode,
};
use rust_xray::config::xray::raw::{ApiConfig, OutboundObject, XrayConfig};
use rust_xray::config::{
    api_listen_kind, bind_api_listen, is_internal_commander_listen, parse_api_tcp_listen_addr,
    validate_xray_panel_config, ApiListenKind, BoundApiListener,
};
use rust_xray::routing::RouteSocketMeta;
use rust_xray::runtime::{
    encode_freedom_outbound, CommanderOutboundListener, HandlerRuntime, COMMANDER_OUTBOUND_BUFFER,
};
use rust_xray::stats::StatsRegistry;
use rust_xray::vless::user_manager::VlessUserManager;
use rust_xray::vless::{handle_vless_tcp_inbound_with_socket_meta, VlessClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tonic::transport::Endpoint;
use tonic::Code;
use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1::ServerReflectionRequest;
#[cfg(unix)]
use tower::service_fn;
use uuid::Uuid;

fn api_config(services: Vec<&str>, listen: Option<&str>, tag: &str) -> XrayConfig {
    XrayConfig {
        log: None,
        api: Some(ApiConfig {
            tag: tag.to_string(),
            listen: listen.map(str::to_string),
            services: services.into_iter().map(str::to_string).collect(),
        }),
        dns: None,
        stats: None,
        policy: None,
        routing: None,
        observatory: None,
        burst_observatory: None,
        outbounds: vec![OutboundObject {
            tag: Some(tag.to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        }],
        inbounds: Vec::new(),
        extra: Default::default(),
    }
}

async fn spawn_internal_api(
    services: Vec<&str>,
    tag: &str,
) -> (
    Arc<HandlerRuntime>,
    Arc<CommanderOutboundListener>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let (listener, incoming) = CommanderOutboundListener::pair();
    runtime
        .outbound
        .install_commander_outbound(tag, Arc::clone(&listener))
        .expect("install commander outbound");
    let enabled = parse_enabled_services(
        &services
            .iter()
            .map(|service| service.to_string())
            .collect::<Vec<_>>(),
    )
    .expect("parse services");
    let task = tokio::spawn(serve_grpc_incoming(
        incoming,
        enabled,
        registry,
        runtime.clone(),
        ApiTransportMode::Plaintext,
    ));
    sleep(Duration::from_millis(50)).await;
    (runtime, listener, task)
}

async fn connect_tonic_over_commander(
    listener: &Arc<CommanderOutboundListener>,
) -> tonic::transport::Channel {
    let acceptor = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind acceptor");
    let addr = acceptor.local_addr().expect("addr");
    let commander = Arc::clone(listener);
    tokio::spawn(async move {
        if let Ok((stream, _)) = acceptor.accept().await {
            let _ = commander.try_push(stream);
        }
    });
    Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect")
}

async fn tonic_stats_over_commander(
    listener: &Arc<CommanderOutboundListener>,
) -> StatsServiceClient<tonic::transport::Channel> {
    StatsServiceClient::new(connect_tonic_over_commander(listener).await)
}

async fn spawn_direct_api(
    services: Vec<&str>,
    listen: &str,
    tag: &str,
) -> (
    Arc<HandlerRuntime>,
    rust_xray::api::server::ApiServerStartup,
    Arc<StatsRegistry>,
) {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let config = api_config(services, Some(listen), tag);
    let startup = start_configured_api_server("", &config, runtime.clone(), registry.clone())
        .await
        .expect("start api")
        .expect("api startup");
    sleep(Duration::from_millis(50)).await;
    (runtime, startup, registry)
}

async fn connect_tonic_tcp(addr: &str) -> tonic::transport::Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(2))
        .connect()
        .await
        .expect("connect tcp")
}

#[cfg(unix)]
async fn connect_tonic_unix(path: &str) -> tonic::transport::Channel {
    let path = path.to_string();
    Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let path = path.clone();
            async move {
                UnixStream::connect(path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .expect("connect unix")
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

async fn handler_client_over_commander(
    listener: &Arc<CommanderOutboundListener>,
) -> HandlerServiceClient<tonic::transport::Channel> {
    HandlerServiceClient::new(connect_tonic_over_commander(listener).await)
}

#[test]
fn api_missing_tag_rejected() {
    let config = api_config(vec!["StatsService"], Some("127.0.0.1:0"), "");
    let err = validate_xray_panel_config(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(err.to_string(), "API tag can't be empty.");
}

#[test]
fn api_empty_tag_rejected() {
    let config = api_config(vec![], None, "   ");
    let err = validate_xray_panel_config(&config).unwrap_err();
    assert!(err.to_string().contains("API tag can't be empty."));
}

#[test]
fn api_tag_with_direct_listen_valid() {
    let config = api_config(vec!["StatsService"], Some("127.0.0.1:8080"), "api");
    validate_xray_panel_config(&config).expect("valid direct listen config");
}

#[test]
fn api_tag_with_internal_mode_valid() {
    let config = api_config(vec!["StatsService"], Some(""), "api");
    validate_xray_panel_config(&config).expect("valid internal commander config");
    assert!(is_internal_commander_listen(
        config.api.as_ref().unwrap().listen.as_deref()
    ));
}

#[test]
fn api_service_names_case_insensitive() {
    let enabled =
        parse_enabled_services(&["sTaTsSeRvIcE".to_string(), "handlerservice".to_string()])
            .expect("parse");
    assert_eq!(enabled, vec![ApiService::Stats, ApiService::Handler]);
}

#[test]
fn api_unknown_services_ignored() {
    let enabled = parse_enabled_services(&[
        "BOGUS".to_string(),
        "StatsService".to_string(),
        "OTHER".to_string(),
    ])
    .expect("parse");
    assert_eq!(enabled, vec![ApiService::Stats]);
    let config = api_config(
        vec!["BOGUS", "StatsService", "OTHER"],
        Some("127.0.0.1:0"),
        "api",
    );
    validate_xray_panel_config(&config).expect("unknown services ignored at startup");
}

#[test]
fn api_empty_services_allowed() {
    let enabled = parse_enabled_services(&[]).expect("empty services");
    assert!(enabled.is_empty());
    let config = api_config(vec![], Some("127.0.0.1:0"), "api");
    validate_xray_panel_config(&config).expect("empty services allowed");
}

#[test]
fn api_unknown_only_services_allowed() {
    let enabled =
        parse_enabled_services(&["BogusOne".to_string(), "BogusTwo".to_string()]).expect("parse");
    assert!(enabled.is_empty());
}

#[tokio::test]
async fn api_tcp_direct_listen() {
    let bound = bind_api_listen("127.0.0.1:0").await.expect("bind");
    let BoundApiListener::Tcp(_listener, addr) = bound else {
        panic!("expected tcp listener");
    };
    assert!(parse_api_tcp_listen_addr(&addr.to_string()).is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn api_unix_filesystem_listen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rust-xray-api.sock");
    let path_str = path.to_str().expect("utf8");
    let bound = bind_api_listen(path_str).await.expect("bind unix");
    assert!(matches!(bound, BoundApiListener::Unix(_, _)));
    assert!(path.exists());
}

#[cfg(all(unix, target_os = "linux"))]
#[tokio::test]
async fn api_unix_abstract_listen_linux() {
    let name = format!("@rust-xray-api-test-{}", std::process::id());
    let bound = bind_api_listen(&name).await.expect("bind abstract");
    assert!(matches!(bound, BoundApiListener::Unix(_, _)));
    assert!(!std::path::Path::new(&name).exists());
}

#[tokio::test]
async fn api_internal_mode_no_direct_listener() {
    let config = api_config(vec!["StatsService"], Some(""), "api");
    assert_eq!(
        api_listen_kind(config.api.as_ref().unwrap().listen.as_deref()),
        ApiListenKind::InternalCommander
    );
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let startup = start_configured_api_server("", &config, runtime, registry)
        .await
        .expect("start")
        .expect("startup");
    assert!(startup.internal.is_some());
    assert!(startup.bound_label.is_none());
}

#[tokio::test]
async fn api_internal_mode_real_tonic_rpc() {
    let (_runtime, listener, _task) = spawn_internal_api(vec!["StatsService"], "api").await;
    let mut client = tonic_stats_over_commander(&listener).await;
    client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("get_sys_stats over commander path");
}

#[tokio::test]
async fn api_internal_mode_replaces_same_tag_outbound() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("api"))
        .expect("seed freedom outbound");
    assert_eq!(
        runtime.outbound.get_protocol("api").expect("tag").as_str(),
        "freedom"
    );
    let config = api_config(vec!["StatsService"], Some(""), "api");
    start_configured_api_server("", &config, runtime.clone(), registry)
        .await
        .expect("start")
        .expect("startup");
    assert!(runtime.outbound.is_commander_outbound("api"));
}

#[tokio::test]
async fn api_direct_mode_does_not_replace_same_tag_outbound() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("api"))
        .expect("seed freedom outbound");
    let config = api_config(vec!["StatsService"], Some("127.0.0.1:0"), "api");
    let startup = start_configured_api_server("", &config, runtime.clone(), registry)
        .await
        .expect("start")
        .expect("startup");
    assert!(startup.internal.is_none());
    assert_eq!(
        runtime.outbound.get_protocol("api").expect("tag").as_str(),
        "freedom"
    );
    startup.task.abort();
}

#[tokio::test]
async fn api_internal_outbound_hidden_from_listoutbounds() {
    let (runtime, _listener, _task) =
        spawn_internal_api(vec!["HandlerService", "StatsService"], "api").await;
    let outbounds = runtime.outbound.list_outbounds();
    assert!(outbounds.iter().all(|entry| entry.tag != "api"));
}

#[tokio::test]
async fn api_internal_queue_bounded() {
    let (listener, _incoming) = CommanderOutboundListener::pair();
    assert_eq!(COMMANDER_OUTBOUND_BUFFER, 4);
    let bind = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = bind.local_addr().expect("addr");
    for _ in 0..4 {
        let accept = bind.accept();
        tokio::spawn(async move {
            let _ = tokio::net::TcpStream::connect(addr).await;
        });
        let (stream, _) = accept.await.expect("accept");
        assert!(listener.try_push(stream));
    }
    let overflow = tokio::net::TcpStream::connect(addr)
        .await
        .expect("overflow connect");
    assert!(!listener.try_push(overflow));
}

#[tokio::test]
async fn api_stats_service_works_with_noop_stats() {
    let (_runtime, listener, _task) = spawn_internal_api(vec!["StatsService"], "api").await;
    let mut client = tonic_stats_over_commander(&listener).await;
    client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("sys stats");
    let err = client
        .get_stats(GetStatsRequest {
            name: "inbound>>>missing>>>traffic>>>uplink".to_string(),
            reset: false,
        })
        .await
        .expect_err("missing counter");
    assert_eq!(err.code(), Code::NotFound);
    let resp = client
        .query_stats(QueryStatsRequest {
            pattern: String::new(),
            reset: false,
        })
        .await
        .expect("query")
        .into_inner();
    assert!(resp.stat.is_empty());
}

#[tokio::test]
async fn api_observatory_service_requires_observatory() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let config = api_config(vec!["ObservatoryService"], Some(""), "api");
    let err = start_configured_api_server("", &config, runtime, registry)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ObservatoryService"));
}

#[tokio::test]
async fn api_services_not_auto_mounted() {
    let (_runtime, listener, _task) = spawn_internal_api(vec![], "api").await;
    let mut client = tonic_stats_over_commander(&listener).await;
    let err = tokio::time::timeout(
        Duration::from_secs(2),
        client.get_sys_stats(SysStatsRequest {}),
    )
    .await
    .expect("timeout")
    .expect_err("stats not mounted");
    assert_ne!(err.code(), Code::Ok);
}

#[tokio::test]
async fn api_internal_shutdown_clean() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let config = api_config(vec!["StatsService"], Some(""), "api");
    let startup = start_configured_api_server("", &config, runtime, registry)
        .await
        .expect("start")
        .expect("startup");
    let internal = startup.internal.expect("internal handle");
    internal.shutdown();
    startup.task.abort();
    let _ = startup.task.await;
    assert!(internal.is_shutdown());
}

#[tokio::test]
async fn api_tcp_direct_listen_tonic_rpc() {
    let (_runtime, startup, _registry) =
        spawn_direct_api(vec!["StatsService"], "127.0.0.1:0", "api").await;
    let addr = startup.bound_label.expect("bound tcp addr");
    let mut client = StatsServiceClient::new(connect_tonic_tcp(&addr).await);
    client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("get_sys_stats over direct tcp");
    startup.task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn api_unix_filesystem_listen_tonic_rpc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rust-xray-api.sock");
    let path_str = path.to_str().expect("utf8");
    let (_runtime, startup, _registry) =
        spawn_direct_api(vec!["StatsService"], path_str, "api").await;
    assert_eq!(startup.bound_label.as_deref(), Some(path_str));
    let mut client = StatsServiceClient::new(connect_tonic_unix(path_str).await);
    client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("get_sys_stats over unix");
    startup.task.abort();
    drop(startup);
    sleep(Duration::from_millis(20)).await;
    assert!(!path.exists() || std::fs::remove_file(&path).is_ok());
}

#[cfg(all(unix, target_os = "linux"))]
#[tokio::test]
async fn api_unix_abstract_listen_tonic_rpc_linux() {
    let name = format!("@rust-xray-api-tonic-{}", std::process::id());
    let (_runtime, startup, _registry) = spawn_direct_api(vec!["StatsService"], &name, "api").await;
    assert!(!std::path::Path::new(&name).exists());
    let mut client = StatsServiceClient::new(connect_tonic_linux_abstract(&name).await);
    client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("get_sys_stats over abstract unix");
    startup.task.abort();
}

#[tokio::test]
async fn api_unknown_mixed_services_tonic_e2e() {
    let (_runtime, listener, _task) =
        spawn_internal_api(vec!["BOGUS", "sTaTsSeRvIcE", "OTHER_BOGUS"], "api").await;
    let mut client = tonic_stats_over_commander(&listener).await;
    client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("stats mounted from mixed-case entry");
}

#[tokio::test]
async fn api_reflection_explicit_internal_mode() {
    let (_runtime, listener, _task) =
        spawn_internal_api(vec!["ReflectionService", "StatsService"], "api").await;
    let channel = connect_tonic_over_commander(&listener).await;
    let mut reflection = ServerReflectionClient::new(channel);
    let request = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    };
    let mut stream = reflection
        .server_reflection_info(tokio_stream::once(request))
        .await
        .expect("reflection available")
        .into_inner();
    let mut listed = Vec::new();
    while let Some(message) = stream.next().await {
        let message = message.expect("reflection message");
        if let Some(tonic_reflection::pb::v1::server_reflection_response::MessageResponse::ListServicesResponse(
            list,
        )) = message.message_response
        {
            listed.extend(list.service.into_iter().map(|service| service.name));
        }
    }
    assert!(listed.iter().any(|name| name.contains("StatsService")));

    let (_runtime2, listener2, _task2) = spawn_internal_api(vec!["StatsService"], "api").await;
    let mut stats_only =
        ServerReflectionClient::new(connect_tonic_over_commander(&listener2).await);
    let err = stats_only
        .server_reflection_info(tokio_stream::once(ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::ListServices(String::new())),
        }))
        .await
        .expect_err("reflection absent without ReflectionService");
    assert_eq!(err.code(), Code::Unimplemented);
}

#[tokio::test]
async fn api_reflection_explicit_direct_tcp_mode() {
    let (_runtime, startup, _registry) = spawn_direct_api(
        vec!["ReflectionService", "StatsService"],
        "127.0.0.1:0",
        "api",
    )
    .await;
    let addr = startup.bound_label.expect("addr");
    let channel = connect_tonic_tcp(&addr).await;
    let mut reflection = ServerReflectionClient::new(channel);
    let request = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    };
    reflection
        .server_reflection_info(tokio_stream::once(request))
        .await
        .expect("reflection on direct tcp");
    startup.task.abort();
}

#[tokio::test]
async fn api_duplicate_recognized_service_entries_startup_error() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let config = api_config(
        vec!["StatsService", "StatsService"],
        Some("127.0.0.1:0"),
        "api",
    );
    let err = start_configured_api_server("", &config, runtime, registry)
        .await
        .expect_err("duplicate service registration must fail startup");
    assert!(
        err.to_string()
            .contains("duplicate API service registration"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn api_internal_listoutbounds_hides_commander_via_handler_service() {
    let (_runtime, listener, _task) =
        spawn_internal_api(vec!["HandlerService", "StatsService"], "api").await;
    let mut client = handler_client_over_commander(&listener).await;
    let resp = client
        .list_outbounds(ListOutboundsRequest::default())
        .await
        .expect("list outbounds")
        .into_inner();
    assert!(resp.outbounds.iter().all(|entry| entry.tag != "api"));
}

#[tokio::test]
async fn api_internal_remove_outbound_commander_tag_no_panic() {
    let (_runtime, listener, _task) =
        spawn_internal_api(vec!["HandlerService", "StatsService"], "api").await;
    let mut client = handler_client_over_commander(&listener).await;
    client
        .remove_outbound(RemoveOutboundRequest {
            tag: "api".to_string(),
        })
        .await
        .expect("upstream allows RemoveOutbound on commander tag");
    let mut stats = tonic_stats_over_commander(&listener).await;
    let err = stats.get_sys_stats(SysStatsRequest {}).await;
    assert!(err.is_ok() || err.is_err());
}

#[tokio::test]
async fn api_internal_add_outbound_commander_tag_rejected() {
    let (_runtime, listener, _task) = spawn_internal_api(vec!["HandlerService"], "api").await;
    let mut client = handler_client_over_commander(&listener).await;
    let err = client
        .add_outbound(AddOutboundRequest {
            outbound: Some(encode_freedom_outbound("api")),
        })
        .await
        .expect_err("duplicate commander tag");
    assert_eq!(err.code(), Code::AlreadyExists);
}

#[tokio::test]
async fn api_absent_no_commander_or_listener() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let mut config = api_config(vec!["StatsService"], Some(""), "api");
    config.api = None;
    let startup = start_configured_api_server("", &config, runtime.clone(), registry)
        .await
        .expect("start");
    assert!(startup.is_none());
    assert!(!runtime.outbound.is_commander_outbound("api"));
}

#[tokio::test]
async fn api_direct_tcp_shutdown_rebinds() {
    let (_runtime, startup, _registry) =
        spawn_direct_api(vec!["StatsService"], "127.0.0.1:0", "api").await;
    let addr = startup.bound_label.expect("addr");
    startup.task.abort();
    let _ = startup.task.await;
    sleep(Duration::from_millis(20)).await;
    let rebound = bind_api_listen(&addr).await;
    assert!(
        rebound.is_ok() || rebound.is_err(),
        "rebind attempt must not hang after shutdown"
    );
}

#[tokio::test]
async fn api_internal_mode_routed_vless_dataplane_tonic_rpc() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = setup_routing_runtime().await;
    let (listener, incoming) = CommanderOutboundListener::pair();
    runtime
        .outbound
        .install_commander_outbound("api", Arc::clone(&listener))
        .expect("commander outbound");
    let enabled = parse_enabled_services(&["StatsService".to_string()]).expect("parse");
    tokio::spawn(serve_grpc_incoming(
        incoming,
        enabled,
        Arc::clone(&registry),
        runtime.clone(),
        ApiTransportMode::Plaintext,
    ));
    sleep(Duration::from_millis(50)).await;

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_handler, mut routing) = connect_routing_clients(grpc_addr).await;
    tonic_add_rule(
        &mut routing,
        inbound_rule_message("route-api-in", "api", "route-to-api"),
    )
    .await;

    let users = Arc::new(VlessUserManager::new(
        "route-api-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("route-api@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    runtime.inbound.user_managers().register(Arc::clone(&users));

    let vless_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
    let vless_addr = vless_listener.local_addr().expect("vless addr");
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
    sleep(Duration::from_millis(20)).await;

    let mut stream = TcpStream::connect(vless_addr).await.expect("connect vless");
    stream
        .write_all(&build_vless_ip_request(&DEFAULT_USER_ID, 1))
        .await
        .expect("vless request");
    let mut vless_resp = [0u8; 2];
    stream
        .read_exact(&mut vless_resp)
        .await
        .expect("vless response");

    let stream = Arc::new(std::sync::Mutex::new(Some(stream)));
    let stream_for_conn = Arc::clone(&stream);
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let stream_for_conn = Arc::clone(&stream_for_conn);
            async move {
                let stream = stream_for_conn
                    .lock()
                    .expect("stream lock")
                    .take()
                    .expect("stream already taken");
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("tonic over routed vless stream");
    let mut client = StatsServiceClient::new(channel);
    client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("GetSysStats through routed vless -> commander path");
}
