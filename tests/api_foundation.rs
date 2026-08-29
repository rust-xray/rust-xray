//! Stage 8A gRPC API foundation tests (transport-level, reflection, descriptor set).

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use prost_types::FileDescriptorSet;
use rust_xray::api::proto::app::proxyman::command::handler_service_client::HandlerServiceClient;
use rust_xray::api::proto::app::proxyman::command::handler_service_server::HandlerServiceServer;
use rust_xray::api::proto::app::proxyman::command::ListInboundsRequest;
use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::stats_service_server::StatsServiceServer;
use rust_xray::api::proto::app::stats::command::{GetStatsRequest, SysStatsRequest};
use rust_xray::api::proto::FILE_DESCRIPTOR_SET;
use rust_xray::api::server::{
    bind_api_listener, parse_enabled_services, serve_grpc_on, ApiService, ApiTransportMode,
};
use rust_xray::api::stats::StatsServiceImpl;
use rust_xray::runtime::HandlerRuntime;
use rust_xray::stats::StatsRegistry;
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tonic::server::NamedService;
use tonic::transport::Endpoint;
use tonic::Code;
use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1::ServerReflectionRequest;

async fn spawn_plaintext_server(services: Vec<ApiService>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let registry = Arc::new(StatsRegistry::new());
    let inbound_users =
        HandlerRuntime::for_handler_tests(Arc::new(rust_xray::stats::StatsRegistry::new()));
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
    tokio::time::sleep(Duration::from_millis(30)).await;
    addr
}

async fn connect_plaintext(addr: std::net::SocketAddr) -> tonic::transport::Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(Duration::from_secs(2))
        .connect()
        .await
        .expect("connect")
}

#[test]
fn descriptor_set_includes_required_canonical_services() {
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("decode descriptor set");
    let service_names: Vec<String> = set
        .file
        .iter()
        .flat_map(|file| file.service.iter())
        .filter_map(|service| service.name.clone())
        .collect();

    for required in [
        "StatsService",
        "HandlerService",
        "LoggerService",
        "RoutingService",
    ] {
        assert!(
            service_names.iter().any(|name| name == required),
            "descriptor set missing service {required}: {service_names:?}"
        );
    }
}

#[test]
fn canonical_stats_service_grpc_path() {
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

#[test]
fn canonical_handler_service_grpc_path() {
    assert_eq!(
        HandlerServiceServer::<rust_xray::api::handler::HandlerServiceImpl>::NAME,
        "xray.app.proxyman.command.HandlerService"
    );
}

#[tokio::test]
async fn plaintext_server_get_sys_stats_over_canonical_path() {
    let addr = spawn_plaintext_server(vec![ApiService::Stats]).await;
    let channel = connect_plaintext(addr).await;
    let mut client = StatsServiceClient::new(channel);
    let resp = client
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("/xray.app.stats.command.StatsService/GetSysStats")
        .into_inner();
    assert!(resp.uptime <= 5);
}

#[tokio::test]
async fn reflection_enabled_exposes_configured_services() {
    let addr = spawn_plaintext_server(vec![
        ApiService::Reflection,
        ApiService::Stats,
        ApiService::Handler,
    ])
    .await;
    let channel = connect_plaintext(addr).await;
    let mut client = ServerReflectionClient::new(channel);
    let request = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    };
    let mut stream = client
        .server_reflection_info(tokio_stream::once(request))
        .await
        .expect("reflection stream")
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
    assert!(listed.iter().any(|name| name.contains("HandlerService")));
}

#[tokio::test]
async fn reflection_disabled_when_not_configured() {
    let addr = spawn_plaintext_server(vec![ApiService::Stats]).await;
    let channel = connect_plaintext(addr).await;
    let mut client = ServerReflectionClient::new(channel);
    let request = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    };
    let err = client
        .server_reflection_info(tokio_stream::once(request))
        .await
        .expect_err("reflection must be absent");
    assert_eq!(err.code(), Code::Unimplemented);
}

#[tokio::test]
async fn service_filtering_stats_only_does_not_mount_handler() {
    let addr = spawn_plaintext_server(vec![ApiService::Stats]).await;
    let channel = connect_plaintext(addr).await;

    let mut stats = StatsServiceClient::new(channel.clone());
    stats
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("stats mounted");

    let mut handler = HandlerServiceClient::new(channel);
    let err = handler
        .list_inbounds(ListInboundsRequest {
            is_only_tags: false,
        })
        .await
        .expect_err("handler must not be mounted");
    assert_eq!(err.code(), Code::Unimplemented);
}

#[tokio::test]
async fn service_filtering_handler_only_does_not_mount_stats() {
    let enabled = parse_enabled_services(&["HandlerService".to_string()]).expect("parse");
    assert_eq!(enabled, vec![ApiService::Handler]);

    let addr = spawn_plaintext_server(vec![ApiService::Handler]).await;
    let channel = connect_plaintext(addr).await;

    let mut handler = HandlerServiceClient::new(channel.clone());
    handler
        .list_inbounds(ListInboundsRequest {
            is_only_tags: false,
        })
        .await
        .expect("handler mounted");

    let mut stats = StatsServiceClient::new(channel);
    let err = stats
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect_err("stats must not be mounted");
    assert_eq!(err.code(), Code::Unimplemented);
}

#[tokio::test]
async fn bind_api_listener_surfaces_clear_error_when_port_taken() {
    let (listener, bound) = bind_api_listener("127.0.0.1:0")
        .await
        .expect("bind first listener");
    let listen = format!("127.0.0.1:{}", bound.port());
    let err = bind_api_listener(&listen).await.unwrap_err();
    assert!(
        err.to_string().contains("failed to bind Xray API listener"),
        "unexpected error: {err}"
    );
    drop(listener);
}

#[tokio::test]
async fn malformed_get_stats_empty_name_returns_grpc_status_not_panic() {
    let addr = spawn_plaintext_server(vec![ApiService::Stats]).await;
    let channel = connect_plaintext(addr).await;
    let mut client = StatsServiceClient::new(channel);
    let err = client
        .get_stats(GetStatsRequest {
            name: String::new(),
            reset: false,
        })
        .await
        .expect_err("empty stat name");
    assert_eq!(err.code(), Code::NotFound);
}
