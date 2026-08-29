//! Stage 8E4-A Standard Observatory runtime and API tests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prost::Message;
use prost_types::FileDescriptorSet;
use rust_xray::api::proto::app::observatory::command::observatory_service_client::ObservatoryServiceClient;
use rust_xray::api::proto::app::observatory::command::observatory_service_server::ObservatoryServiceServer;
use rust_xray::api::proto::app::observatory::command::{
    GetOutboundStatusRequest, GetOutboundStatusResponse,
};
use rust_xray::api::proto::app::observatory::{ObservationResult, OutboundStatus};
use rust_xray::api::proto::FILE_DESCRIPTOR_SET;
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::observatory::{ObservatoryRuntimeConfig, TestHooks, DEAD_PROBE_DELAY_MS};
use rust_xray::runtime::{encode_blackhole_outbound, encode_freedom_outbound, HandlerRuntime};
use rust_xray::stats::StatsRegistry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tonic::server::NamedService;
use tonic::transport::Endpoint;
use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1::ServerReflectionRequest;

static OBSERVATORY_TEST_SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn observatory_test_serial() -> tokio::sync::MutexGuard<'static, ()> {
    OBSERVATORY_TEST_SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[derive(Clone, Copy)]
enum ProbeServerMode {
    Ok204,
    Redirect302,
    Stall,
    DelayedOk,
}

#[derive(Clone)]
struct ProbeServerState {
    requests: Arc<AtomicUsize>,
    release: Arc<Notify>,
}

async fn spawn_probe_server(
    mode: ProbeServerMode,
) -> (std::net::SocketAddr, JoinHandle<()>, Arc<Notify>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe server");
    let addr = listener.local_addr().expect("probe addr");
    let requests = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let state = ProbeServerState {
        requests: Arc::clone(&requests),
        release: Arc::clone(&release),
    };
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let state = state.clone();
            tokio::spawn(async move {
                state.requests.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0_u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                match mode {
                    ProbeServerMode::Stall => {
                        state.release.notified().await;
                    }
                    ProbeServerMode::DelayedOk => {
                        state.release.notified().await;
                        let response = "HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    ProbeServerMode::Redirect302 if req.contains("GET /probe") => {
                        let response = "HTTP/1.1 302 Found\r\nLocation: /other\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    ProbeServerMode::Redirect302 => {
                        let response = "HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    ProbeServerMode::Ok204 => {
                        let response = "HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                }
            });
        }
    });
    (addr, handle, release)
}

fn probe_url(addr: std::net::SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

fn build_runtime(
    selector: Vec<&str>,
    probe_url: &str,
    enable_concurrency: bool,
    outbounds: Vec<rust_xray::api::proto::core::OutboundHandlerConfig>,
) -> Arc<HandlerRuntime> {
    HandlerRuntime::for_observatory_tests(
        Arc::new(StatsRegistry::new()),
        ObservatoryRuntimeConfig::for_test(
            selector.into_iter().map(str::to_string).collect(),
            probe_url,
            Duration::from_millis(50),
            enable_concurrency,
        ),
        outbounds,
    )
}

fn status_by_tag<'a>(result: &'a ObservationResult, tag: &str) -> Option<&'a OutboundStatus> {
    result
        .status
        .iter()
        .find(|status| status.outbound_tag == tag)
}

fn standard_observatory(
    runtime: &Arc<HandlerRuntime>,
) -> &Arc<rust_xray::observatory::RuntimeObservatory> {
    runtime
        .observatory
        .as_ref()
        .expect("observatory")
        .standard()
        .expect("standard observatory")
}

async fn probe_once_and_get(runtime: &Arc<HandlerRuntime>, tag: &str) -> OutboundStatus {
    let observatory = standard_observatory(runtime);
    observatory.probe_once().await;
    status_by_tag(&observatory.observation_result(), tag)
        .cloned()
        .expect("status for tag")
}

async fn spawn_observatory_api(
    runtime: Arc<HandlerRuntime>,
) -> (std::net::SocketAddr, JoinHandle<std::io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind api");
    let addr = listener.local_addr().expect("api addr");
    let registry = Arc::new(StatsRegistry::new());
    let task = tokio::spawn(async move {
        serve_grpc_on(
            listener,
            vec![ApiService::Reflection, ApiService::Observatory],
            registry,
            runtime,
            ApiTransportMode::Plaintext,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    (addr, task)
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
fn observatory_proto_matches_upstream() {
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("decode descriptor set");

    let config_file = set
        .file
        .iter()
        .find(|file| file.name.as_deref() == Some("app/observatory/config.proto"))
        .expect("observatory config proto");
    let observation = config_file
        .message_type
        .iter()
        .find(|msg| msg.name.as_deref() == Some("ObservationResult"))
        .expect("ObservationResult");
    assert_eq!(
        observation
            .field
            .iter()
            .find(|f| f.number == Some(1))
            .unwrap()
            .name,
        Some("status".to_string())
    );

    let outbound = config_file
        .message_type
        .iter()
        .find(|msg| msg.name.as_deref() == Some("OutboundStatus"))
        .expect("OutboundStatus");
    let fields: HashMap<i32, String> = outbound
        .field
        .iter()
        .map(|field| {
            (
                field.number.unwrap_or_default(),
                field.name.clone().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(fields.get(&1).map(String::as_str), Some("alive"));
    assert_eq!(fields.get(&2).map(String::as_str), Some("delay"));
    assert_eq!(
        fields.get(&3).map(String::as_str),
        Some("last_error_reason")
    );
    assert_eq!(fields.get(&4).map(String::as_str), Some("outbound_tag"));
    assert_eq!(fields.get(&5).map(String::as_str), Some("last_seen_time"));
    assert_eq!(fields.get(&6).map(String::as_str), Some("last_try_time"));
    assert_eq!(fields.get(&7).map(String::as_str), Some("health_ping"));

    let health_ping = config_file
        .message_type
        .iter()
        .find(|msg| msg.name.as_deref() == Some("HealthPingMeasurementResult"))
        .expect("HealthPingMeasurementResult");
    for (number, name) in [
        (1, "all"),
        (2, "fail"),
        (3, "deviation"),
        (4, "average"),
        (5, "max"),
        (6, "min"),
    ] {
        assert!(
            health_ping.field.iter().any(|field| {
                field.number == Some(number) && field.name.as_deref() == Some(name)
            }),
            "missing HealthPingMeasurementResult.{name}"
        );
    }

    let command_file = set
        .file
        .iter()
        .find(|file| file.name.as_deref() == Some("app/observatory/command/command.proto"))
        .expect("observatory command proto");
    let service = command_file
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("ObservatoryService"))
        .expect("ObservatoryService");
    assert_eq!(service.method.len(), 1);
    assert_eq!(service.method[0].name.as_deref(), Some("GetOutboundStatus"));
}

#[test]
fn observatory_service_canonical_grpc_path() {
    assert_eq!(
        ObservatoryServiceServer::<rust_xray::api::observatory::ObservatoryServiceImpl>::NAME,
        "xray.core.app.observatory.command.ObservatoryService"
    );
}

#[tokio::test]
async fn observatory_service_reflection() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_runtime(
        vec!["direct"],
        &probe_url(probe_addr, "/probe"),
        false,
        vec![encode_freedom_outbound("direct")],
    );
    let (addr, _task) = spawn_observatory_api(Arc::clone(&runtime)).await;
    let channel = connect_plaintext(addr).await;
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
        let message = message.expect("reflection message");
        if let Some(tonic_reflection::pb::v1::server_reflection_response::MessageResponse::ListServicesResponse(
            list,
        )) = message.message_response
        {
            listed.extend(list.service.into_iter().map(|service| service.name));
        }
    }
    assert!(listed
        .iter()
        .any(|name| name == "xray.core.app.observatory.command.ObservatoryService"));
}

#[tokio::test]
async fn get_outbound_status_tonic() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_runtime(
        vec!["direct"],
        &probe_url(probe_addr, "/probe"),
        false,
        vec![encode_freedom_outbound("direct")],
    );
    runtime.start_observatory();
    let observatory = standard_observatory(&runtime);
    observatory.probe_once().await;

    let (addr, _task) = spawn_observatory_api(Arc::clone(&runtime)).await;
    let mut client = ObservatoryServiceClient::new(connect_plaintext(addr).await);
    let response: GetOutboundStatusResponse = client
        .get_outbound_status(GetOutboundStatusRequest {})
        .await
        .expect("GetOutboundStatus")
        .into_inner();
    let status = response.status.expect("status payload");
    let direct = status_by_tag(&status, "direct").expect("direct status");
    assert!(direct.alive);
    assert!(direct.delay >= 0);
    assert!(direct.last_try_time > 0);
    assert!(direct.last_seen_time > 0);
    assert!(direct.last_error_reason.is_empty());
    assert!(direct.health_ping.is_none());
}

#[tokio::test]
async fn standard_observatory_direct_alive() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_runtime(
        vec!["direct"],
        &probe_url(probe_addr, "/probe"),
        false,
        vec![encode_freedom_outbound("direct")],
    );
    let status = probe_once_and_get(&runtime, "direct").await;
    assert!(status.alive);
    assert!(status.delay >= 0);
    assert!(status.last_try_time > 0);
    assert!(status.last_seen_time > 0);
    assert!(status.last_error_reason.is_empty());
    assert!(status.health_ping.is_none());
}

#[tokio::test]
async fn standard_observatory_blackhole_dead() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_runtime(
        vec!["blocked"],
        &probe_url(probe_addr, "/probe"),
        false,
        vec![encode_blackhole_outbound("blocked")],
    );
    let status = probe_once_and_get(&runtime, "blocked").await;
    assert!(!status.alive);
    assert_eq!(status.delay, DEAD_PROBE_DELAY_MS);
    assert!(!status.last_error_reason.is_empty());
    assert!(status.last_try_time > 0);
}

#[tokio::test]
async fn standard_observatory_uses_selected_outbound() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = build_runtime(
        vec!["probe-"],
        &url,
        false,
        vec![
            encode_freedom_outbound("probe-direct"),
            encode_blackhole_outbound("probe-blackhole"),
        ],
    );
    let observatory = standard_observatory(&runtime);
    observatory.probe_once().await;
    let result = observatory.observation_result();
    let direct = status_by_tag(&result, "probe-direct").expect("direct");
    let blackhole = status_by_tag(&result, "probe-blackhole").expect("blackhole");
    assert!(direct.alive);
    assert!(!blackhole.alive);
}

#[tokio::test]
async fn standard_observatory_dynamic_add_outbound() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = build_runtime(
        vec!["probe-"],
        &url,
        false,
        vec![encode_freedom_outbound("probe-a")],
    );
    let observatory = standard_observatory(&runtime);
    observatory.probe_once().await;
    assert!(status_by_tag(&observatory.observation_result(), "probe-a").is_some());
    assert!(status_by_tag(&observatory.observation_result(), "probe-b").is_none());

    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("probe-b"))
        .expect("add outbound");
    observatory.probe_once().await;
    assert!(status_by_tag(&observatory.observation_result(), "probe-b").is_some());
}

#[tokio::test]
async fn standard_observatory_removed_outbound_pruned() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = build_runtime(
        vec!["probe-"],
        &url,
        false,
        vec![
            encode_freedom_outbound("probe-a"),
            encode_freedom_outbound("probe-b"),
        ],
    );
    let observatory = standard_observatory(&runtime);
    observatory.probe_once().await;
    assert!(status_by_tag(&observatory.observation_result(), "probe-b").is_some());

    runtime.outbound.remove_outbound("probe-b").expect("remove");
    observatory.probe_once().await;
    assert!(status_by_tag(&observatory.observation_result(), "probe-b").is_none());
}

#[tokio::test]
async fn standard_observatory_empty_selector_no_worker() {
    let _guard = observatory_test_serial().await;
    let runtime = build_runtime(
        vec![],
        "http://127.0.0.1:1/probe",
        false,
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = standard_observatory(&runtime);
    observatory.start();
    observatory.probe_once().await;
    assert!(observatory.observation_result().status.is_empty());
}

#[tokio::test]
async fn standard_observatory_shutdown_cancels() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Stall).await;
    let runtime = build_runtime(
        vec!["direct"],
        &probe_url(probe_addr, "/probe"),
        false,
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = standard_observatory(&runtime);
    observatory.start();
    observatory.wake();
    let shutdown = observatory.shutdown();
    let finished = tokio::time::timeout(Duration::from_secs(2), shutdown).await;
    assert!(
        finished.is_ok(),
        "observatory shutdown must finish promptly"
    );
}

#[tokio::test]
async fn standard_observatory_sequential_mode() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = build_runtime(
        vec!["probe-"],
        &url,
        false,
        vec![
            encode_freedom_outbound("probe-b"),
            encode_freedom_outbound("probe-a"),
        ],
    );
    let observatory = standard_observatory(&runtime);
    let order = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let order_hook = Arc::clone(&order);
    observatory
        .set_test_hooks(TestHooks {
            after_probe: Some(Arc::new(move |tag| {
                order_hook.lock().expect("order lock").push(tag.to_string());
            })),
            ..Default::default()
        })
        .await;
    observatory.probe_once().await;
    let order = order.lock().expect("order lock").clone();
    assert_eq!(order, vec!["probe-a", "probe-b"]);
}

#[tokio::test]
async fn standard_observatory_concurrent_mode() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, release) = spawn_probe_server(ProbeServerMode::DelayedOk).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = build_runtime(
        vec!["probe-"],
        &url,
        true,
        vec![
            encode_freedom_outbound("probe-a"),
            encode_freedom_outbound("probe-b"),
        ],
    );
    let observatory = standard_observatory(&runtime);
    let entered = Arc::new(AtomicUsize::new(0));
    let entered_hook = Arc::clone(&entered);
    observatory
        .set_test_hooks(TestHooks {
            before_probe: Some(Arc::new(move |_| {
                entered_hook.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        })
        .await;

    let probe = tokio::spawn({
        let observatory = Arc::clone(observatory);
        async move {
            observatory.probe_once().await;
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while entered.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("both probes must overlap before either completes");
    assert!(
        !probe.is_finished(),
        "round must still be waiting on delayed probe responses"
    );
    release.notify_waiters();
    probe.await.expect("probe round");
}

#[tokio::test]
async fn standard_observatory_status_timestamps() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_runtime(
        vec!["direct"],
        &probe_url(probe_addr, "/probe"),
        false,
        vec![encode_freedom_outbound("direct")],
    );
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let status = probe_once_and_get(&runtime, "direct").await;
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(status.last_try_time >= before && status.last_try_time <= after);
    assert_eq!(status.last_seen_time, status.last_try_time);
}

#[tokio::test]
async fn standard_observatory_failure_preserves_last_seen() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = build_runtime(
        vec!["direct"],
        &url,
        false,
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = standard_observatory(&runtime);
    observatory.probe_once().await;
    let alive = status_by_tag(&observatory.observation_result(), "direct")
        .expect("alive status")
        .last_seen_time;

    runtime
        .outbound
        .remove_outbound("direct")
        .expect("remove direct");
    runtime
        .outbound
        .add_outbound(encode_blackhole_outbound("direct"))
        .expect("replace with blackhole");
    observatory.probe_once().await;
    let result = observatory.observation_result();
    let dead = status_by_tag(&result, "direct").expect("dead status");
    assert!(!dead.alive);
    assert_eq!(dead.last_seen_time, alive);
}

#[tokio::test]
async fn standard_observatory_redirect_not_followed() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Redirect302).await;
    let runtime = build_runtime(
        vec!["direct"],
        &probe_url(probe_addr, "/probe"),
        false,
        vec![encode_freedom_outbound("direct")],
    );
    let status = probe_once_and_get(&runtime, "direct").await;
    assert!(status.alive, "upstream treats first HTTP response as alive");
}

#[tokio::test]
async fn standard_observatory_without_api_service_still_probes() {
    let _guard = observatory_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_runtime(
        vec!["direct"],
        &probe_url(probe_addr, "/probe"),
        false,
        vec![encode_freedom_outbound("direct")],
    );
    runtime.start_observatory();
    let observatory = standard_observatory(&runtime);
    observatory.probe_once().await;
    assert!(
        status_by_tag(&observatory.observation_result(), "direct")
            .expect("status")
            .alive
    );
}
