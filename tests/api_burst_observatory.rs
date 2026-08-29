//! Stage 8E4-B BurstObservatory and HealthPing tests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prost::Message;
use prost_types::FileDescriptorSet;
use rust_xray::api::proto::app::observatory::command::observatory_service_client::ObservatoryServiceClient;
use rust_xray::api::proto::app::observatory::command::{
    GetOutboundStatusRequest, GetOutboundStatusResponse,
};
use rust_xray::api::proto::app::observatory::ObservationResult;
use rust_xray::api::proto::FILE_DESCRIPTOR_SET;
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::observatory::{
    BurstObservatoryRuntimeConfig, BurstTestHooks, HealthPingRuntimeConfig,
    ObservatoryRuntimeConfig, ProbeDelaySource, RuntimeBurstObservatory,
};
use rust_xray::routing::{
    HealthPingObservation, OutboundHealthObservation, OutboundHealthProvider,
};
use rust_xray::runtime::{encode_blackhole_outbound, encode_freedom_outbound, HandlerRuntime};
use rust_xray::stats::StatsRegistry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tonic::transport::Endpoint;

static BURST_TEST_SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn burst_test_serial() -> tokio::sync::MutexGuard<'static, ()> {
    BURST_TEST_SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[derive(Clone, Copy)]
enum ProbeServerMode {
    Ok204,
    Ok200,
    Fail500,
    Redirect302,
    Stall,
}

#[derive(Clone)]
struct ProbeServerState {
    requests: Arc<AtomicUsize>,
    method: Arc<tokio::sync::Mutex<Option<String>>>,
    release: Arc<Notify>,
}

async fn spawn_probe_server(
    mode: ProbeServerMode,
) -> (std::net::SocketAddr, JoinHandle<()>, ProbeServerState) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe server");
    let addr = listener.local_addr().expect("probe addr");
    let requests = Arc::new(AtomicUsize::new(0));
    let method = Arc::new(tokio::sync::Mutex::new(None));
    let release = Arc::new(Notify::new());
    let state = ProbeServerState {
        requests: Arc::clone(&requests),
        method: Arc::clone(&method),
        release: Arc::clone(&release),
    };
    let worker_state = state.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let state = worker_state.clone();
            tokio::spawn(async move {
                state.requests.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0_u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                if let Some(line) = req.lines().next() {
                    let mut method = state.method.lock().await;
                    *method = line.split_whitespace().next().map(str::to_string);
                }
                match mode {
                    ProbeServerMode::Stall => {
                        state.release.notified().await;
                    }
                    ProbeServerMode::Fail500 => {
                        let response = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    ProbeServerMode::Ok200 => {
                        let response =
                            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    ProbeServerMode::Redirect302 => {
                        let response = "HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: http://127.0.0.1/\r\nContent-Length: 0\r\n\r\n";
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
    (addr, handle, state)
}

fn probe_url(addr: std::net::SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

fn build_burst_runtime(
    selector: Vec<&str>,
    ping: HealthPingRuntimeConfig,
    outbounds: Vec<rust_xray::api::proto::core::OutboundHandlerConfig>,
) -> Arc<HandlerRuntime> {
    HandlerRuntime::for_burst_observatory_tests(
        Arc::new(StatsRegistry::new()),
        BurstObservatoryRuntimeConfig::for_test(
            selector.into_iter().map(str::to_string).collect(),
            ping,
        ),
        outbounds,
    )
}

fn burst_observatory(runtime: &Arc<HandlerRuntime>) -> &Arc<RuntimeBurstObservatory> {
    runtime
        .burst_observatory
        .as_ref()
        .expect("burst observatory")
}

fn status_by_tag<'a>(
    result: &'a ObservationResult,
    tag: &str,
) -> Option<&'a rust_xray::api::proto::app::observatory::OutboundStatus> {
    result
        .status
        .iter()
        .find(|status| status.outbound_tag == tag)
}

struct SequentialDelaySource {
    delays: std::sync::Mutex<Vec<Duration>>,
}

impl ProbeDelaySource for SequentialDelaySource {
    fn delay(&self, _max: Duration, seed: u64) -> Duration {
        self.delays
            .lock()
            .expect("delays")
            .get(seed as usize)
            .copied()
            .unwrap_or(Duration::ZERO)
    }
}

#[test]
fn burst_proto_matches_upstream() {
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("decode descriptor set");
    let file = set
        .file
        .iter()
        .find(|file| file.name.as_deref() == Some("app/observatory/burst/config.proto"))
        .expect("burst config proto");
    let config = file
        .message_type
        .iter()
        .find(|msg| msg.name.as_deref() == Some("Config"))
        .expect("Config");
    let fields: HashMap<i32, String> = config
        .field
        .iter()
        .map(|field| {
            (
                field.number.unwrap_or_default(),
                field.name.clone().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(fields.get(&2).map(String::as_str), Some("subject_selector"));
    assert_eq!(fields.get(&3).map(String::as_str), Some("ping_config"));
    let ping = file
        .message_type
        .iter()
        .find(|msg| msg.name.as_deref() == Some("HealthPingConfig"))
        .expect("HealthPingConfig");
    let ping_fields: HashMap<i32, String> = ping
        .field
        .iter()
        .map(|field| {
            (
                field.number.unwrap_or_default(),
                field.name.clone().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        ping_fields.get(&4).map(String::as_str),
        Some("samplingCount")
    );
}

#[tokio::test]
async fn burst_tagged_direct_alive() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = burst_observatory(&runtime);
    observatory.check(&["direct".to_string()]).await;
    let snapshot = observatory.observation_result();
    let status = status_by_tag(&snapshot, "direct").expect("status");
    assert!(status.alive);
    assert!(status.delay >= 0);
    assert_eq!(status.last_seen_time, 0);
    assert_eq!(status.last_try_time, 0);
    let health = status.health_ping.as_ref().expect("health ping");
    assert_eq!(health.all, 1);
    assert_eq!(health.fail, 0);
    assert!(health.average > 0);
}

#[tokio::test]
async fn burst_tagged_blackhole_failed() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["blocked"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_blackhole_outbound("blocked")],
    );
    let observatory = burst_observatory(&runtime);
    observatory.check(&["blocked".to_string()]).await;
    let snapshot = observatory.observation_result();
    let status = status_by_tag(&snapshot, "blocked").expect("status");
    assert!(!status.alive);
    assert_eq!(status.health_ping.as_ref().expect("health").fail, 1);
}

#[tokio::test]
async fn burst_connectivity_success_records_failure() {
    let _guard = burst_test_serial().await;
    let (dest_addr, _dest, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let (conn_addr, _conn, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["blocked"],
        HealthPingRuntimeConfig::for_test(
            probe_url(dest_addr, "/probe"),
            &probe_url(conn_addr, "/connectivity"),
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_blackhole_outbound("blocked")],
    );
    let observatory = burst_observatory(&runtime);
    observatory.check(&["blocked".to_string()]).await;
    let snapshot = observatory.observation_result();
    let health = status_by_tag(&snapshot, "blocked")
        .expect("status")
        .health_ping
        .as_ref()
        .expect("health");
    assert_eq!(health.fail, 1);
}

#[tokio::test]
async fn burst_connectivity_failure_skips_sample() {
    let _guard = burst_test_serial().await;
    let (dest_addr, _dest, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["blocked"],
        HealthPingRuntimeConfig::for_test(
            probe_url(dest_addr, "/probe"),
            "http://127.0.0.1:1/unreachable",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_blackhole_outbound("blocked")],
    );
    let observatory = burst_observatory(&runtime);
    observatory.check(&["blocked".to_string()]).await;
    assert!(observatory.observation_result().status.is_empty());
}

#[tokio::test]
async fn burst_dynamic_outbound_add() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = build_burst_runtime(
        vec!["probe-"],
        HealthPingRuntimeConfig::for_test(
            url.clone(),
            "",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("probe-a")],
    );
    let observatory = burst_observatory(&runtime);
    observatory.check(&["probe-a".to_string()]).await;
    assert!(status_by_tag(&observatory.observation_result(), "probe-a").is_some());
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("probe-b"))
        .expect("add");
    observatory
        .check(&["probe-a".to_string(), "probe-b".to_string()])
        .await;
    assert!(status_by_tag(&observatory.observation_result(), "probe-b").is_some());
}

#[tokio::test]
async fn burst_removed_outbound_cleanup() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = build_burst_runtime(
        vec!["probe-"],
        HealthPingRuntimeConfig::for_test(
            url,
            "",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![
            encode_freedom_outbound("probe-a"),
            encode_freedom_outbound("probe-b"),
        ],
    );
    let observatory = burst_observatory(&runtime);
    observatory
        .check(&["probe-a".to_string(), "probe-b".to_string()])
        .await;
    runtime.outbound.remove_outbound("probe-b").expect("remove");
    observatory.cleanup(&["probe-a".to_string()]);
    assert!(status_by_tag(&observatory.observation_result(), "probe-b").is_none());
}

#[tokio::test]
async fn burst_initial_check_one_sample() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, state) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            5,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = burst_observatory(&runtime);
    observatory.check(&["direct".to_string()]).await;
    assert_eq!(state.requests.load(Ordering::SeqCst), 1);
    let snapshot = observatory.observation_result();
    let health = status_by_tag(&snapshot, "direct")
        .expect("status")
        .health_ping
        .as_ref()
        .expect("health");
    assert_eq!(health.all, 1);
}

#[tokio::test]
async fn burst_scheduler_sampling_period() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, state) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_millis(100),
            2,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = burst_observatory(&runtime);
    observatory
        .set_test_hooks(BurstTestHooks {
            delay_source: Some(Arc::new(SequentialDelaySource {
                delays: std::sync::Mutex::new(vec![Duration::ZERO, Duration::from_millis(50)]),
            })),
            ..Default::default()
        })
        .await;
    observatory
        .do_scheduled_check_for_test(&["direct".to_string()], Duration::from_millis(100), 2)
        .await;
    assert_eq!(state.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn burst_scheduler_cancels_previous_round() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, state) = spawn_probe_server(ProbeServerMode::Stall).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_millis(200),
            1,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = Arc::clone(burst_observatory(&runtime));
    observatory.start();
    while state.requests.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    state.release.notify_waiters();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snapshot = observatory.observation_result();
    let health = status_by_tag(&snapshot, "direct")
        .expect("status")
        .health_ping
        .as_ref()
        .expect("health");
    assert_eq!(health.all, 1);
    observatory.shutdown().await;
}

#[tokio::test]
async fn burst_startup_runs_initial_check_and_scheduled_round() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, state) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_millis(500),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = burst_observatory(&runtime);
    observatory
        .set_test_hooks(BurstTestHooks {
            delay_source: Some(Arc::new(SequentialDelaySource {
                delays: std::sync::Mutex::new(vec![Duration::ZERO, Duration::ZERO, Duration::ZERO]),
            })),
            ..Default::default()
        })
        .await;
    observatory.start();
    while state.requests.load(Ordering::SeqCst) < 4 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(observatory.scheduled_round_starts.load(Ordering::SeqCst) >= 1);
    observatory.shutdown().await;
}

#[tokio::test]
async fn burst_probe_stalled_http_respects_timeout() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Stall).await;
    let timeout = Duration::from_millis(150);
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            3,
            timeout,
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = burst_observatory(&runtime);
    let started = std::time::Instant::now();
    observatory.check(&["direct".to_string()]).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    let snapshot = observatory.observation_result();
    let health = status_by_tag(&snapshot, "direct")
        .expect("status")
        .health_ping
        .as_ref()
        .expect("health");
    assert_eq!(health.fail, 1);
}

#[tokio::test]
async fn burst_observation_result_concurrent_stress() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            5,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = Arc::clone(burst_observatory(&runtime));
    let mut writers = Vec::new();
    for _ in 0..8 {
        let obs = Arc::clone(&observatory);
        writers.push(tokio::spawn(async move {
            obs.check(&["direct".to_string()]).await;
        }));
    }
    let mut readers = Vec::new();
    for _ in 0..32 {
        let obs = Arc::clone(&observatory);
        readers.push(tokio::spawn(async move {
            let snapshot = obs.observation_result();
            let status = status_by_tag(&snapshot, "direct");
            if let Some(status) = status {
                let health = status.health_ping.as_ref().expect("health");
                assert!(health.all >= health.fail);
            }
            obs.observations().expect("observations");
        }));
    }
    for handle in writers.into_iter().chain(readers) {
        handle.await.expect("task");
    }
}

#[tokio::test]
async fn burst_shutdown_terminates_stalled_probe() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, state) = spawn_probe_server(ProbeServerMode::Stall).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = burst_observatory(&runtime);
    observatory.start();
    while state.requests.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let started = std::time::Instant::now();
    observatory.shutdown().await;
    assert!(started.elapsed() < Duration::from_secs(3));
    let requests = state.requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.requests.load(Ordering::SeqCst), requests);
}

#[tokio::test]
async fn burst_standard_coexistence_both_run() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr, "/probe");
    let runtime = HandlerRuntime::for_coexistence_observatory_tests(
        Arc::new(StatsRegistry::new()),
        ObservatoryRuntimeConfig::for_test(
            vec!["direct".to_string()],
            url.clone(),
            Duration::from_millis(50),
            false,
        ),
        BurstObservatoryRuntimeConfig::for_test(
            vec!["direct".to_string()],
            HealthPingRuntimeConfig::for_test(
                url,
                "",
                Duration::from_secs(30),
                3,
                Duration::from_secs(5),
                "HEAD",
            ),
        ),
        vec![encode_freedom_outbound("direct")],
    );
    runtime.start_observatory();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let standard = runtime
        .standard_observatory
        .as_ref()
        .expect("standard runtime");
    let burst = runtime.burst_observatory.as_ref().expect("burst runtime");
    assert!(burst.scheduled_round_starts.load(Ordering::SeqCst) >= 1);
    let standard_status = standard.observation_result();
    let standard_direct = status_by_tag(&standard_status, "direct");
    assert!(
        standard_direct.is_some_and(|status| status.last_try_time > 0),
        "standard scheduler should have probed"
    );
    let api_status = runtime
        .observatory
        .as_ref()
        .expect("active observatory")
        .observation_result();
    let api_direct = status_by_tag(&api_status, "direct").expect("api status");
    assert!(api_direct.health_ping.is_none());
    let burst_status = burst.observation_result();
    let burst_direct = status_by_tag(&burst_status, "direct").expect("burst status");
    assert!(burst_direct.health_ping.is_some());
    runtime.shutdown_observatory().await;
}

#[tokio::test]
async fn burst_health_ping_uses_configured_http_method() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, state) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "GET",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    burst_observatory(&runtime)
        .check(&["direct".to_string()])
        .await;
    assert_eq!(state.method.lock().await.as_deref(), Some("GET"));
}

#[tokio::test]
async fn burst_probe_accepts_non_204_http_responses() {
    let _guard = burst_test_serial().await;
    for (mode, label) in [
        (ProbeServerMode::Ok200, "200"),
        (ProbeServerMode::Fail500, "500"),
        (ProbeServerMode::Redirect302, "redirect"),
    ] {
        let (probe_addr, _probe, _) = spawn_probe_server(mode).await;
        let runtime = build_burst_runtime(
            vec!["direct"],
            HealthPingRuntimeConfig::for_test(
                probe_url(probe_addr, "/probe"),
                "",
                Duration::from_secs(30),
                3,
                Duration::from_secs(5),
                "HEAD",
            ),
            vec![encode_freedom_outbound("direct")],
        );
        burst_observatory(&runtime)
            .check(&["direct".to_string()])
            .await;
        let snapshot = burst_observatory(&runtime).observation_result();
        let status = status_by_tag(&snapshot, "direct")
            .unwrap_or_else(|| panic!("missing status for {label}"));
        assert!(status.alive, "{label} should count as successful probe");
    }
}

#[tokio::test]
async fn burst_health_ping_delay_units_abi() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    burst_observatory(&runtime)
        .check(&["direct".to_string()])
        .await;
    let snapshot = burst_observatory(&runtime).observation_result();
    let status = status_by_tag(&snapshot, "direct").expect("status");
    let health = status.health_ping.as_ref().expect("health ping");
    assert!(status.delay >= 0);
    assert!(health.average > 0);
    assert_eq!(status.delay, (health.average / 1_000_000).max(0));
    assert_eq!(health.average, health.max);
    assert_eq!(health.average, health.min);
}

#[tokio::test]
async fn burst_observatory_tonic_health_ping() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = build_burst_runtime(
        vec!["direct"],
        HealthPingRuntimeConfig::for_test(
            probe_url(probe_addr, "/probe"),
            "",
            Duration::from_secs(30),
            3,
            Duration::from_secs(5),
            "HEAD",
        ),
        vec![encode_freedom_outbound("direct")],
    );
    burst_observatory(&runtime)
        .check(&["direct".to_string()])
        .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let runtime_for_api = Arc::clone(&runtime);
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Observatory],
            Arc::new(StatsRegistry::new()),
            runtime_for_api,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let mut client = ObservatoryServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    let response: GetOutboundStatusResponse = client
        .get_outbound_status(GetOutboundStatusRequest {})
        .await
        .expect("rpc")
        .into_inner();
    let status = response.status.expect("status");
    let direct = status_by_tag(&status, "direct").expect("direct");
    assert!(direct.alive);
    assert!(direct.health_ping.is_some());
    assert!(direct.health_ping.as_ref().unwrap().average > 0);
}

#[tokio::test]
async fn burst_standard_observatory_regression() {
    let _guard = burst_test_serial().await;
    let (probe_addr, _probe, _) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let standard = HandlerRuntime::for_observatory_tests(
        Arc::new(StatsRegistry::new()),
        ObservatoryRuntimeConfig::for_test(
            vec!["direct".to_string()],
            probe_url(probe_addr, "/probe"),
            Duration::from_millis(50),
            false,
        ),
        vec![encode_freedom_outbound("direct")],
    );
    let observatory = standard
        .observatory
        .as_ref()
        .expect("observatory")
        .standard()
        .expect("standard");
    observatory.probe_once().await;
    let snapshot = observatory.observation_result();
    let status = status_by_tag(&snapshot, "direct").expect("status");
    assert!(status.last_try_time > 0);
    assert!(status.health_ping.is_none());
}

#[test]
fn leastload_adapter_preserves_nanosecond_health_ping_units() {
    let observation = OutboundHealthObservation {
        outbound_tag: "proxy-a".to_string(),
        alive: true,
        delay_ms: 25,
        health_ping: Some(HealthPingObservation {
            all: 1,
            fail: 0,
            average: 25_000_000,
            deviation: 12_500_000,
            max: 25_000_000,
            min: 25_000_000,
        }),
    };
    assert_eq!(observation.delay_ms, 25);
    assert_eq!(
        observation.health_ping.as_ref().unwrap().average,
        25_000_000
    );
}
