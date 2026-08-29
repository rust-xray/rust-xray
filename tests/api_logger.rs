//! Stage 8E3 LoggerService parity tests.

use std::fs;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prost::Message;
use prost_types::FileDescriptorSet;
use rust_xray::api::proto::app::log::command::logger_service_client::LoggerServiceClient;
use rust_xray::api::proto::app::log::command::logger_service_server::LoggerServiceServer;
use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::SysStatsRequest;
use rust_xray::api::proto::FILE_DESCRIPTOR_SET;
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::cli::{Command, RunOptions};
use rust_xray::logging::{
    init_logging_with_config, LogOutputKind, LogOutputSpec, LoggerRuntimeConfig,
    RuntimeLoggerController,
};
use rust_xray::runtime::HandlerRuntime;
use rust_xray::stats::StatsRegistry;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tonic::server::NamedService;
use tonic::transport::Endpoint;
use tonic::Code;
use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1::ServerReflectionRequest;

fn wait_for_file_contains(path: &std::path::Path, needle: &str, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        if let Ok(contents) = fs::read_to_string(path) {
            if contents.contains(needle) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

async fn spawn_logger_api_server(
    services: Vec<ApiService>,
) -> (std::net::SocketAddr, JoinHandle<std::io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let registry = Arc::new(StatsRegistry::new());
    let handler_runtime = HandlerRuntime::for_handler_tests(Arc::new(StatsRegistry::new()));
    let task = tokio::spawn(async move {
        serve_grpc_on(
            listener,
            services,
            registry,
            handler_runtime,
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

static TEST_LOGGING_WORKER: OnceLock<()> = OnceLock::new();
static LOGGER_TEST_SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn logger_test_serial() -> tokio::sync::MutexGuard<'static, ()> {
    LOGGER_TEST_SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn init_file_logger(error_path: &std::path::Path, access_path: Option<&std::path::Path>) {
    let guard = init_logging_with_config(
        &Command::Run(RunOptions {
            config: "test.json".into(),
            format: None,
        }),
        LoggerRuntimeConfig {
            error: LogOutputSpec::file(error_path),
            access: access_path
                .map(LogOutputSpec::file)
                .unwrap_or_else(LogOutputSpec::none),
            dns_log: false,
        },
    )
    .expect("init logging");
    if TEST_LOGGING_WORKER.set(()).is_ok() {
        std::mem::forget(guard);
    }
}

#[test]
fn logger_proto_matches_upstream() {
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("decode descriptor set");
    let logger_service = set
        .file
        .iter()
        .find(|file| file.name.as_deref() == Some("app/log/command/config.proto"))
        .and_then(|file| {
            file.service
                .iter()
                .find(|service| service.name.as_deref() == Some("LoggerService"))
        })
        .expect("LoggerService descriptor");
    assert_eq!(logger_service.method.len(), 1);
    assert_eq!(
        logger_service.method[0].name.as_deref(),
        Some("RestartLogger")
    );
    assert_ne!(logger_service.method[0].client_streaming, Some(true));
    assert_ne!(logger_service.method[0].server_streaming, Some(true));
}

#[test]
fn canonical_logger_service_grpc_path() {
    assert_eq!(
        LoggerServiceServer::<rust_xray::api::logger::LoggerServiceImpl>::NAME,
        "xray.app.log.command.LoggerService"
    );
}

#[tokio::test]
async fn logger_service_reflection_contains_restart_logger() {
    let _serial = logger_test_serial().await;
    init_file_logger(std::path::Path::new("/dev/null"), None);
    let (addr, _task) =
        spawn_logger_api_server(vec![ApiService::Reflection, ApiService::Logger]).await;
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
    let mut services = Vec::new();
    while let Some(message) = stream.next().await {
        if let Some(tonic_reflection::pb::v1::server_reflection_response::MessageResponse::ListServicesResponse(
            list,
        )) = message.expect("message").message_response
        {
            services.extend(list.service.into_iter().map(|service| service.name));
        }
    }
    assert!(services
        .iter()
        .any(|name| name.contains("xray.app.log.command.LoggerService")));
}

#[tokio::test]
async fn restart_logger_tonic_succeeds() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("test.log");
    init_file_logger(&log_path, None);
    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger]).await;
    let mut client = LoggerServiceClient::new(connect_plaintext(addr).await);
    client
        .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
        .await
        .expect("restart logger")
        .into_inner();
}

#[tokio::test]
async fn restart_logger_reopens_rotated_file() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("test.log");
    init_file_logger(&log_path, None);

    tracing::error!("BEFORE_ROTATION_MARKER");
    assert!(
        wait_for_file_contains(&log_path, "BEFORE_ROTATION_MARKER", 2000),
        "before marker must land in active file"
    );

    let rotated = temp.path().join("test.log.1");
    fs::rename(&log_path, &rotated).expect("rotate");

    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger]).await;
    let mut client = LoggerServiceClient::new(connect_plaintext(addr).await);
    client
        .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
        .await
        .expect("restart logger")
        .into_inner();

    tracing::error!("AFTER_ROTATION_MARKER");
    assert!(
        wait_for_file_contains(&log_path, "AFTER_ROTATION_MARKER", 2000),
        "after marker must land in reopened file"
    );
    let rotated_contents = fs::read_to_string(&rotated).expect("rotated");
    assert!(rotated_contents.contains("BEFORE_ROTATION_MARKER"));
    assert!(!rotated_contents.contains("AFTER_ROTATION_MARKER"));
}

#[tokio::test]
async fn restart_logger_reopens_access_and_error_outputs() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let error_path = temp.path().join("error.log");
    let access_path = temp.path().join("access.log");
    init_file_logger(&error_path, Some(&access_path));

    let controller = RuntimeLoggerController::global().expect("controller");
    controller
        .write_access(b"ACCESS_BEFORE\n")
        .expect("access before");
    tracing::error!("ERROR_BEFORE");
    assert!(wait_for_file_contains(&error_path, "ERROR_BEFORE", 2000));
    assert!(wait_for_file_contains(&access_path, "ACCESS_BEFORE", 2000));

    let error_rotated = temp.path().join("error.log.1");
    let access_rotated = temp.path().join("access.log.1");
    fs::rename(&error_path, &error_rotated).expect("rotate error");
    fs::rename(&access_path, &access_rotated).expect("rotate access");

    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger]).await;
    LoggerServiceClient::new(connect_plaintext(addr).await)
        .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
        .await
        .expect("restart")
        .into_inner();

    controller
        .write_access(b"ACCESS_AFTER\n")
        .expect("access after");
    tracing::error!("ERROR_AFTER");
    assert!(wait_for_file_contains(&error_path, "ERROR_AFTER", 2000));
    assert!(wait_for_file_contains(&access_path, "ACCESS_AFTER", 2000));
    assert!(!fs::read_to_string(&error_rotated)
        .expect("error rotated")
        .contains("ERROR_AFTER"));
    assert!(!fs::read_to_string(&access_rotated)
        .expect("access rotated")
        .contains("ACCESS_AFTER"));
}

#[tokio::test]
async fn restart_logger_does_not_duplicate_events() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("dup.log");
    init_file_logger(&log_path, None);
    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger]).await;
    let mut client = LoggerServiceClient::new(connect_plaintext(addr).await);

    for index in 0..3 {
        client
            .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
            .await
            .expect("restart")
            .into_inner();
        tracing::error!("DUP_MARKER_{index}");
        assert!(
            wait_for_file_contains(&log_path, &format!("DUP_MARKER_{index}"), 2000),
            "marker {index}"
        );
    }

    let contents = fs::read_to_string(&log_path).expect("log");
    assert_eq!(contents.matches("DUP_MARKER_0").count(), 1);
    assert_eq!(contents.matches("DUP_MARKER_1").count(), 1);
    assert_eq!(contents.matches("DUP_MARKER_2").count(), 1);
}

#[tokio::test]
async fn restart_logger_repeated_calls() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("repeat.log");
    init_file_logger(&log_path, None);
    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger]).await;
    let mut client = LoggerServiceClient::new(connect_plaintext(addr).await);
    for _ in 0..3 {
        client
            .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
            .await
            .expect("restart")
            .into_inner();
    }
    tracing::error!("REPEAT_OK");
    assert!(wait_for_file_contains(&log_path, "REPEAT_OK", 2000));
}

#[tokio::test]
async fn restart_logger_concurrent_logging_safe() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("concurrent.log");
    init_file_logger(&log_path, None);
    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger]).await;
    let mut client = LoggerServiceClient::new(connect_plaintext(addr).await);

    let emitters: Vec<_> = (0..8)
        .map(|index| {
            tokio::spawn(async move {
                for _ in 0..20 {
                    tracing::error!("CONCURRENT_{index}");
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        })
        .collect();

    for _ in 0..5 {
        client
            .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
            .await
            .expect("restart")
            .into_inner();
    }

    for handle in emitters {
        handle.await.expect("emitter");
    }
    tracing::error!("CONCURRENT_DONE");
    assert!(wait_for_file_contains(&log_path, "CONCURRENT_DONE", 2000));
}

#[tokio::test]
async fn restart_logger_concurrent_rpc_safe() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("rpc.log");
    init_file_logger(&log_path, None);
    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger]).await;

    let mut handles = Vec::new();
    for _ in 0..4 {
        let channel = connect_plaintext(addr).await;
        handles.push(tokio::spawn(async move {
            LoggerServiceClient::new(channel)
                .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
                .await
        }));
    }

    for handle in handles {
        handle.await.expect("join").expect("restart rpc");
    }
}

#[tokio::test]
async fn restart_logger_failure_is_reported_and_recovers() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("fail.log");
    init_file_logger(&log_path, None);
    let controller = RuntimeLoggerController::global().expect("controller");
    controller.set_next_open_failure();

    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger, ApiService::Stats]).await;
    let mut logger = LoggerServiceClient::new(connect_plaintext(addr).await);
    let err = logger
        .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
        .await
        .expect_err("restart must fail");
    assert_eq!(err.code(), Code::Internal);
    assert!(err.message().contains("failed to start logger"));

    logger
        .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
        .await
        .expect("recovery restart")
        .into_inner();

    tracing::error!("RECOVERY_MARKER");
    assert!(wait_for_file_contains(&log_path, "RECOVERY_MARKER", 2000));
}

#[tokio::test]
async fn restart_logger_keeps_api_alive() {
    let _serial = logger_test_serial().await;
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("alive.log");
    init_file_logger(&log_path, None);
    let (addr, _task) = spawn_logger_api_server(vec![ApiService::Logger, ApiService::Stats]).await;
    let channel = connect_plaintext(addr).await;
    let mut logger = LoggerServiceClient::new(channel.clone());
    let mut stats = StatsServiceClient::new(channel);

    logger
        .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
        .await
        .expect("restart")
        .into_inner();
    stats
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("stats after restart")
        .into_inner();
    logger
        .restart_logger(rust_xray::api::proto::app::log::command::RestartLoggerRequest {})
        .await
        .expect("second restart")
        .into_inner();
}

#[test]
fn parse_log_runtime_config_maps_access_and_error_files() {
    use rust_xray::config::LogConfig;
    use rust_xray::logging::parse_log_runtime_config;

    let config = LogConfig {
        access: Some("/tmp/access.log".to_string()),
        error: Some("/tmp/error.log".to_string()),
        dns_log: true,
        loglevel: Some("warning".to_string()),
        extra: Default::default(),
    };
    let runtime = parse_log_runtime_config(Some(&config));
    assert_eq!(runtime.error.kind, LogOutputKind::File);
    assert_eq!(runtime.access.kind, LogOutputKind::File);
    assert!(runtime.dns_log);
}
