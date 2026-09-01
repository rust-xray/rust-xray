use super::*;
use crate::transport::xhttp::packet_up::{shared_packet_up_manager, PacketUpLimits};
use crate::transport::xhttp::stream_up::shared_stream_up_manager;
use crate::vless::VlessUserManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn resolve_xhttp_mode_for_settings_accepts_all_known_modes() {
    let auto = XHttpSettings::default();
    assert_eq!(
        resolve_xhttp_mode_for_settings(&auto, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::StreamOne
    );
    let stream_one = XHttpSettings {
        mode: Some("stream-one".to_string()),
        ..XHttpSettings::default()
    };
    assert_eq!(
        resolve_xhttp_mode_for_settings(&stream_one, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::StreamOne
    );
    let packet_up = XHttpSettings {
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    assert_eq!(
        resolve_xhttp_mode_for_settings(&packet_up, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::PacketUp
    );
    let packet_down = XHttpSettings {
        mode: Some("packet-down".to_string()),
        ..XHttpSettings::default()
    };
    assert_eq!(
        resolve_xhttp_mode_for_settings(&packet_down, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::PacketDown
    );
    let stream_up = XHttpSettings {
        mode: Some("stream-up".to_string()),
        ..XHttpSettings::default()
    };
    assert_eq!(
        resolve_xhttp_mode_for_settings(&stream_up, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::StreamUp
    );
}

#[test]
fn resolve_xhttp_mode_for_settings_rejects_unknown_mode() {
    let unknown = XHttpSettings {
        mode: Some("not-a-mode".to_string()),
        ..XHttpSettings::default()
    };
    let err = resolve_xhttp_mode_for_settings(&unknown, TransportSecurity::Reality).unwrap_err();
    assert_eq!(err.to_string(), "unsupported XHTTP mode: not-a-mode");
}

async fn run_post(settings: XHttpSettings, request_target: &str, host: &str) -> Vec<u8> {
    let request =
        format!("POST {request_target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n");
    run_request(settings, request.into_bytes()).await
}

async fn run_post_with_outbound_probe(
    settings: XHttpSettings,
    request_target: &str,
    host: &str,
) -> (Vec<u8>, bool) {
    use crate::vless::config::VlessClient;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    const USER_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outbound_port = listener.local_addr().unwrap().port();
    let outbound_connected = Arc::new(AtomicBool::new(false));
    let outbound_connected_task = Arc::clone(&outbound_connected);
    tokio::spawn(async move {
        if tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept())
            .await
            .ok()
            .and_then(Result::ok)
            .is_some()
        {
            outbound_connected_task.store(true, Ordering::SeqCst);
        }
    });

    let mut vless_body = vec![0u8];
    vless_body.extend_from_slice(&USER_ID);
    vless_body.push(0);
    vless_body.push(0x01);
    vless_body.extend_from_slice(&outbound_port.to_be_bytes());
    vless_body.push(0x01);
    vless_body.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());

    let request = format!(
        "POST {request_target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
        vless_body.len()
    );
    let mut request_bytes = request.into_bytes();
    request_bytes.extend_from_slice(&vless_body);

    let users = Arc::new(VlessUserManager::new(
        "xhttp-test",
        vec![VlessClient {
            id: uuid::Uuid::from_bytes(USER_ID),
            email: None,
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move {
        serve_xhttp_stream_one(server, &settings, users, None, None, None).await
    });
    client.write_all(&request_bytes).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let _ = task.await.unwrap();
    (response, outbound_connected.load(Ordering::SeqCst))
}

#[tokio::test]
async fn packet_down_returns_unsupported_without_bridge() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-down".to_string()),
        ..XHttpSettings::default()
    };
    let (response, outbound_connected) =
        run_post_with_outbound_probe(settings, "/xhttp", "example.com").await;
    let body = String::from_utf8_lossy(&response);
    assert!(body.starts_with("HTTP/1.1 501 Not Implemented"), "{body}");
    assert!(!outbound_connected);
}

#[tokio::test]
async fn packet_up_http1_post_creates_session_and_returns_ok() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_post(settings, "/xhttp/session-a/0", "example.com").await;
    let body = String::from_utf8_lossy(&response);
    assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
}

#[tokio::test]
async fn packet_up_http1_get_without_session_is_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_request(
        settings,
        b"GET /xhttp HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 404 Not Found"));
}

#[tokio::test]
async fn packet_up_http1_get_attaches_to_session() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    let manager = shared_packet_up_manager();
    manager
        .begin_upload_packet(
            "session-a",
            Some(0),
            PacketUpLimits::from_settings(&settings),
        )
        .expect("create session");
    let response = run_request(
        settings,
        b"GET /xhttp/session-a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    let body = String::from_utf8_lossy(&response);
    assert!(body.contains("Content-Type: text/event-stream"), "{body}");
    assert!(body.contains("Transfer-Encoding: chunked"), "{body}");
}

#[tokio::test]
async fn packet_up_duplicate_download_get_is_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    let manager = shared_packet_up_manager();
    let _download_rx = manager
        .bind_download_session("session-dup")
        .expect("first download bind");
    let response = run_request(
        settings,
        b"GET /xhttp/session-dup HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 409 Conflict"));
}

#[tokio::test]
async fn packet_up_oversized_post_is_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        extra: [("scMaxEachPostBytes".to_string(), serde_json::json!(16))].into(),
        ..XHttpSettings::default()
    };
    let request = format!(
        "POST /xhttp/session-big/0 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 32\r\n\r\n{}",
        "x".repeat(32)
    );
    let response = run_request(settings, request.into_bytes()).await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 413 Payload Too Large"));
}

#[tokio::test]
async fn packet_up_http1_get_invalid_session_id_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_request(
        settings,
        b"GET /xhttp/../escape HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400 Bad Request"));
}

#[tokio::test]
async fn packet_up_http1_chunked_upload_accepted() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    let payload = b"packet-up-chunked";
    let request = format!(
        "POST /xhttp/session-chunk/0 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        payload.len(),
        std::str::from_utf8(payload).unwrap()
    );
    let response = run_request(settings, request.into_bytes()).await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn packet_up_http1_malformed_chunked_upload_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_request(
        settings,
        b"POST /xhttp/session-bad/0 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400 Bad Request"));
}

#[tokio::test]
async fn packet_up_http1_chunked_early_eof_rejected_and_session_reusable() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    let truncated = b"POST /xhttp/session-eof/0 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
    let first = run_partial_request(settings.clone(), truncated).await;
    assert!(
        String::from_utf8_lossy(&first).starts_with("HTTP/1.1 400 Bad Request"),
        "{}",
        String::from_utf8_lossy(&first)
    );

    let recovery = run_post_chunked(settings, "session-eof", 1, b"ok").await;
    assert!(String::from_utf8_lossy(&recovery).starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn packet_up_http1_oversized_chunked_upload_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        extra: [("scMaxEachPostBytes".to_string(), serde_json::json!(10))].into(),
        ..XHttpSettings::default()
    };
    let body = format!(
        "POST /xhttp/session-big-chunk/0 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n{}\r\n6\r\n{}\r\n0\r\n\r\n",
        "a".repeat(6),
        "b".repeat(6)
    );
    let response = run_request(settings, body.into_bytes()).await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 413 Payload Too Large"));
}

#[tokio::test]
async fn packet_up_http1_chunked_buffered_posts_limit_enforced() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        extra: [("scMaxBufferedPosts".to_string(), serde_json::json!(1))].into(),
        ..XHttpSettings::default()
    };
    let first = run_post_chunked(settings.clone(), "session-buf", 2, b"x").await;
    assert!(String::from_utf8_lossy(&first).starts_with("HTTP/1.1 200 OK"));
    let second = run_post_chunked(settings, "session-buf", 3, b"y").await;
    assert!(String::from_utf8_lossy(&second).starts_with("HTTP/1.1 400 Bad Request"));
}

#[test]
fn packet_up_h2_is_supported_when_download_side_ready() {
    use crate::transport::xhttp::{packet_up_download_side_ready, EffectiveXHttpMode};
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        ..XHttpSettings::default()
    };
    assert!(packet_up_download_side_ready());
    assert_eq!(
        resolve_xhttp_mode_for_settings(&settings, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::PacketUp
    );
    assert!(xhttp_runtime_unsupported_reason(&settings, EffectiveXHttpMode::PacketUp).is_none());
}

#[tokio::test]
async fn stream_up_http1_post_without_seq_attaches_upload() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-up".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_post(settings, "/xhttp/session-a", "example.com").await;
    let body = String::from_utf8_lossy(&response);
    assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
}

#[tokio::test]
async fn stream_up_http1_post_with_seq_is_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-up".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_post(settings, "/xhttp/session-a/0", "example.com").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400 Bad Request"));
}

#[tokio::test]
async fn stream_up_http1_get_attaches_to_session() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-up".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_request(
        settings,
        b"GET /xhttp/session-a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    let body = String::from_utf8_lossy(&response);
    assert!(body.contains("Content-Type: text/event-stream"), "{body}");
    assert!(body.contains("Transfer-Encoding: chunked"), "{body}");
}

#[tokio::test]
async fn stream_up_duplicate_download_get_is_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-up".to_string()),
        ..XHttpSettings::default()
    };
    let manager = shared_stream_up_manager();
    let _download_rx = manager
        .bind_download_session("session-dup")
        .expect("first download bind");
    let response = run_request(
        settings,
        b"GET /xhttp/session-dup HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 409 Conflict"));
}

#[test]
fn stream_up_h2_is_supported_when_download_side_ready() {
    use crate::transport::xhttp::{stream_up_download_side_ready, EffectiveXHttpMode};
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-up".to_string()),
        ..XHttpSettings::default()
    };
    assert!(stream_up_download_side_ready());
    assert_eq!(
        resolve_xhttp_mode_for_settings(&settings, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::StreamUp
    );
    assert!(xhttp_runtime_unsupported_reason(&settings, EffectiveXHttpMode::StreamUp).is_none());
}

#[tokio::test]
async fn xmux_returns_unsupported_without_bridge() {
    use crate::config::XmuxSettings;
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-one".to_string()),
        xmux: Some(XmuxSettings::default()),
        ..XHttpSettings::default()
    };
    let (response, outbound_connected) =
        run_post_with_outbound_probe(settings, "/xhttp", "example.com").await;
    let body = String::from_utf8_lossy(&response);
    assert!(body.starts_with("HTTP/1.1 501 Not Implemented"), "{body}");
    assert!(!outbound_connected);
}

#[tokio::test]
async fn unsupported_mode_does_not_hang() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-down".to_string()),
        ..XHttpSettings::default()
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        run_post(settings, "/xhttp", "example.com"),
    )
    .await
    .expect("unsupported mode request should finish quickly");
    assert!(String::from_utf8_lossy(&result).starts_with("HTTP/1.1 501 Not Implemented"));
}

#[tokio::test]
async fn xhttp_duplex_reads_prebuffer_then_body_limit() {
    let (mut client, server) = tokio::io::duplex(128);
    client.write_all(b"worldextra").await.unwrap();
    let mut xhttp = XHttpDuplexStream::new(server, b"hello".to_vec(), Some(10));
    let mut out = Vec::new();
    xhttp.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"helloworld");
}

#[tokio::test]
async fn xhttp_duplex_writes_chunked_response() {
    let (client, server) = tokio::io::duplex(128);
    let mut xhttp = XHttpDuplexStream::new(server, Vec::new(), Some(0));
    xhttp.write_all(b"pong").await.unwrap();
    xhttp.shutdown().await.unwrap();
    let mut client = client;
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"4\r\npong\r\n0\r\n\r\n");
}

async fn run_request(settings: XHttpSettings, request: impl AsRef<[u8]>) -> Vec<u8> {
    let (mut client, server) = tokio::io::duplex(2048);
    let users = Arc::new(VlessUserManager::new("xhttp-test", Vec::new()));
    let task = tokio::spawn(async move {
        serve_xhttp_stream_one(server, &settings, users, None, None, None).await
    });
    client.write_all(request.as_ref()).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let _ = task.await.unwrap();
    response
}

async fn run_partial_request(settings: XHttpSettings, request: impl AsRef<[u8]>) -> Vec<u8> {
    let (mut client, server) = tokio::io::duplex(2048);
    let users = Arc::new(VlessUserManager::new("xhttp-test", Vec::new()));
    let task = tokio::spawn(async move {
        serve_xhttp_stream_one(server, &settings, users, None, None, None).await
    });
    client.write_all(request.as_ref()).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;
    let _ = task.await;
    response
}

async fn run_post_chunked(
    settings: XHttpSettings,
    session_id: &str,
    seq: u64,
    payload: &[u8],
) -> Vec<u8> {
    let request = format!(
        "POST /xhttp/{session_id}/{seq} HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        payload.len(),
        std::str::from_utf8(payload).unwrap_or("")
    );
    run_request(settings, request.into_bytes()).await
}

async fn run_accepted_post(settings: XHttpSettings, request_target: &str, host: &str) -> Vec<u8> {
    use crate::vless::config::VlessClient;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    const USER_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outbound_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.write_all(b"x").await;
        }
    });

    let mut vless_body = vec![0u8];
    vless_body.extend_from_slice(&USER_ID);
    vless_body.push(0);
    vless_body.push(0x01);
    vless_body.extend_from_slice(&outbound_port.to_be_bytes());
    vless_body.push(0x01);
    vless_body.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());

    let request = format!(
        "POST {request_target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
        vless_body.len()
    );
    let mut request_bytes = request.into_bytes();
    request_bytes.extend_from_slice(&vless_body);

    let users = Arc::new(VlessUserManager::new(
        "xhttp-test",
        vec![VlessClient {
            id: uuid::Uuid::from_bytes(USER_ID),
            email: None,
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    ));
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move {
        serve_xhttp_stream_one(server, &settings, users, None, None, None).await
    });
    client.write_all(&request_bytes).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let _ = task.await.unwrap();
    response
}

#[tokio::test]
async fn wrong_path_is_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    };
    let response = run_request(
        settings,
        b"POST /wrong HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 404 Not Found"));
}

#[tokio::test]
async fn query_string_does_not_break_path_match() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    };
    let response = run_accepted_post(settings, "/xhttp?sessionId=abc&seq=1", "example.com").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn wrong_host_is_rejected_when_configured() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        host: Some("example.com".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_request(
        settings,
        b"POST /xhttp HTTP/1.1\r\nHost: other.example\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 404 Not Found"));
}

#[tokio::test]
async fn configured_host_accepts_host_header_with_port() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        host: Some("example.com".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_accepted_post(settings, "/xhttp", "example.com:443").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn host_absent_accepts_any_host() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    };
    let response = run_accepted_post(settings, "/xhttp", "arbitrary.example").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn configured_host_exact_match_accepted() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        host: Some("example.com".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_accepted_post(settings, "/xhttp", "example.com").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn trailing_slash_path_accepted() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    };
    let response = run_accepted_post(settings, "/xhttp/", "example.com").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn host_with_non_default_port_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        host: Some("example.com".to_string()),
        ..XHttpSettings::default()
    };
    let response = run_request(
        settings,
        b"POST /xhttp HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 404 Not Found"));
}

#[test]
fn query_keys_extracts_names_without_values() {
    assert_eq!(
        query_keys("/xhttp?sessionId=abc&seqStr=1&flag"),
        vec![
            "sessionId".to_string(),
            "seqStr".to_string(),
            "flag".to_string()
        ]
    );
}

#[tokio::test]
async fn get_is_rejected_for_stream_one() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    };
    let response = run_request(
        settings,
        b"GET /xhttp HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 405 Method Not Allowed"));
}

#[tokio::test]
async fn correct_path_starts_stream_one_response() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    };
    let response = run_accepted_post(settings, "/xhttp", "example.com").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
}
