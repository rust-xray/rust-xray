//! Low-level live TCP probes for XHTTP packet-up HTTP/1.1 chunked upload.
//!
//! Exercises `serve_xhttp_stream_one` over real `TcpStream` (same HTTP/1 adapter used
//! after REALITY TLS application data when the client omits the HTTP/2 connection preface).
//! This is **not** official Xray REALITY client interop over HTTP/1.1 origin.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use rust_xray::config::XHttpSettings;
use rust_xray::transport::xhttp::serve_xhttp_stream_one;
use rust_xray::vless::VlessUserManager;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

fn packet_up_settings(extra: BTreeMap<String, Value>) -> XHttpSettings {
    XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-up".to_string()),
        extra,
        ..XHttpSettings::default()
    }
}

async fn spawn_xhttp_tcp_server(settings: XHttpSettings) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe listener");
    let addr = listener.local_addr().expect("listener addr");
    let users = Arc::new(VlessUserManager::new("h1-chunked-live-probe", Vec::new()));
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let settings = settings.clone();
            let users = Arc::clone(&users);
            tokio::spawn(async move {
                let _ = serve_xhttp_stream_one(socket, &settings, users, None).await;
            });
        }
    });
    (addr, task)
}

async fn http1_exchange(addr: SocketAddr, request: impl AsRef<[u8]>) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect probe server");
    stream
        .write_all(request.as_ref())
        .await
        .expect("write request");
    stream.shutdown().await.expect("shutdown write half");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    response
}

async fn http1_exchange_partial(addr: SocketAddr, request: impl AsRef<[u8]>) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect probe server");
    stream
        .write_all(request.as_ref())
        .await
        .expect("write partial request");
    stream.shutdown().await.expect("shutdown write half");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_to_end(&mut response),
    )
    .await;
    response
}

fn chunked_post(session_id: &str, seq: u64, payload: &[u8]) -> Vec<u8> {
    format!(
        "POST /xhttp/{session_id}/{seq} HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        payload.len(),
        std::str::from_utf8(payload).unwrap_or("")
    )
    .into_bytes()
}

#[tokio::test]
async fn live_tcp_chunked_upload_accepted() {
    let settings = packet_up_settings(BTreeMap::new());
    let (addr, server) = spawn_xhttp_tcp_server(settings).await;
    let response = http1_exchange(addr, chunked_post("live-ok", 0, b"chunked-live")).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    server.abort();
}

#[tokio::test]
async fn live_tcp_malformed_chunked_rejected() {
    let settings = packet_up_settings(BTreeMap::new());
    let (addr, server) = spawn_xhttp_tcp_server(settings).await;
    let request = b"POST /xhttp/live-bad/0 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n";
    let response = http1_exchange(addr, request).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400 Bad Request"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    server.abort();
}

#[tokio::test]
async fn live_tcp_oversized_chunked_rejected() {
    let mut extra = BTreeMap::new();
    extra.insert("scMaxEachPostBytes".to_string(), Value::from(10));
    let settings = packet_up_settings(extra);
    let (addr, server) = spawn_xhttp_tcp_server(settings).await;
    let body = format!(
        "POST /xhttp/live-big/0 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n{}\r\n6\r\n{}\r\n0\r\n\r\n",
        "a".repeat(6),
        "b".repeat(6)
    );
    let response = http1_exchange(addr, body.into_bytes()).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 413 Payload Too Large"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    server.abort();
}

#[tokio::test]
async fn live_tcp_early_eof_cleans_session() {
    let settings = packet_up_settings(BTreeMap::new());
    let (addr, server) = spawn_xhttp_tcp_server(settings).await;
    let truncated = b"POST /xhttp/live-eof/0 HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
    let first = http1_exchange_partial(addr, truncated).await;
    assert!(
        String::from_utf8_lossy(&first).starts_with("HTTP/1.1 400 Bad Request"),
        "{}",
        String::from_utf8_lossy(&first)
    );
    let recovery = http1_exchange(addr, chunked_post("live-eof", 1, b"ok")).await;
    assert!(
        String::from_utf8_lossy(&recovery).starts_with("HTTP/1.1 200 OK"),
        "{}",
        String::from_utf8_lossy(&recovery)
    );
    server.abort();
}

#[tokio::test]
async fn live_tcp_duplicate_download_get_conflict() {
    use rust_xray::transport::xhttp::packet_up::shared_packet_up_manager;

    let settings = packet_up_settings(BTreeMap::new());
    let (addr, server) = spawn_xhttp_tcp_server(settings).await;
    let manager = shared_packet_up_manager();
    let _download_rx = manager
        .bind_download_session("live-dup")
        .expect("bind first download");
    let request = b"GET /xhttp/live-dup HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let response = http1_exchange(addr, request).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 409 Conflict"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    manager.detach_download_session("live-dup");
    server.abort();
}

#[tokio::test]
async fn live_tcp_stream_up_post_without_session_is_rejected() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-up".to_string()),
        ..XHttpSettings::default()
    };
    let (addr, server) = spawn_xhttp_tcp_server(settings).await;
    let request = b"POST /xhttp HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    let response = http1_exchange(addr, request).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400 Bad Request"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    server.abort();
}

#[tokio::test]
async fn live_tcp_packet_down_unsupported() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("packet-down".to_string()),
        ..XHttpSettings::default()
    };
    let (addr, server) = spawn_xhttp_tcp_server(settings).await;
    let request = b"POST /xhttp HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
    let response = http1_exchange(addr, request).await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 501 Not Implemented"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    server.abort();
}
