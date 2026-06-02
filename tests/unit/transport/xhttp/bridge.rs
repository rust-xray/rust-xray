use super::*;
use crate::vless::config::VlessClient;
use crate::vless::encode_vless_response_header;
use crate::vless::VlessUserManager;
use std::net::Ipv4Addr;

const USER_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const UNKNOWN_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn test_clients() -> Vec<VlessClient> {
    vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("user@example.com".to_string()),
        flow: None,
        level: None,
    }]
}

fn build_vless_tcp_request(user_id: [u8; 16], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&user_id);
    out.push(0);
    out.push(0x01);
    out.extend_from_slice(&port.to_be_bytes());
    out.push(0x01);
    out.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    out.extend_from_slice(payload);
    out
}

fn http1_post_request(path: &str, host: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn split_http_request(request: &[u8]) -> (Vec<u8>, Bytes) {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("headers")
        + 4;
    (
        request[..header_end].to_vec(),
        Bytes::copy_from_slice(&request[header_end..]),
    )
}

async fn run_http1_bridge_request(
    user_id: [u8; 16],
    clients: Vec<VlessClient>,
    body: Vec<u8>,
    duplex_capacity: usize,
) -> (Vec<u8>, io::Result<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outbound_port = listener.local_addr().unwrap().port();
    let drain_only = body.len() >= 1024 * 1024;
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if drain_only => continue,
                    Ok(n) => {
                        if socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });

    let mut vless_body = build_vless_tcp_request(user_id, outbound_port, &[]);
    vless_body.extend(body);
    let request = http1_post_request("/xhttp", "example.com", &vless_body);
    let (_, prebuffer) = split_http_request(&request);

    let (mut client, server) = tokio::io::duplex(duplex_capacity.max(512 * 1024));
    let bridge_result = async move {
        let users = VlessUserManager::new("xhttp-bridge-test", clients);
        run_http1_stream_one_bridge(
            server,
            prebuffer,
            Some(vless_body.len() as u64),
            "xhttp-bridge-test",
            1,
            Instant::now(),
            &users,
            None,
        )
        .await
    };
    let client_result = async move {
        for chunk in request.chunks(64 * 1024) {
            client.write_all(chunk).await?;
        }
        client.shutdown().await?;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await?;
        Ok::<_, io::Error>(response)
    };

    let (result, response) = tokio::join!(bridge_result, client_result);
    (response.unwrap(), result)
}

fn response_body(response: &[u8]) -> &[u8] {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers")
        + 4;
    &response[header_end..]
}

use tokio::net::TcpListener;

#[tokio::test]
async fn small_request_response_roundtrip() {
    let (response, result) =
        run_http1_bridge_request(USER_ID, test_clients(), b"ping".to_vec(), 8192).await;
    result.unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200 OK"));
    let body = response_body(&response);
    assert!(body
        .windows(2)
        .any(|w| w == encode_vless_response_header(0, None)));
}

#[tokio::test]
async fn ten_mb_request_pump_streams_without_full_buffer() {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (tx, mut rx) = mpsc::channel(XHTTP_BRIDGE_CHANNEL_CAPACITY);
    let body = vec![0xABu8; 10 * 1024 * 1024];
    let pump = tokio::spawn(pump_http1_request_body(
        server,
        Bytes::new(),
        Some(body.len() as u64),
        tx,
        42,
    ));
    let write_task = tokio::spawn(async move {
        let mut client = client;
        for chunk in body.chunks(64 * 1024) {
            client.write_all(chunk).await?;
        }
        client.shutdown().await
    });

    let mut total = 0usize;
    while let Some(Ok(chunk)) = rx.recv().await {
        total += chunk.len();
    }
    write_task.await.unwrap().unwrap();
    pump.await.unwrap();
    assert_eq!(total, 10 * 1024 * 1024);
}

#[tokio::test]
async fn large_transfer_roundtrip_through_bridge() {
    let payload = vec![0xCDu8; 256 * 1024];
    let (response, result) =
        run_http1_bridge_request(USER_ID, test_clients(), payload, 128 * 1024).await;
    result.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn eof_propagation_with_zero_length_body() {
    let (response, result) =
        run_http1_bridge_request(USER_ID, test_clients(), Vec::new(), 4096).await;
    result.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn vless_auth_failure_does_not_send_http_ok_or_leak_details() {
    let users = VlessUserManager::new("xhttp-bridge-test", Vec::new());
    let vless_body = build_vless_tcp_request(UNKNOWN_ID, 443, b"secret-payload");
    let request = http1_post_request("/xhttp", "example.com", &vless_body);
    let (_, prebuffer) = split_http_request(&request);

    let (mut client, server) = tokio::io::duplex(4096);
    let bridge_task = tokio::spawn(async move {
        run_http1_stream_one_bridge(
            server,
            prebuffer,
            Some(vless_body.len() as u64),
            "xhttp-bridge-test",
            2,
            Instant::now(),
            &users,
            None,
        )
        .await
    });

    client.write_all(&request).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response).await;
    let result = bridge_task.await.unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    let text = String::from_utf8_lossy(&response);
    assert!(!text.starts_with("HTTP/1.1 200 OK"));
    assert!(!text.to_ascii_lowercase().contains("permission"));
    assert!(!text.contains("secret-payload"));
}

#[tokio::test]
async fn client_disconnect_aborts_bridge_cleanly() {
    let vless_body = build_vless_tcp_request(USER_ID, 443, b"abc");
    let request = http1_post_request("/xhttp", "example.com", &vless_body);
    let (_, prebuffer) = split_http_request(&request);

    let (client, server) = tokio::io::duplex(1024);
    let bridge_task = tokio::spawn(async move {
        let users = VlessUserManager::new("xhttp-bridge-test", test_clients());
        run_http1_stream_one_bridge(
            server,
            prebuffer,
            Some(vless_body.len() as u64),
            "xhttp-bridge-test",
            3,
            Instant::now(),
            &users,
            None,
        )
        .await
    });

    drop(client);
    let result = bridge_task.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn bounded_backpressure_on_slow_reader() {
    let (req_tx, req_rx) = mpsc::channel(2);
    let mut reader = BridgeRequestReader {
        conn_id: 99,
        rx: req_rx,
        current: None,
        pos: 0,
        eof_logged: false,
    };

    req_tx.send(Ok(Bytes::from_static(b"a"))).await.unwrap();
    req_tx.send(Ok(Bytes::from_static(b"b"))).await.unwrap();
    assert!(req_tx.try_send(Ok(Bytes::from_static(b"c"))).is_err());

    let mut buf = [0u8; 1];
    assert_eq!(
        tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
            .await
            .unwrap(),
        1
    );
    assert_eq!(buf[0], b'a');
    assert_eq!(
        tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
            .await
            .unwrap(),
        1
    );
    assert_eq!(buf[0], b'b');
}
