use std::sync::Arc;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::runtime::VlessInboundAuthContext;
use crate::vless::encryption::{
    build_encryption_server, handshake_and_wrap_with_rng, X25519SecretKey,
};
use crate::vless::handle_vless_tcp_inbound_with_auth_context;
use crate::vless::user_manager::VlessUserManager;
use crate::vless::vision::{encode_vision_flow_addons_protobuf, wrap_vision_uplink_block};
use crate::vless::VlessClient;

use super::client_sim::{
    build_native_x25519_client_hello, client_complete_1rtt_handshake, client_upload_writer,
    read_server_handshake_response, server_config_from_single_x25519,
};
use super::test_rng::TestHandshakeRng;

const USER_ID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

fn build_vless_tcp_request(user_id: &[u8; 16], port: u16, payload: &[u8]) -> Vec<u8> {
    build_vless_tcp_request_with_addons(user_id, &[], port, payload)
}

fn build_vless_tcp_request_with_addons(
    user_id: &[u8; 16],
    addons: &[u8],
    port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(addons.len() as u8);
    buf.extend_from_slice(addons);
    buf.push(0x01);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&[0x01, 127, 0, 0, 1]);
    buf.extend_from_slice(payload);
    buf
}

fn test_auth_context() -> VlessInboundAuthContext {
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("enc@test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    VlessInboundAuthContext::from_single_manager(
        Arc::new(VlessUserManager::new("enc-in", clients)),
        None,
    )
}

fn vision_auth_context() -> VlessInboundAuthContext {
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("enc-vision@test".to_string()),
        flow: Some("xtls-rprx-vision".to_string()),
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    VlessInboundAuthContext::from_single_manager(
        Arc::new(VlessUserManager::new("enc-in", clients)),
        None,
    )
}

#[tokio::test]
async fn encrypted_vless_header_parsed_by_runtime() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 64];
        let n = socket.read(&mut buf).await.expect("read payload");
        socket.write_all(&buf[..n]).await.expect("echo");
    });

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let (client_io, server_io) = duplex(65536);
    let vless_body = build_vless_tcp_request(&USER_ID, target_port, b"ping");
    let auth = test_auth_context();

    let client = tokio::spawn(async move {
        let mut encrypted =
            client_complete_1rtt_handshake(client_io, &hello, &parts, &config, 99, config.xor_mode)
                .await
                .expect("client handshake");
        encrypted
            .write_all(&vless_body)
            .await
            .expect("client handshake+traffic");
        encrypted.flush().await.expect("flush");
        let mut sink = [0u8; 4096];
        while encrypted.read(&mut sink).await.unwrap_or(0) > 0 {}
    });

    let encrypted =
        handshake_and_wrap_with_rng(server.as_ref(), server_io, &mut TestHandshakeRng::new(99))
            .await
            .expect("server handshake");

    let relay = tokio::spawn(async move {
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
            .await
    });

    client.await.expect("client task");
    relay.await.expect("relay task").expect("vless inbound");
}

#[tokio::test]
async fn encrypted_initial_payload_reaches_target_once() {
    use std::sync::Mutex;

    let initial_payload = b"CLIENT-TLS-CLIENTHELLO-BYTES";
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_task = Arc::clone(&captured);
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 512];
        let n = socket.read(&mut buf).await.expect("read");
        captured_task
            .lock()
            .expect("lock")
            .extend_from_slice(&buf[..n]);
        socket.write_all(b"ok").await.expect("write");
    });

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let vless_body = build_vless_tcp_request(&USER_ID, target_port, initial_payload);
    // Header-only portion ends before initial payload; entire blob is one encrypted record.
    let (client_io, server_io) = duplex(65536);
    let auth = test_auth_context();

    let client = tokio::spawn(async move {
        let mut encrypted =
            client_complete_1rtt_handshake(client_io, &hello, &parts, &config, 99, config.xor_mode)
                .await
                .expect("client");
        encrypted.write_all(&vless_body).await.expect("write");
        encrypted.flush().await.expect("flush");
        let mut sink = [0u8; 4096];
        while encrypted.read(&mut sink).await.unwrap_or(0) > 0 {}
    });

    let encrypted =
        handshake_and_wrap_with_rng(server.as_ref(), server_io, &mut TestHandshakeRng::new(99))
            .await
            .expect("handshake");

    let relay = tokio::spawn(async move {
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
            .await
    });

    client.await.expect("client");
    relay.await.expect("relay").expect("relay ok");
    assert_eq!(
        *captured.lock().expect("lock"),
        initial_payload.to_vec(),
        "initial payload must reach target exactly once"
    );
}

#[tokio::test]
async fn fragmented_vless_header_across_encrypted_records() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 64];
        let n = socket.read(&mut buf).await.expect("read");
        socket.write_all(&buf[..n]).await.expect("echo");
    });

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let full = build_vless_tcp_request(&USER_ID, target_port, b"tail-payload");
    let split_at = 12usize;
    assert!(split_at < full.len());
    let record_one = full[..split_at].to_vec();
    let record_two = full[split_at..].to_vec();

    let (client_io, server_io) = duplex(65536);
    let auth = test_auth_context();
    let hello_clone = hello.clone();
    let parts_clone = parts;

    let client = tokio::spawn(async move {
        let config = config.clone();
        let mut encrypted = client_complete_1rtt_handshake(
            client_io,
            &hello_clone,
            &parts_clone,
            &config,
            99,
            config.xor_mode,
        )
        .await
        .expect("client handshake");
        encrypted
            .write_all(&record_one)
            .await
            .expect("write record one");
        encrypted
            .write_all(&record_two)
            .await
            .expect("write record two");
        encrypted.flush().await.expect("flush");
        let mut sink = [0u8; 4096];
        while encrypted.read(&mut sink).await.unwrap_or(0) > 0 {}
    });

    let encrypted =
        handshake_and_wrap_with_rng(server.as_ref(), server_io, &mut TestHandshakeRng::new(99))
            .await
            .expect("handshake");

    let relay = tokio::spawn(async move {
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
            .await
    });

    client.await.expect("client");
    relay.await.expect("relay").expect("vless inbound");
}

#[tokio::test]
async fn encrypted_vision_flow_reaches_runtime() {
    let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02];
    let vision_payload = wrap_vision_uplink_block(&USER_ID, &tls_client_hello);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_task = Arc::clone(&captured);
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 512];
        let n = socket.read(&mut buf).await.expect("read");
        captured_task
            .lock()
            .expect("lock")
            .extend_from_slice(&buf[..n]);
        socket.write_all(b"ok").await.expect("write");
    });

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let addons = encode_vision_flow_addons_protobuf();
    let mut vless_body = build_vless_tcp_request_with_addons(&USER_ID, &addons, target_port, &[]);
    vless_body.extend_from_slice(&vision_payload);

    let (client_io, server_io) = duplex(65536);
    let auth = vision_auth_context();

    let client = tokio::spawn(async move {
        let mut encrypted =
            client_complete_1rtt_handshake(client_io, &hello, &parts, &config, 99, config.xor_mode)
                .await
                .expect("client");
        encrypted.write_all(&vless_body).await.expect("write");
        encrypted.flush().await.expect("flush");
        let mut sink = [0u8; 4096];
        while encrypted.read(&mut sink).await.unwrap_or(0) > 0 {}
    });

    let encrypted =
        handshake_and_wrap_with_rng(server.as_ref(), server_io, &mut TestHandshakeRng::new(99))
            .await
            .expect("handshake");

    let relay = tokio::spawn(async move {
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
            .await
    });

    client.await.expect("client");
    relay.await.expect("relay").expect("vision relay");
    assert_eq!(
        *captured.lock().expect("lock"),
        tls_client_hello.to_vec(),
        "vision-unpadded TLS client hello must reach target"
    );
}

#[tokio::test]
async fn encrypted_traffic_decrypt_failure_does_not_fallback() {
    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(7));

    let (mut client_io, server_io) = duplex(65536);
    let auth = test_auth_context();

    let client = tokio::spawn(async move {
        client_io.write_all(&hello).await.expect("hello");
        let response = read_server_handshake_response(&mut client_io, &config, 99)
            .await
            .expect("response");
        let _ = client_upload_writer(&parts, &response).expect("writer");
        client_io
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x20])
            .await
            .expect("bad frame header");
        client_io.write_all(&[0u8; 32]).await.expect("bad body");
        client_io.shutdown().await.ok();
    });

    let encrypted =
        handshake_and_wrap_with_rng(server.as_ref(), server_io, &mut TestHandshakeRng::new(5))
            .await
            .expect("handshake");

    let result =
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
            .await;

    client.await.expect("client");
    assert!(
        result.is_err(),
        "malformed encrypted traffic must fail closed"
    );
}
