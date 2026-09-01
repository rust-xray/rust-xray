//! Encrypted VLESS + Mux TCP child through CommonConn (deterministic integration).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::mux::encode_mux_new_tcp;
use crate::runtime::VlessInboundAuthContext;
use crate::vless::encryption::{
    build_encryption_server, handshake_and_wrap_with_rng, X25519SecretKey,
};
use crate::vless::handle_vless_tcp_inbound_with_auth_context;
use crate::vless::protocol::VlessDestination;
use crate::vless::user_manager::VlessUserManager;
use crate::vless::VlessClient;

use super::client_sim::{
    build_native_x25519_client_hello, client_1rtt_handshake_and_write,
    server_config_from_single_x25519,
};
use super::test_rng::TestHandshakeRng;

const USER_ID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

fn build_vless_mux_request(user_id: &[u8; 16], mux_payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(0);
    buf.push(0x03);
    buf.extend_from_slice(mux_payload);
    buf
}

#[tokio::test]
async fn encrypted_mux_tcp_child_reaches_local_target() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    let captured_task = Arc::clone(&captured);
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 256];
        let n = socket.read(&mut buf).await.expect("read");
        captured_task
            .lock()
            .expect("lock")
            .extend_from_slice(&buf[..n]);
        socket.write_all(b"mux-tcp-reply").await.expect("write");
    });

    let destination = VlessDestination::Domain("127.0.0.1".to_string(), target_port);
    let mux_open = encode_mux_new_tcp(1, &destination, b"mux-tcp-payload");
    let vless_body = build_vless_mux_request(&USER_ID, &mux_open);

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let (mut client_io, server_io) = duplex(65536);
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("enc-mux@test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    let auth = VlessInboundAuthContext::from_single_manager(
        Arc::new(VlessUserManager::new("enc-in", clients)),
        None,
    );

    let client = tokio::spawn(async move {
        client_1rtt_handshake_and_write(
            client_io,
            &hello,
            &parts,
            &config,
            99,
            config.xor_mode,
            &vless_body,
        )
        .await
        .expect("client");
        tokio::time::sleep(Duration::from_millis(500)).await;
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
    tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay timeout")
        .expect("relay join")
        .expect("mux relay");
    assert_eq!(*captured.lock().expect("lock"), b"mux-tcp-payload".to_vec());
}
