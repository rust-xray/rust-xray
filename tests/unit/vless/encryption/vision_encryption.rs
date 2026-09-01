//! Vision + VLESS encryption: DIRECT must not bypass CommonConn on encrypted inbounds.

use std::sync::Arc;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use crate::vless::encryption::{
    build_encryption_server, handshake_and_wrap_with_rng, X25519SecretKey,
};
use crate::vless::handle_vless_tcp_inbound_with_auth_context;
use crate::vless::user_manager::VlessUserManager;
use crate::vless::vision::{encode_vision_flow_addons_protobuf, wrap_vision_uplink_block};
use crate::vless::VlessClient;

use super::client_sim::{
    build_native_x25519_client_hello, client_complete_1rtt_handshake,
    server_config_from_single_x25519,
};
use super::stream_common::build_client_frames;
use super::stream_helpers::ScriptStream;
use super::test_rng::TestHandshakeRng;

const USER_ID: [u8; 16] = [0x11; 16];

#[tokio::test]
async fn encrypted_vision_path_has_no_tls_direct_relay() {
    // Encrypted inbound uses handle_vless_tcp_inbound_with_auth_context which passes
    // direct_relay=None into relay_vless_tcp_bidirectional — Vision DIRECT cannot
    // splice around CommonConn even after padding ends.
    let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x08, 0x01];
    let vision_payload = wrap_vision_uplink_block(&USER_ID, &tls_client_hello);
    let addons = encode_vision_flow_addons_protobuf();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 256];
            if let Ok(n) = socket.read(&mut buf).await {
                let _ = socket.write_all(&buf[..n]).await;
            }
        }
    });

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let mut vless_body = Vec::new();
    vless_body.push(0);
    vless_body.extend_from_slice(&USER_ID);
    vless_body.push(addons.len() as u8);
    vless_body.extend_from_slice(&addons);
    vless_body.push(0x01);
    vless_body.extend_from_slice(&port.to_be_bytes());
    vless_body.extend_from_slice(&[0x01, 127, 0, 0, 1]);
    vless_body.extend_from_slice(&vision_payload);

    let (client_io, server_io) = duplex(65536);
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("vision-enc@test".to_string()),
        flow: Some("xtls-rprx-vision".to_string()),
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    let auth = crate::runtime::VlessInboundAuthContext::from_single_manager(
        Arc::new(VlessUserManager::new("enc-in", clients)),
        None,
    );

    let client = tokio::spawn(async move {
        let mut encrypted =
            client_complete_1rtt_handshake(client_io, &hello, &parts, &config, 99, config.xor_mode)
                .await
                .expect("client");
        encrypted.write_all(&vless_body).await.expect("write");
        encrypted.flush().await.expect("flush");
        let mut sink = [0u8; 512];
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
    relay.await.expect("relay task").expect("relay ok");
}

#[test]
fn encrypted_traffic_frames_remain_tls_application_records() {
    let wire = build_client_frames(&[b"vision-direct-wire-check"]);
    assert!(
        wire.starts_with(&[0x17, 0x03, 0x03]),
        "CommonConn wire prefix"
    );
    let mut stream = super::stream_common::make_encrypted_on(ScriptStream::from_read(wire), true);
    let out = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
                .await
                .expect("read");
            buf
        });
    assert_eq!(out, b"vision-direct-wire-check");
}
