//! Paired Vision DIRECT capability: unencrypted REALITY vs encrypted CommonConn.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use crate::reality::tls13::ApplicationStreamDirectRelay;
use crate::vless::encryption::{
    build_encryption_server, handshake_and_wrap_with_rng, X25519SecretKey,
};
use crate::vless::handle_vless_tcp_inbound_with_auth_context;
use crate::vless::user_manager::VlessUserManager;
use crate::vless::vision::{
    encode_vision_flow_addons_protobuf, wrap_vision_uplink_block, VisionDirectCapability,
    VisionRelayReader, COMMAND_PADDING_DIRECT, FLOW_XTLS_RPRX_VISION,
};
use crate::vless::VlessClient;

use super::client_sim::{
    build_native_x25519_client_hello, client_complete_1rtt_handshake,
    server_config_from_single_x25519,
};
use super::test_rng::TestHandshakeRng;

const USER_ID: [u8; 16] = [0x11; 16];

fn vision_direct_uplink_frame(tail: &[u8]) -> Vec<u8> {
    let mut framed = Vec::new();
    framed.extend_from_slice(&USER_ID);
    framed.push(COMMAND_PADDING_DIRECT);
    framed.extend_from_slice(&(tail.len() as u16).to_be_bytes());
    framed.extend_from_slice(&0u16.to_be_bytes());
    framed.extend_from_slice(tail);
    framed
}

#[tokio::test]
async fn unencrypted_vision_direct_relay_allowed_on_direct_command() {
    let traffic = crate::vless::vision::new_shared_traffic_state(USER_ID);
    let reader_flag = Arc::new(AtomicBool::new(false));
    let writer_flag = Arc::new(AtomicBool::new(false));
    let direct_relay =
        ApplicationStreamDirectRelay::from_shared(Arc::clone(&reader_flag), writer_flag);
    let capability = VisionDirectCapability::from_reality_tls_split(direct_relay.clone());

    let framed = vision_direct_uplink_frame(b"direct-tail");
    let (mut client, server) = duplex(4096);
    client.write_all(&framed).await.expect("write");
    drop(client);

    let mut reader = VisionRelayReader::new(server, traffic, capability.direct_relay());
    let mut out = [0u8; 32];
    let read = reader.read(&mut out).await.expect("read");
    assert_eq!(&out[..read], b"direct-tail");
    assert!(
        reader_flag.load(Ordering::SeqCst),
        "unencrypted REALITY Vision must enable TLS direct relay on COMMAND_DIRECT"
    );
}

#[tokio::test]
async fn encrypted_vision_blocks_direct_relay_on_direct_command() {
    let capability = VisionDirectCapability::blocked_by_vless_encryption();
    assert!(capability.is_blocked());
    assert!(capability.direct_relay().is_none());

    let traffic = crate::vless::vision::new_shared_traffic_state(USER_ID);
    let framed = vision_direct_uplink_frame(b"enc-direct-blocked");

    let (mut client, server) = duplex(4096);
    client.write_all(&framed).await.expect("write");
    drop(client);

    let mut reader = VisionRelayReader::new(server, traffic, capability.direct_relay());
    let mut out = [0u8; 32];
    let read = reader.read(&mut out).await.expect("read unpadded");
    assert_eq!(&out[..read], b"enc-direct-blocked");
}

#[tokio::test]
async fn encrypted_vision_runtime_never_enables_tls_direct_relay() {
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

    let (mut client_io, server_io) = duplex(65536);
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("vision-enc@test".to_string()),
        flow: Some(FLOW_XTLS_RPRX_VISION.to_string()),
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
fn vision_direct_capability_blocked_has_no_relay_handle() {
    let blocked = VisionDirectCapability::blocked_by_vless_encryption();
    assert!(blocked.is_blocked());
    assert!(blocked.direct_relay().is_none());
}
