//! Encrypted native VLESS UDP and generic Mux UDP through CommonConn.

use std::sync::Arc;

use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::mux::{encode_mux_keep_data, encode_mux_new_udp};
use crate::runtime::VlessInboundAuthContext;
use crate::vless::encryption::{
    build_encryption_server, handshake_and_wrap_with_rng, X25519SecretKey,
};
use crate::vless::handle_vless_tcp_inbound_with_auth_context;
use crate::vless::protocol::VlessDestination;
use crate::vless::udp_framing::encode_vless_udp_packet;
use crate::vless::user_manager::VlessUserManager;
use crate::vless::VlessClient;

use super::client_sim::{
    build_native_x25519_client_hello, client_1rtt_handshake_and_write,
    client_complete_1rtt_handshake, server_config_from_single_x25519,
};
use super::test_rng::TestHandshakeRng;

const USER_ID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

fn build_vless_udp_request(user_id: &[u8; 16], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(0);
    buf.push(0x02); // UDP command
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&[0x01, 127, 0, 0, 1]);
    buf.extend_from_slice(payload);
    buf
}

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
async fn encrypted_native_vless_udp_reaches_echo() {
    std::env::set_var("RUST_XRAY_VLESS_UDP_DOWNLINK_GRACE_MS", "50");
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let echo_port = echo.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((len, peer)) = echo.recv_from(&mut buf).await else {
                break;
            };
            echo.send_to(&buf[..len], peer).await.ok();
        }
    });

    let udp_frame = encode_vless_udp_packet(b"enc-native-udp").expect("frame");
    let vless_body = build_vless_udp_request(&USER_ID, echo_port, &udp_frame);

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let (mut client_io, server_io) = duplex(65536);
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("enc-udp@test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    let auth = VlessInboundAuthContext::from_single_manager(
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
        let _ = encrypted.shutdown().await;
        tokio::select! {
            _ = async {
                let mut sink = [0u8; 4096];
                while encrypted.read(&mut sink).await.unwrap_or(0) > 0 {}
            } => {}
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    });

    let encrypted =
        handshake_and_wrap_with_rng(server.as_ref(), server_io, &mut TestHandshakeRng::new(99))
            .await
            .expect("handshake");

    let relay = tokio::spawn(async move {
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay timeout")
        .expect("relay join")
        .expect("native udp relay");
    client.abort();
}

#[tokio::test]
async fn encrypted_generic_mux_udp_persistent_association() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let echo_port = echo.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((len, peer)) = echo.recv_from(&mut buf).await else {
                break;
            };
            echo.send_to(&buf[..len], peer).await.ok();
        }
    });

    let destination = VlessDestination::Domain("127.0.0.1".to_string(), echo_port);
    let mut mux_payload = encode_mux_new_udp(12, &destination, b"generic-open");
    mux_payload.extend(encode_mux_keep_data(12, b"generic-keep").expect("generic mux keep"));

    let vless_body = build_vless_mux_request(&USER_ID, &mux_payload);

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let (mut client_io, server_io) = duplex(65536);
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("enc-mux-udp@test".to_string()),
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
        .expect("generic mux udp relay");
}
