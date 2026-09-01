//! Encrypted VLESS + Mux + XUDP through CommonConn.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{duplex, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::config::xray::raw::OutboundObject;
use crate::dns::DnsEngine;
use crate::mux::{encode_mux_keep_data, encode_mux_new_udp_xudp};
use crate::routing::RuntimeRouter;
use crate::runtime::{RuntimeOutboundManager, VlessInboundAuthContext};
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

fn freedom_router() -> Arc<RuntimeRouter> {
    let outbound = RuntimeOutboundManager::new();
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("direct".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("freedom outbound");
    RuntimeRouter::new(
        None,
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router")
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
async fn encrypted_xudp_association_returns_response() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
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
    let global_id = [0x42u8; 8];
    let mux_open = encode_mux_new_udp_xudp(7, &destination, &global_id, b"xudp-probe");
    let vless_body = build_vless_mux_request(&USER_ID, &mux_open);

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let (mut client_io, server_io) = duplex(65536);
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("enc-xudp@test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    let auth = VlessInboundAuthContext::from_single_manager(
        Arc::new(VlessUserManager::new("enc-in", clients)),
        None,
    );
    let router = freedom_router();

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
        handle_vless_tcp_inbound_with_auth_context(
            encrypted,
            &auth,
            &Default::default(),
            Some(&router),
        )
        .await
    });

    client.await.expect("client");
    tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay timeout")
        .expect("relay join")
        .expect("xudp relay");
}

#[tokio::test]
async fn encrypted_destinationless_xudp_keep_reuses_association() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
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
    let global_id = [0x55u8; 8];
    let mut mux_payload = encode_mux_new_udp_xudp(9, &destination, &global_id, b"first");
    mux_payload
        .extend(encode_mux_keep_data(9, b"destination-less keep").expect("destination-less keep"));

    let secret = X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8));
    let config = server_config_from_single_x25519(&secret);
    let server = build_encryption_server(&config).expect("server");
    let (hello, parts) =
        build_native_x25519_client_hello(&config, &secret, &mut TestHandshakeRng::new(42));

    let vless_body = build_vless_mux_request(&USER_ID, &mux_payload);
    let (mut client_io, server_io) = duplex(65536);
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("enc-xudp-keep@test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    let auth = VlessInboundAuthContext::from_single_manager(
        Arc::new(VlessUserManager::new("enc-in", clients)),
        None,
    );
    let router = freedom_router();

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
        handle_vless_tcp_inbound_with_auth_context(
            encrypted,
            &auth,
            &Default::default(),
            Some(&router),
        )
        .await
    });

    client.await.expect("client");
    tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("relay timeout")
        .expect("relay join")
        .expect("xudp keep relay");
}
