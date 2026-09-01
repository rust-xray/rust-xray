//! 0-RTT downstream VLESS runtime: TCP, Vision, Mux, XUDP, UDP, xorpub/random.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::config::xray::raw::OutboundObject;
use crate::config::XrayConfig;
use crate::dns::DnsEngine;
use crate::mux::{
    encode_mux_keep_data, encode_mux_new_tcp, encode_mux_new_udp, encode_mux_new_udp_xudp,
};
use crate::routing::RuntimeRouter;
use crate::runtime::{RuntimeOutboundManager, VlessInboundAuthContext};
use crate::stats::{StatsRegistry, StatsState};
use crate::vless::encryption::stream::VlessEncryptedStream;
use crate::vless::encryption::{
    compose_pfs_key, compose_united_key, VlessEncryptionServer, XorMode,
};
use crate::vless::handle_vless_tcp_inbound_with_auth_context;
use crate::vless::protocol::VlessDestination;
use crate::vless::udp_framing::encode_vless_udp_packet;
use crate::vless::user_manager::VlessUserManager;
use crate::vless::vision::{
    encode_vision_flow_addons_protobuf, wrap_vision_uplink_block, VisionDirectCapability,
    FLOW_XTLS_RPRX_VISION,
};
use crate::vless::VlessClient;

use super::client_sim::{
    build_zero_rtt_client_hello, build_zero_rtt_coalesced_wire, client_zero_rtt_duplex_stream,
    client_zero_rtt_stream, config_with_ticket_lifetime_and_xor, perform_1rtt_and_capture_resume,
    read_zero_rtt_random_download_payload, seal_client_traffic, server_config_with_ticket_lifetime,
    server_secret_for_tests, ClientResumeState,
};
use super::stream_helpers::{ScriptStream, StripServerPrewriteReader};
use super::test_rng::TestHandshakeRng;

const USER_ID: [u8; 16] = [0x11; 16];

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

fn build_vless_mux_request(user_id: &[u8; 16], mux_payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(0);
    buf.push(0x03);
    buf.extend_from_slice(mux_payload);
    buf
}

fn build_vless_udp_request(user_id: &[u8; 16], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(0);
    buf.push(0x02);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&[0x01, 127, 0, 0, 1]);
    buf.extend_from_slice(payload);
    buf
}

fn test_auth_context() -> VlessInboundAuthContext {
    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("0rtt@test".to_string()),
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
        email: Some("0rtt-vision@test".to_string()),
        flow: Some(FLOW_XTLS_RPRX_VISION.to_string()),
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    VlessInboundAuthContext::from_single_manager(
        Arc::new(VlessUserManager::new("enc-in", clients)),
        None,
    )
}

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

async fn zero_rtt_encrypted_stream(
    server: &VlessEncryptionServer,
    config: &crate::vless::encryption::Mlkem768X25519PlusConfig,
    resume: &ClientResumeState,
    coalesced: &[&[u8]],
    rng_seed: u64,
) -> VlessEncryptedStream<crate::vless::encryption::PrefixStream<ScriptStream>> {
    let secret = server_secret_for_tests();
    let (wire, _, _) = build_zero_rtt_coalesced_wire(
        config,
        resume,
        &secret,
        &mut TestHandshakeRng::new(rng_seed + 100),
        coalesced,
    );
    let (result, prefix) = server
        .handshake(
            ScriptStream::from_read(wire),
            &mut TestHandshakeRng::new(rng_seed),
        )
        .await
        .expect("0rtt handshake");
    assert!(result.is_zero_rtt);
    VlessEncryptedStream::from_handshake(prefix, result)
}

#[tokio::test]
async fn zero_rtt_tcp_full_pipeline_reaches_local_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 64];
        let n = socket.read(&mut buf).await.expect("read");
        socket.write_all(&buf[..n]).await.expect("echo");
    });

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let vless_body = build_vless_tcp_request(&USER_ID, target_port, b"0rtt-tcp-ping");
    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 7).await;
    let auth = test_auth_context();
    handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
        .await
        .expect("tcp inbound");
}

#[tokio::test]
async fn zero_rtt_immediate_vless_initial_payload_reaches_target_once() {
    let initial = b"0RTT-VLESS-INITIAL-PAYLOAD";
    let captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
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

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let vless_body = build_vless_tcp_request(&USER_ID, target_port, initial);
    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 8).await;
    let auth = test_auth_context();
    handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
        .await
        .expect("inbound");
    assert_eq!(*captured.lock().expect("lock"), initial.to_vec());
}

#[tokio::test]
async fn zero_rtt_commonconn_stable_after_first_record() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(9));
    let mut writer = super::client_sim::client_zero_rtt_upload_writer(&resume, &parts, &enc_ticket);
    let first = seal_client_traffic(&mut writer, b"record-one").expect("seal1");
    let second = seal_client_traffic(&mut writer, b"record-two").expect("seal2");
    let mut wire = hello;
    wire.extend_from_slice(&first);
    wire.extend_from_slice(&second);

    let (result, prefix) = server
        .handshake(ScriptStream::from_read(wire), &mut TestHandshakeRng::new(5))
        .await
        .expect("0rtt");
    let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
    let mut buf = [0u8; 32];
    let n1 = stream.read(&mut buf).await.expect("read1");
    assert_eq!(&buf[..n1], b"record-one");
    let n2 = stream.read(&mut buf).await.expect("read2");
    assert_eq!(&buf[..n2], b"record-two");
}

#[tokio::test]
async fn zero_rtt_vision_reaches_runtime_with_unpadded_tls_hello() {
    let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02];
    let vision_payload = wrap_vision_uplink_block(&USER_ID, &tls_client_hello);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
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

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let addons = encode_vision_flow_addons_protobuf();
    let mut vless_body = build_vless_tcp_request_with_addons(&USER_ID, &addons, target_port, &[]);
    vless_body.extend_from_slice(&vision_payload);

    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 10).await;
    let auth = vision_auth_context();
    handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
        .await
        .expect("vision inbound");
    assert_eq!(*captured.lock().expect("lock"), tls_client_hello.to_vec());
}

#[test]
fn zero_rtt_vision_direct_remains_blocked_by_encryption() {
    let blocked = VisionDirectCapability::blocked_by_vless_encryption();
    assert!(blocked.is_blocked());
    assert!(blocked.direct_relay().is_none());
}

#[tokio::test]
async fn zero_rtt_mux_coalesced_plaintext_matches_vless_body() {
    let destination = VlessDestination::Domain("127.0.0.1".to_string(), 9);
    let mux_open = encode_mux_new_tcp(1, &destination, b"0rtt-mux-tcp");
    let vless_body = build_vless_mux_request(&USER_ID, &mux_open);

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let mut encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 11).await;
    let mut out = vec![0u8; 512];
    let n = encrypted.read(&mut out).await.expect("read plaintext");
    assert_eq!(&out[..n], vless_body.as_slice());
}

#[tokio::test]
async fn zero_rtt_mux_tcp_child_reaches_local_target() {
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
        socket.write_all(b"mux-reply").await.expect("write");
    });

    let destination = VlessDestination::Domain("127.0.0.1".to_string(), target_port);
    let mux_open = encode_mux_new_tcp(1, &destination, b"0rtt-mux-tcp");
    let vless_body = build_vless_mux_request(&USER_ID, &mux_open);

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let (mut client_io, server_io) = duplex(65536);
    let vless_for_client = vless_body.clone();
    let resume_for_client = resume.clone();
    let config_for_client = config.clone();
    let client = tokio::spawn(async move {
        let (hello, parts, enc_ticket) = build_zero_rtt_client_hello(
            &config_for_client,
            &resume_for_client,
            &server_secret_for_tests(),
            &mut TestHandshakeRng::new(20),
        );
        client_io.write_all(&hello).await.expect("hello");
        let mut client_stream = client_zero_rtt_stream(
            client_io,
            &resume_for_client,
            &parts,
            &enc_ticket,
            config_for_client.xor_mode,
        )
        .expect("client");
        client_stream
            .write_all(&vless_for_client)
            .await
            .expect("vless");
        client_stream.flush().await.expect("flush");
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let (result, prefix) = server
        .handshake(server_io, &mut TestHandshakeRng::new(11))
        .await
        .expect("0rtt mux handshake");
    assert!(result.is_zero_rtt);
    let encrypted = VlessEncryptedStream::from_handshake(prefix, result);
    let auth = test_auth_context();
    let relay = tokio::spawn(async move {
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
            .await
    });

    client.await.expect("client");
    let _ = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .expect("timeout")
        .expect("mux inbound");
    assert_eq!(*captured.lock().expect("lock"), b"0rtt-mux-tcp".to_vec());
}

#[tokio::test]
async fn zero_rtt_xudp_association_returns_response() {
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
    let global_id = [0x42u8; 8];
    let mux_open = encode_mux_new_udp_xudp(7, &destination, &global_id, b"0rtt-xudp");
    let vless_body = build_vless_mux_request(&USER_ID, &mux_open);

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 12).await;
    let auth = test_auth_context();
    let router = freedom_router();
    tokio::time::timeout(
        Duration::from_secs(5),
        handle_vless_tcp_inbound_with_auth_context(
            encrypted,
            &auth,
            &Default::default(),
            Some(&router),
        ),
    )
    .await
    .expect("timeout")
    .expect("xudp inbound");
}

#[tokio::test]
async fn zero_rtt_destinationless_xudp_keep_reuses_association() {
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
    let global_id = [0x55u8; 8];
    let mut mux_payload = encode_mux_new_udp_xudp(9, &destination, &global_id, b"first");
    mux_payload.extend(encode_mux_keep_data(9, b"0rtt-destless-keep").expect("keep"));
    let vless_body = build_vless_mux_request(&USER_ID, &mux_payload);

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 13).await;
    let auth = test_auth_context();
    let router = freedom_router();
    tokio::time::timeout(
        Duration::from_secs(5),
        handle_vless_tcp_inbound_with_auth_context(
            encrypted,
            &auth,
            &Default::default(),
            Some(&router),
        ),
    )
    .await
    .expect("timeout")
    .expect("xudp keep");
}

#[tokio::test]
async fn zero_rtt_native_vless_udp_reaches_echo() {
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

    let udp_frame = encode_vless_udp_packet(b"0rtt-native-udp").expect("frame");
    let vless_body = build_vless_udp_request(&USER_ID, echo_port, &udp_frame);

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 14).await;
    let auth = test_auth_context();
    tokio::time::timeout(
        Duration::from_secs(5),
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None),
    )
    .await
    .expect("timeout")
    .expect("native udp");
}

#[tokio::test]
async fn zero_rtt_generic_mux_udp_persistent_association() {
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
    let mut mux_payload = encode_mux_new_udp(12, &destination, b"0rtt-generic-open");
    mux_payload.extend(encode_mux_keep_data(12, b"0rtt-generic-keep").expect("keep"));
    let vless_body = build_vless_mux_request(&USER_ID, &mux_payload);

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 15).await;
    let auth = test_auth_context();
    tokio::time::timeout(
        Duration::from_secs(5),
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None),
    )
    .await
    .expect("timeout")
    .expect("generic mux udp");
}

async fn run_zero_rtt_full_duplex(mode: XorMode, client_a: &[u8], server_b: &[u8]) {
    let client_a = client_a.to_vec();
    let server_b = server_b.to_vec();
    let secret = server_secret_for_tests();
    let config = config_with_ticket_lifetime_and_xor(&secret, 600, 600, mode);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let (coalesced, parts, enc_ticket) = build_zero_rtt_coalesced_wire(
        &config,
        &resume,
        &secret,
        &mut TestHandshakeRng::new(42),
        &[client_a.as_slice()],
    );

    let (mut client_io, server_io) = duplex(512 * 1024);
    let (server_random_tx, server_random_rx) = tokio::sync::oneshot::channel();

    let client_a_for_server = client_a.clone();
    let server_b_for_server = server_b.clone();
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let (result, prefix) = server
                .handshake(server_io, &mut TestHandshakeRng::new(5))
                .await
                .expect("0rtt server");
            assert!(result.is_zero_rtt);
            if mode == XorMode::Random {
                assert!(result.xor_conn.is_some());
                assert_eq!(result.xor_conn.as_ref().expect("xor").outbound_skip, 16);
            }
            let server_random = result.server_prewrite.expect("prewrite");
            let _ = server_random_tx.send(server_random);

            let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
            let mut buf = vec![0u8; client_a_for_server.len().max(8192)];
            let n = stream.read(&mut buf).await.expect("server read A");
            assert_eq!(&buf[..n], client_a_for_server.as_slice());

            stream
                .write_all(&server_b_for_server)
                .await
                .expect("server write B");
            stream.flush().await.expect("server flush");
        })
    };

    client_io.write_all(&coalesced).await.expect("client wire");
    client_io.flush().await.expect("client flush");

    let server_random = server_random_rx.await.expect("server random");
    server_task.await.expect("server task");

    if mode == XorMode::Random {
        let out_b = read_zero_rtt_random_download_payload(
            client_io,
            &server_random,
            &resume,
            &parts,
            server_b.len(),
        )
        .await
        .expect("random download");
        assert_eq!(out_b, server_b, "client must read exact server payload B");
        return;
    }

    let read_io = StripServerPrewriteReader::new(client_io, server_random);
    let mut download =
        client_zero_rtt_duplex_stream(read_io, &resume, &parts, &enc_ticket, &server_random, mode)
            .expect("download client");

    let mut out_b = vec![0u8; server_b.len()];
    download
        .read_exact(&mut out_b)
        .await
        .expect("client read B");
    assert_eq!(out_b, server_b, "client must read exact server payload B");
}

#[tokio::test]
async fn zero_rtt_random_download_decrypt_matrix_finds_working_combo() {
    use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
    use crate::vless::encryption::aead::TrafficAead;
    use crate::vless::encryption::handshake::TrafficDirectionKeys;
    use crate::vless::encryption::header::decode_traffic_header;
    use crate::vless::encryption::stream::{EncryptedReader, XorTrafficReader};

    let server_b = b"random-matrix-payload".to_vec();
    let secret = server_secret_for_tests();
    let config = config_with_ticket_lifetime_and_xor(&secret, 600, 600, XorMode::Random);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;
    let (coalesced, parts, _enc_ticket) = build_zero_rtt_coalesced_wire(
        &config,
        &resume,
        &secret,
        &mut TestHandshakeRng::new(42),
        &[b"client-uplink"],
    );

    let (mut client_io, server_io) = duplex(512 * 1024);
    let (server_random_tx, server_random_rx) = tokio::sync::oneshot::channel();
    let server_b_for_server = server_b.clone();
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let (result, prefix) = server
                .handshake(server_io, &mut TestHandshakeRng::new(5))
                .await
                .expect("0rtt");
            let server_random = result.server_prewrite.expect("prewrite");
            let _ = server_random_tx.send(server_random);
            let mut stream = VlessEncryptedStream::from_handshake(prefix, result);
            let mut sink = [0u8; 32];
            let _ = stream.read(&mut sink).await;
            stream.write_all(&server_b_for_server).await.expect("write");
            stream.flush().await.expect("flush");
        })
    };
    client_io.write_all(&coalesced).await.expect("wire");
    client_io.flush().await.expect("flush");
    let server_random = server_random_rx.await.expect("random");
    server_task.await.expect("server");

    let mut raw = Vec::new();
    client_io.read_to_end(&mut raw).await.expect("read raw");
    assert!(raw.len() > 16);

    let pfs = compose_pfs_key(
        resume.pfs_key[..MLKEM768_SHARED_SECRET_LEN]
            .try_into()
            .expect("mlkem"),
        resume.pfs_key[MLKEM768_SHARED_SECRET_LEN..]
            .try_into()
            .expect("x25519"),
    );
    let united = *compose_united_key(&pfs, &parts.nfs_key).as_bytes();

    let mut winning = None;
    for skip in [0usize, 16] {
        for first_record in [true, false] {
            if raw.len() <= 16 {
                continue;
            }
            let mut frame = raw[16..].to_vec();
            let mut xor =
                XorTrafficReader::new_client_download_with_skip(&united, &server_random, skip);
            crate::vless::encryption::stream::apply_xor_read_for_test(&mut xor, &mut frame);
            if frame.len() < 5 {
                continue;
            }
            let header: [u8; 5] = frame[..5].try_into().expect("hdr");
            if decode_traffic_header(&header).is_err() {
                continue;
            }
            let payload_len = decode_traffic_header(&header).expect("len") as usize;
            if frame.len() < 5 + payload_len {
                continue;
            }
            let body = &frame[5..5 + payload_len];
            let download = TrafficDirectionKeys {
                aead: TrafficAead::new(&server_random, &united, resume.use_aes),
                context_label: server_random.to_vec(),
            };
            let mut reader = if first_record {
                EncryptedReader::new(download, united, resume.use_aes)
            } else {
                EncryptedReader::new_post_handshake(download, united, resume.use_aes)
            };
            if reader.decrypt_record(&header, body).is_ok() {
                winning = Some((skip, first_record));
            }
        }
    }
    let (skip, first_record) = winning.expect("expected at least one decrypt combo to succeed");
    assert_eq!((skip, first_record), (16, false));
}

#[tokio::test]
async fn zero_rtt_xorpub_full_duplex_asymmetric_payloads() {
    let payload_a: Vec<u8> = (0..1237).map(|i| (i % 251) as u8).collect();
    let payload_b: Vec<u8> = (0..2741).map(|i| ((i * 7) % 253) as u8).collect();
    run_zero_rtt_full_duplex(XorMode::XorPub, &payload_a, &payload_b).await;
}

#[tokio::test]
async fn zero_rtt_random_full_duplex_asymmetric_payloads_and_outbound_skip() {
    let payload_a: Vec<u8> = (0..900).map(|i| (i % 241) as u8).collect();
    let payload_b: Vec<u8> = (0..1500).map(|i| ((i * 5) % 257) as u8).collect();
    run_zero_rtt_full_duplex(XorMode::Random, &payload_a, &payload_b).await;
}

#[tokio::test]
async fn zero_rtt_stats_count_logical_payload_not_handshake_overhead() {
    let uplink = vec![0xCDu8; 1000];
    let downlink = vec![0xEFu8; 2000];
    let uplink_for_target = uplink.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target_port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 4096];
        let n = socket.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], uplink_for_target.as_slice());
        socket.write_all(&downlink).await.expect("write");
    });

    let registry = Arc::new(StatsRegistry::new());
    let xray: XrayConfig = serde_json::from_str(
        r#"{
            "stats": {},
            "policy": {
                "system": {
                    "statsInboundUplink": true,
                    "statsInboundDownlink": true
                }
            }
        }"#,
    )
    .expect("parse config");
    let stats_state = StatsState::from_xray_config_with_registry(
        &xray,
        Arc::clone(&registry),
        "enc-in".to_string(),
    );

    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let vless_body = build_vless_tcp_request(&USER_ID, target_port, &uplink);
    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&vless_body], 16).await;

    let clients = vec![VlessClient {
        id: uuid::Uuid::from_bytes(USER_ID),
        email: Some("0rtt-stats@test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }];
    let auth = VlessInboundAuthContext::from_single_manager(
        Arc::new(VlessUserManager::new("enc-in", clients)),
        Some(Arc::new(stats_state)),
    );

    handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
        .await
        .expect("stats inbound");

    assert_eq!(
        registry
            .get("inbound>>>enc-in>>>traffic>>>uplink", false)
            .unwrap_or(0),
        1000
    );
    assert_eq!(
        registry
            .get("inbound>>>enc-in>>>traffic>>>downlink", false)
            .unwrap_or(0),
        2000
    );
}

#[tokio::test]
async fn zero_rtt_accepted_resume_malformed_vless_fails_closed() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let garbage = [0xFFu8; 8];
    let encrypted =
        zero_rtt_encrypted_stream(server.as_ref(), &config, &resume, &[&garbage], 17).await;
    let auth = test_auth_context();
    let result =
        handle_vless_tcp_inbound_with_auth_context(encrypted, &auth, &Default::default(), None)
            .await;
    assert!(
        result.is_err(),
        "malformed vless after accepted 0rtt must fail"
    );
}
