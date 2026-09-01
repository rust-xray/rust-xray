use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use uuid::Uuid;

use crate::config::xray::raw::OutboundObject;
use crate::dns::DnsEngine;
use crate::mux::encoder::encode_mux_new_udp_xudp;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::session::handle_mux_cool_inbound_with_env;
use crate::mux::xudp::{XudpManager, XudpManagerConfig, XudpStatus};
use crate::reality::post_handshake::UselessRecordTolerance;
use crate::reality::tls13::{
    is_useless_record_overflow, tls13_cipher_suite, useless_record_overflow_limit,
    RealityTls13ApplicationStream, SplitMuxInbound, Tls13RecordDecryptor, Tls13RecordEncryptor,
    TLS_AES_128_GCM_SHA256,
};
use crate::routing::{RouteSocketMeta, RuntimeRouter};
use crate::runtime::RuntimeOutboundManager;
use crate::tls::records::{
    parse_tls_records, TLS13_COMPATIBILITY_CCS_RECORD, TLS_LEGACY_VERSION_1_2,
};
use crate::tls::TlsRecordContentType;
use crate::vless::protocol::VlessDestination;
use crate::vless::user_manager::VlessAuthenticatedClient;

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

fn aes128_keys(seed: u8) -> crate::reality::tls13::Tls13TrafficKeys {
    crate::reality::tls13::Tls13TrafficKeys {
        key: (seed..seed + 16).collect(),
        iv: (0x01..0x0d).collect(),
    }
}

fn server_to_client_pair(seed: u8) -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let keys = aes128_keys(seed);
    (
        Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor"),
        Tls13RecordDecryptor::new(suite, keys).expect("decryptor"),
    )
}

async fn read_one_record_from_peer(peer: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let read = peer.read(&mut buf).await.expect("read one TLS record");
    buf.truncate(read);
    buf
}

async fn read_fatal_overflow_alert_record(
    peer: &mut (impl AsyncReadExt + Unpin),
    decryptor: &mut Tls13RecordDecryptor,
) -> u64 {
    for _ in 0..8 {
        let record_bytes = read_one_record_from_peer(peer).await;
        if record_bytes.is_empty() {
            continue;
        }
        let records = parse_tls_records(&record_bytes).expect("parse TLS records");
        for record in records {
            if record.content_type != TlsRecordContentType::ApplicationData {
                continue;
            }
            let sequence_before = decryptor.sequence;
            let inner = decryptor
                .decrypt_record_payload(&record)
                .expect("AEAD decrypt TLS application record");
            if inner == [0x02, 0x0a, 0x15] {
                assert_eq!(
                    decryptor.sequence,
                    sequence_before + 1,
                    "exactly one encrypted fatal alert at current write sequence"
                );
                assert_eq!(
                    record.legacy_version, TLS_LEGACY_VERSION_1_2,
                    "legacy version"
                );
                return sequence_before;
            }
        }
    }
    panic!("fatal unexpected_message alert not found on REALITY wire");
}

fn test_auth() -> VlessAuthenticatedClient {
    VlessAuthenticatedClient {
        id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid"),
        email: Some("xudp@example.test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        inbound_tag: "vless-in".to_string(),
    }
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

fn test_route_env(router: Arc<RuntimeRouter>, xudp: Arc<XudpManager>) -> MuxRouteEnv {
    MuxRouteEnv {
        router,
        inbound_tag: "vless-in".to_string(),
        auth: test_auth(),
        socket_meta: RouteSocketMeta::default(),
        sniffing_enabled: false,
        vision_mux_udp_only: false,
        stats: None,
        xudp,
        test_dispatch_counter: None,
    }
}

async fn bind_echo_udp() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.expect("recv");
            let _ = socket.send_to(&buf[..len], peer).await;
        }
    });
    addr
}

async fn run_split_mux_xudp_with_production_overflow_handling<R, W>(
    mut mux_stream: SplitMuxInbound<R, W>,
    route_env: MuxRouteEnv,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin + crate::reality::tls13::Tls13OverflowAlertWriter,
{
    let result = handle_mux_cool_inbound_with_env(
        &mut mux_stream,
        DnsEngine::shared(),
        None,
        Some(route_env),
    )
    .await;
    if let Err(err) = result {
        if useless_record_overflow_limit(&err).is_some() {
            let _ = mux_stream.send_useless_overflow_fatal_alert().await;
        }
        return Err(err);
    }
    Ok(())
}

#[test]
fn reality_mux_xudp_overflow_emits_encrypted_fatal_alert() {
    block_on(async {
        let echo = bind_echo_udp().await;
        let manager = Arc::new(XudpManager::new(XudpManagerConfig {
            expiry: Duration::from_secs(60),
            ..Default::default()
        }));
        let route_env = test_route_env(freedom_router(), Arc::clone(&manager));

        let global_id = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];
        let destination = VlessDestination::Ip(echo.ip(), echo.port());
        let initial_payload = encode_mux_new_udp_xudp(30, &destination, &global_id, b"xudp-probe");

        let (mut client_io, server_io) = duplex(8192);
        let (_client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (server_encryptor, server_alert_decryptor) = server_to_client_pair(0x20);

        let stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );
        let split = stream.split_for_relay().expect("split");
        let mux_stream = SplitMuxInbound::new(split.reader, split.writer, initial_payload);

        let manager_for_wait = Arc::clone(&manager);
        let server_task = tokio::spawn(run_split_mux_xudp_with_production_overflow_handling(
            mux_stream, route_env,
        ));

        for _ in 0..50 {
            if manager_for_wait.status_of(global_id).await == Some(XudpStatus::Active) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            manager_for_wait.status_of(global_id).await,
            Some(XudpStatus::Active),
            "XUDP association must be active before useless-record overflow"
        );
        assert_eq!(
            manager_for_wait.association_count().await,
            1,
            "exactly one manager entry for GlobalID"
        );

        for _ in 0..2 {
            client_io
                .write_all(&TLS13_COMPATIBILITY_CCS_RECORD)
                .await
                .expect("write useless CCS");
        }

        let mux_err = server_task
            .await
            .expect("mux task join")
            .expect_err("overflow terminates REALITY mux+XUDP");
        assert!(is_useless_record_overflow(&mux_err));
        assert_eq!(useless_record_overflow_limit(&mux_err), Some(1));

        let mut decryptor = server_alert_decryptor;
        let alert_sequence_before =
            read_fatal_overflow_alert_record(&mut client_io, &mut decryptor).await;
        assert!(
            alert_sequence_before >= 1,
            "XUDP mux response must precede overflow alert on REALITY wire"
        );

        assert_eq!(
            manager_for_wait.association_count().await,
            1,
            "parent mux failure must not duplicate manager entries"
        );
    });
}

#[test]
fn reality_mux_xudp_overflow_alert_uses_current_application_write_sequence() {
    block_on(async {
        let echo = bind_echo_udp().await;
        let manager = Arc::new(XudpManager::new(XudpManagerConfig {
            expiry: Duration::from_secs(60),
            ..Default::default()
        }));
        let route_env = test_route_env(freedom_router(), Arc::clone(&manager));

        let global_id = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        let destination = VlessDestination::Ip(echo.ip(), echo.port());
        let initial_payload = encode_mux_new_udp_xudp(31, &destination, &global_id, b"seq-probe");

        let (mut client_io, server_io) = duplex(8192);
        let (_client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (mut server_encryptor, mut server_alert_decryptor) = server_to_client_pair(0x20);
        server_encryptor
            .encrypt_application_data(b"mux-response-prefix")
            .expect("prior app write");

        let stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );
        let split = stream.split_for_relay().expect("split");
        let mux_stream = SplitMuxInbound::new(split.reader, split.writer, initial_payload);

        let server_task = tokio::spawn(run_split_mux_xudp_with_production_overflow_handling(
            mux_stream, route_env,
        ));

        for _ in 0..50 {
            if manager.status_of(global_id).await == Some(XudpStatus::Active) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        for _ in 0..2 {
            client_io
                .write_all(&TLS13_COMPATIBILITY_CCS_RECORD)
                .await
                .expect("write useless CCS");
        }

        let mux_err = server_task.await.expect("join").expect_err("overflow");
        assert!(is_useless_record_overflow(&mux_err));

        let mut wire = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_millis(50), client_io.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => wire.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        let records = parse_tls_records(&wire).expect("parse REALITY wire records");
        assert!(
            records.len() >= 2,
            "XUDP mux response and overflow alert must both be present on wire"
        );
        server_alert_decryptor.sequence = 2;
        let inner = server_alert_decryptor
            .decrypt_record_payload(records.last().expect("alert record"))
            .expect("AEAD decrypt overflow alert at current write sequence");
        assert_eq!(inner, [0x02, 0x0a, 0x15]);
    });
}
