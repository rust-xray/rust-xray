use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::config::xray::raw::OutboundObject;
use crate::dns::DnsEngine;
use crate::mux::encoder::encode_mux_new_udp;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::session::handle_mux_cool_inbound_with_env;
use crate::mux::xudp::{XudpManager, XudpManagerConfig};
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
use uuid::Uuid;

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

async fn bind_echo_udp() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..len], peer).await;
        }
    });
    addr
}

async fn read_fatal_overflow_alert_record(
    peer: &mut (impl AsyncReadExt + Unpin),
    decryptor: &mut Tls13RecordDecryptor,
) -> u64 {
    for _ in 0..8 {
        let mut buf = vec![0u8; 4096];
        let read = peer.read(&mut buf).await.expect("read TLS wire");
        if read == 0 {
            continue;
        }
        buf.truncate(read);
        let records = parse_tls_records(&buf).expect("parse TLS records");
        for record in records {
            if record.content_type != TlsRecordContentType::ApplicationData {
                continue;
            }
            let sequence_before = decryptor.sequence;
            let inner = decryptor
                .decrypt_record_payload(&record)
                .expect("decrypt TLS app record");
            if inner == [0x02, 0x0a, 0x15] {
                assert_eq!(decryptor.sequence, sequence_before + 1);
                assert_eq!(record.legacy_version, TLS_LEGACY_VERSION_1_2);
                return sequence_before;
            }
        }
    }
    panic!("fatal unexpected_message alert not found");
}

#[test]
fn reality_mux_generic_udp_overflow_emits_encrypted_fatal_alert() {
    block_on(async {
        let echo = bind_echo_udp().await;
        let outbound = RuntimeOutboundManager::new();
        outbound
            .register_startup_outbound(&OutboundObject {
                tag: Some("direct".to_string()),
                protocol: Some("freedom".to_string()),
                extra: Default::default(),
            })
            .expect("freedom");
        let router = RuntimeRouter::new(
            None,
            outbound,
            Arc::new(DnsEngine::with_mux_defaults()),
            false,
            None,
        )
        .expect("router");
        let route_env = MuxRouteEnv {
            router,
            inbound_tag: "vless-in".to_string(),
            auth: VlessAuthenticatedClient {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid"),
                email: None,
                flow: None,
                level: None,
                testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
                inbound_tag: "vless-in".to_string(),
            },
            socket_meta: RouteSocketMeta::default(),
            sniffing_enabled: false,
            vision_mux_udp_only: false,
            stats: None,
            xudp: XudpManager::new(XudpManagerConfig::default()),
            test_dispatch_counter: None,
        };

        let destination = VlessDestination::Ip(echo.ip(), echo.port());
        let initial_payload = encode_mux_new_udp(40, &destination, b"generic-active");

        let (mut client_io, server_io) = duplex(8192);
        let (_client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (server_encryptor, server_alert_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x20);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };

        let stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );
        let split = stream.split_for_relay().expect("split");
        let mut mux_stream = SplitMuxInbound::new(split.reader, split.writer, initial_payload);

        let server_task = tokio::spawn(async move {
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
        });

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        for _ in 0..2 {
            client_io
                .write_all(&TLS13_COMPATIBILITY_CCS_RECORD)
                .await
                .expect("write useless CCS");
        }

        let mux_err = server_task
            .await
            .expect("join")
            .expect_err("overflow terminates REALITY mux+generic UDP");
        assert!(is_useless_record_overflow(&mux_err));
        assert_eq!(useless_record_overflow_limit(&mux_err), Some(1));

        let mut decryptor = server_alert_decryptor;
        let alert_sequence_before =
            read_fatal_overflow_alert_record(&mut client_io, &mut decryptor).await;
        assert!(
            alert_sequence_before >= 1,
            "generic UDP mux response must precede overflow alert"
        );
    });
}
