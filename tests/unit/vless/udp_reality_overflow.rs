use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::reality::post_handshake::UselessRecordTolerance;
use crate::reality::tls13::{
    is_useless_record_overflow, tls13_cipher_suite, useless_record_overflow_limit,
    RealityTls13ApplicationStream, Tls13RecordDecryptor, Tls13RecordEncryptor, Tls13TrafficKeys,
    TLS_AES_128_GCM_SHA256,
};
use crate::tls::records::{
    parse_tls_records, TLS13_COMPATIBILITY_CCS_RECORD, TLS_LEGACY_VERSION_1_2,
};
use crate::tls::TlsRecordContentType;
use crate::vless::udp_framing::encode_vless_udp_packet;
use crate::vless::udp_relay::relay_vless_udp_split_with_overflow_alert;
use crate::vless::udp_session::VlessUdpRelayOptions;

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

fn aes128_keys(seed: u8) -> Tls13TrafficKeys {
    Tls13TrafficKeys {
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

fn assert_encrypted_fatal_unexpected_message_alert(
    record_bytes: &[u8],
    decryptor: &mut Tls13RecordDecryptor,
    expected_sequence_before: u64,
) {
    assert_eq!(
        decryptor.sequence, expected_sequence_before,
        "decryptor sequence before alert"
    );
    let records = parse_tls_records(record_bytes).expect("parse alert TLS record");
    assert_eq!(records.len(), 1, "exactly one alert record");
    let record = &records[0];
    assert_eq!(
        record.content_type,
        TlsRecordContentType::ApplicationData,
        "outer content type"
    );
    assert_eq!(
        record.legacy_version, TLS_LEGACY_VERSION_1_2,
        "legacy version"
    );
    let inner = decryptor
        .decrypt_record_payload(record)
        .expect("AEAD decrypt alert record");
    assert_eq!(
        inner,
        [0x02, 0x0a, 0x15],
        "fatal unexpected_message inner plaintext"
    );
    assert_eq!(decryptor.sequence, expected_sequence_before + 1);
}

async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = socket.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.expect("recv");
            socket.send_to(&buf[..len], peer).await.expect("send");
        }
    });
    (addr, task)
}

#[test]
fn native_vless_udp_relay_overflow_emits_encrypted_fatal_alert() {
    block_on(async {
        let (mut client_io, server_io) = tokio::io::duplex(8192);
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

        let (echo_addr, echo_task) = echo_server().await;
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let options = VlessUdpRelayOptions::for_test(std::time::Duration::from_millis(50));

        let relay_task = tokio::spawn(async move {
            relay_vless_udp_split_with_overflow_alert(
                split.reader,
                split.writer,
                Some(Arc::new(client_socket)),
                Some(echo_addr),
                false,
                encode_vless_udp_packet(b"udp").expect("frame"),
                None,
                options,
            )
            .await
        });

        for _ in 0..2 {
            client_io
                .write_all(&TLS13_COMPATIBILITY_CCS_RECORD)
                .await
                .expect("write useless CCS");
        }

        let relay_err = relay_task
            .await
            .expect("relay join")
            .expect_err("overflow terminates native UDP relay");
        assert!(is_useless_record_overflow(&relay_err));
        assert_eq!(useless_record_overflow_limit(&relay_err), Some(1));
        assert_eq!(relay_err.kind(), ErrorKind::InvalidData);
        assert!(relay_err.to_string().contains("too many ignored records"));

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        let mut decryptor = server_alert_decryptor;
        assert_encrypted_fatal_unexpected_message_alert(&alert_bytes, &mut decryptor, 0);

        echo_task.abort();
    });
}

#[test]
fn native_vless_udp_alert_uses_current_application_write_sequence() {
    block_on(async {
        let (mut client_io, server_io) = tokio::io::duplex(8192);
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
            .encrypt_application_data(b"vless-response-prefix")
            .expect("prior app write");

        let stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );
        let split = stream.split_for_relay().expect("split");

        let (echo_addr, echo_task) = echo_server().await;
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let options = VlessUdpRelayOptions::for_test(std::time::Duration::from_millis(50));

        let relay_task = tokio::spawn(async move {
            relay_vless_udp_split_with_overflow_alert(
                split.reader,
                split.writer,
                Some(Arc::new(client_socket)),
                Some(echo_addr),
                false,
                Vec::new(),
                None,
                options,
            )
            .await
        });

        for _ in 0..2 {
            client_io
                .write_all(&TLS13_COMPATIBILITY_CCS_RECORD)
                .await
                .expect("write useless CCS");
        }

        let relay_err = relay_task.await.expect("relay join").expect_err("overflow");
        assert!(is_useless_record_overflow(&relay_err));

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        server_alert_decryptor.sequence = 1;
        assert_encrypted_fatal_unexpected_message_alert(
            &alert_bytes,
            &mut server_alert_decryptor,
            1,
        );

        echo_task.abort();
    });
}
