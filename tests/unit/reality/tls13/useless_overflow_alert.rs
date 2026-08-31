use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{duplex, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::mux::handle_mux_cool_inbound;
use crate::reality::post_handshake::UselessRecordTolerance;
use crate::reality::tls13::record_crypto::{
    parse_tls13_application_inner_plaintext, Tls13RecordDecryptor, Tls13RecordEncryptor,
};
use crate::reality::tls13::stream::{
    read_client_finished_tls_record_from_stream, relay_split_bidirectional_with_overflow_alert,
    relay_tls13_split_bidirectional, write_fatal_useless_overflow_alert, ClientFinishedReadError,
    RealityTls13ApplicationStream, SplitMuxInbound,
};
use crate::reality::tls13::useless_records::{
    is_useless_record_overflow, too_many_ignored_records_error, useless_record_overflow_limit,
    UselessRecordCounter, UselessRecordOverflow,
};
use crate::reality::tls13::{
    tls13_cipher_suite, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
};
use crate::tls::records::{
    parse_tls_records, TLS13_COMPATIBILITY_CCS_RECORD, TLS_LEGACY_VERSION_1_2,
};
use crate::tls::TlsRecordContentType;
use crate::vless::inbound::validate_vless_flow_for_command;
use crate::vless::protocol::VlessCommand;
use crate::vless::vision::FLOW_XTLS_RPRX_VISION;
use crate::vless::vision::{new_shared_traffic_state, VisionRelayReader, VisionRelayWriter};

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

fn server_to_client_pair(suite_id: u16, seed: u8) -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(suite_id).expect("known suite");
    let keys = match suite_id {
        TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 => {
            crate::reality::tls13::Tls13TrafficKeys {
                key: (seed..seed + 32).collect(),
                iv: (0x01..0x0d).collect(),
            }
        }
        _ => aes128_keys(seed),
    };
    let encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor");
    let decryptor = Tls13RecordDecryptor::new(suite, keys).expect("decryptor");
    (encryptor, decryptor)
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

fn compatibility_ccs_record() -> Vec<u8> {
    TLS13_COMPATIBILITY_CCS_RECORD.to_vec()
}

#[test]
fn encrypt_fatal_unexpected_message_alert_all_supported_suites() {
    for suite_id in [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ] {
        let (mut encryptor, mut decryptor) = server_to_client_pair(suite_id, 0x20);
        let record = encryptor
            .encrypt_fatal_unexpected_message_alert()
            .expect("encrypt alert");
        assert_encrypted_fatal_unexpected_message_alert(&record, &mut decryptor, 0);
    }
}

#[test]
fn client_finished_finite_one_allows_first_useless_without_alert() {
    block_on(async {
        let input = compatibility_ccs_record();
        let mut cursor = std::io::Cursor::new(input);

        let err = read_client_finished_tls_record_from_stream(
            &mut cursor,
            UselessRecordTolerance::Finite(1),
        )
        .await
        .expect_err("one useless record is tolerated; EOF waiting for Finished");
        assert!(matches!(err, ClientFinishedReadError::Io(_)));
    });
}

#[test]
fn client_finished_overflow_emits_one_encrypted_fatal_alert() {
    block_on(async {
        let (mut client_io, mut server_io) = duplex(4096);
        for _ in 0..2 {
            client_io
                .write_all(&compatibility_ccs_record())
                .await
                .expect("write CCS");
        }

        let overflow = read_client_finished_tls_record_from_stream(
            &mut server_io,
            UselessRecordTolerance::Finite(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            overflow,
            ClientFinishedReadError::UselessOverflow(UselessRecordOverflow { limit: 1 })
        ));

        let (mut encryptor, mut decryptor) = server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);
        let mut alert_sent = false;
        write_fatal_useless_overflow_alert(&mut server_io, &mut encryptor, &mut alert_sent).await;
        assert!(alert_sent);

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        assert_encrypted_fatal_unexpected_message_alert(&alert_bytes, &mut decryptor, 0);

        let io_err = overflow.into_io_error();
        assert!(is_useless_record_overflow(&io_err));
        assert_eq!(useless_record_overflow_limit(&io_err), Some(1));
    });
}

#[test]
fn fatal_alert_uses_expected_sequence_after_prior_server_records() {
    let (mut encryptor, mut decryptor) = server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);

    encryptor
        .encrypt_application_data(b"position6-or-camouflage-0")
        .expect("record 0");
    encryptor
        .encrypt_application_data(b"camouflage-1")
        .expect("record 1");
    encryptor
        .encrypt_application_data(b"camouflage-2")
        .expect("record 2");
    assert_eq!(encryptor.sequence, 3);

    let alert = encryptor
        .encrypt_fatal_unexpected_message_alert()
        .expect("alert at sequence 3");
    decryptor.sequence = 3;
    assert_encrypted_fatal_unexpected_message_alert(&alert, &mut decryptor, 3);
}

#[test]
fn fatal_alert_follows_normal_application_write_sequence() {
    let (mut encryptor, mut decryptor) = server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);

    let normal = encryptor
        .encrypt_application_data(b"server-app-data")
        .expect("normal app record");
    let mut normal_decryptor = decryptor;
    let normal_records = parse_tls_records(&normal).expect("parse normal record");
    let normal_plaintext = normal_decryptor
        .decrypt_record_payload(&normal_records[0])
        .expect("decrypt normal");
    let normal_body =
        parse_tls13_application_inner_plaintext(&normal_plaintext).expect("parse normal inner");
    assert_eq!(normal_body, b"server-app-data");

    let alert = encryptor
        .encrypt_fatal_unexpected_message_alert()
        .expect("alert after normal write");
    assert_encrypted_fatal_unexpected_message_alert(&alert, &mut normal_decryptor, 1);
}

#[test]
fn duplicate_fatal_alert_write_is_suppressed() {
    block_on(async {
        let (mut client_io, mut server_io) = duplex(4096);
        let (mut encryptor, mut decryptor) = server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);
        let mut alert_sent = false;

        write_fatal_useless_overflow_alert(&mut server_io, &mut encryptor, &mut alert_sent).await;
        write_fatal_useless_overflow_alert(&mut server_io, &mut encryptor, &mut alert_sent).await;

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        assert_encrypted_fatal_unexpected_message_alert(&alert_bytes, &mut decryptor, 0);
        assert_eq!(
            encryptor.sequence, 1,
            "second alert must not consume another sequence"
        );
    });
}

struct BrokenPipeWriter;

impl AsyncWrite for BrokenPipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::Error::new(
            ErrorKind::BrokenPipe,
            "alert write failed",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn alert_write_failure_preserves_overflow_error() {
    block_on(async {
        let (mut encryptor, _) = server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);
        let mut alert_sent = false;
        let mut writer = BrokenPipeWriter;
        write_fatal_useless_overflow_alert(&mut writer, &mut encryptor, &mut alert_sent).await;

        let overflow = too_many_ignored_records_error(1);
        assert_eq!(overflow.kind(), ErrorKind::InvalidData);
        assert_eq!(useless_record_overflow_limit(&overflow), Some(1));
        assert_ne!(overflow.kind(), ErrorKind::BrokenPipe);
    });
}

#[test]
fn counter_reset_does_not_emit_alert_until_new_overflow() {
    let mut counter = UselessRecordCounter::new(UselessRecordTolerance::Finite(1));
    counter.observe_useless().expect("first useless");
    counter.observe_advancing();
    counter
        .observe_useless()
        .expect("new sequence first useless");
    assert_eq!(counter.consecutive(), 1);
}

#[test]
fn unlimited_tolerance_never_overflows_from_policy() {
    let mut counter = UselessRecordCounter::new(UselessRecordTolerance::Unlimited);
    for _ in 0..128 {
        counter.observe_useless().expect("unlimited");
    }
    assert_eq!(counter.consecutive(), 128);
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind localhost");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).await.expect("connect");
    let server = listener.accept().await.expect("accept").0;
    (client, server)
}

#[test]
fn split_relay_overflow_emits_encrypted_fatal_alert() {
    block_on(async {
        let (mut client_io, server_io) = duplex(8192);
        let (client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (server_encryptor, server_alert_decryptor) =
            server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);

        let stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );
        let split = stream.split_for_relay().expect("split");

        for _ in 0..2 {
            client_io
                .write_all(&compatibility_ccs_record())
                .await
                .expect("write useless CCS");
        }

        let (_outbound_client, outbound_server) = tcp_pair().await;
        let relay_err =
            relay_tls13_split_bidirectional(split.reader, split.writer, outbound_server)
                .await
                .expect_err("overflow terminates relay");
        assert!(is_useless_record_overflow(&relay_err));
        assert_eq!(useless_record_overflow_limit(&relay_err), Some(1));

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        let mut decryptor = server_alert_decryptor;
        assert_encrypted_fatal_unexpected_message_alert(&alert_bytes, &mut decryptor, 0);
        let _ = client_encryptor;
    });
}

#[test]
fn application_stream_overflow_is_accepted_path_error_not_fallback() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (server_encryptor, _) = server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);

        let mut stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );

        for _ in 0..2 {
            client_io
                .write_all(&compatibility_ccs_record())
                .await
                .expect("write useless CCS");
        }

        let mut buf = [0u8; 16];
        let err = stream
            .read(&mut buf)
            .await
            .expect_err("overflow closes read");
        assert!(is_useless_record_overflow(&err));
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("too many ignored records"));
        let _ = client_encryptor;
    });
}

#[test]
fn pre_vless_parse_overflow_emits_encrypted_fatal_alert() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (server_encryptor, server_alert_decryptor) =
            server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);

        let mut stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );

        for _ in 0..2 {
            client_io
                .write_all(&compatibility_ccs_record())
                .await
                .expect("write useless CCS");
        }

        let mut buf = [0u8; 16];
        let err = stream
            .read(&mut buf)
            .await
            .expect_err("overflow while reading vless header");
        assert!(is_useless_record_overflow(&err));

        stream
            .send_useless_overflow_fatal_alert()
            .await
            .expect("send overflow alert");

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        let mut decryptor = server_alert_decryptor;
        assert_encrypted_fatal_unexpected_message_alert(&alert_bytes, &mut decryptor, 0);
        let _ = client_encryptor;
    });
}

#[test]
fn vision_split_relay_overflow_emits_encrypted_fatal_alert() {
    block_on(async {
        let (mut client_io, server_io) = duplex(8192);
        let (client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (server_encryptor, server_alert_decryptor) =
            server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);

        let stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );
        let split = stream.split_for_relay().expect("split");
        let user_uuid = [0x42; 16];
        let traffic = new_shared_traffic_state(user_uuid);
        let vision_reader = VisionRelayReader::new(split.reader, Arc::clone(&traffic), None);
        let vision_writer =
            VisionRelayWriter::new(split.writer, traffic, user_uuid, Some(split.direct_relay));

        for _ in 0..2 {
            client_io
                .write_all(&compatibility_ccs_record())
                .await
                .expect("write useless CCS");
        }

        let (_outbound_client, outbound_server) = tcp_pair().await;
        let relay_err = relay_split_bidirectional_with_overflow_alert(
            vision_reader,
            vision_writer,
            outbound_server,
        )
        .await
        .expect_err("vision split relay overflow terminates");

        assert!(is_useless_record_overflow(&relay_err));
        assert_eq!(useless_record_overflow_limit(&relay_err), Some(1));

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        let mut decryptor = server_alert_decryptor;
        assert_encrypted_fatal_unexpected_message_alert(&alert_bytes, &mut decryptor, 0);
        let _ = client_encryptor;
    });
}

async fn run_split_mux_with_production_overflow_handling<R, W>(
    mut mux_stream: SplitMuxInbound<R, W>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin + crate::reality::tls13::Tls13OverflowAlertWriter,
{
    let result = handle_mux_cool_inbound(&mut mux_stream).await;
    if let Err(err) = result {
        if useless_record_overflow_limit(&err).is_some() {
            let _ = mux_stream.send_useless_overflow_fatal_alert().await;
        }
        return Err(err);
    }
    Ok(())
}

#[test]
fn mux_split_overflow_emits_encrypted_fatal_alert() {
    block_on(async {
        let (mut client_io, server_io) = duplex(8192);
        let (client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (server_encryptor, server_alert_decryptor) =
            server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);

        let stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );
        let split = stream.split_for_relay().expect("split");
        let mux_stream = SplitMuxInbound::new(split.reader, split.writer, Vec::new());

        let server_task = tokio::spawn(run_split_mux_with_production_overflow_handling(mux_stream));

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        for _ in 0..2 {
            client_io
                .write_all(&compatibility_ccs_record())
                .await
                .expect("write useless CCS");
        }

        let mux_err = server_task
            .await
            .expect("mux task join")
            .expect_err("overflow");
        assert!(is_useless_record_overflow(&mux_err));
        assert_eq!(useless_record_overflow_limit(&mux_err), Some(1));

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        let mut decryptor = server_alert_decryptor;
        assert_encrypted_fatal_unexpected_message_alert(&alert_bytes, &mut decryptor, 0);
        let _ = client_encryptor;
    });
}

#[test]
fn vision_mux_flow_combination_is_allowed_by_validation() {
    validate_vless_flow_for_command(
        Some(FLOW_XTLS_RPRX_VISION),
        Some(FLOW_XTLS_RPRX_VISION),
        VlessCommand::Mux,
    )
    .expect("vision + mux is reachable when both sides require vision");
}

#[test]
fn vision_mux_split_overflow_emits_encrypted_fatal_alert() {
    block_on(async {
        let (mut client_io, server_io) = duplex(8192);
        let (client_encryptor, server_decryptor) = {
            let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
            let keys = aes128_keys(0x10);
            (
                Tls13RecordEncryptor::new(suite, keys.clone()).expect("enc"),
                Tls13RecordDecryptor::new(suite, keys).expect("dec"),
            )
        };
        let (server_encryptor, server_alert_decryptor) =
            server_to_client_pair(TLS_AES_128_GCM_SHA256, 0x20);

        let stream = RealityTls13ApplicationStream::new_with_tolerance(
            server_io,
            server_decryptor,
            server_encryptor,
            UselessRecordTolerance::Finite(1),
        );
        let split = stream.split_for_relay().expect("split");
        let user_uuid = [0x43; 16];
        let traffic = new_shared_traffic_state(user_uuid);
        let mux_stream = SplitMuxInbound::new(
            VisionRelayReader::new(split.reader, Arc::clone(&traffic), None),
            VisionRelayWriter::new(split.writer, traffic, user_uuid, Some(split.direct_relay)),
            Vec::new(),
        );

        let server_task = tokio::spawn(run_split_mux_with_production_overflow_handling(mux_stream));

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        for _ in 0..2 {
            client_io
                .write_all(&compatibility_ccs_record())
                .await
                .expect("write useless CCS");
        }

        let mux_err = server_task
            .await
            .expect("mux task join")
            .expect_err("overflow");
        assert!(is_useless_record_overflow(&mux_err));
        assert_eq!(useless_record_overflow_limit(&mux_err), Some(1));

        let alert_bytes = read_one_record_from_peer(&mut client_io).await;
        let mut decryptor = server_alert_decryptor;
        assert_encrypted_fatal_unexpected_message_alert(&alert_bytes, &mut decryptor, 0);
        let _ = client_encryptor;
    });
}
