
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use crate::reality::tls13::{tls13_cipher_suite, Tls13TrafficKeys, TLS_AES_128_GCM_SHA256};
use crate::tls::records::{
    build_application_data_record, build_change_cipher_spec_record, build_tls_record,
    parse_tls_records, TLS_LEGACY_VERSION_1_2, TLS_RECORD_ALERT, TLS_RECORD_APPLICATION_DATA,
    TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};

use crate::reality::stages;

use super::*;

use crate::vless::inbound::read_vless_request;
use crate::vless::protocol::{build_vless_domain_address, build_vless_request_wire};

fn aes128_keys(seed: u8) -> Tls13TrafficKeys {
    Tls13TrafficKeys {
        key: (seed..seed + 16).collect(),
        iv: (0x01..0x0d).collect(),
    }
}

fn client_to_server_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys(0x10);
    let encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor");
    let decryptor = Tls13RecordDecryptor::new(suite, keys).expect("decryptor");
    (encryptor, decryptor)
}

fn server_to_client_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys(0x20);
    let encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor");
    let decryptor = Tls13RecordDecryptor::new(suite, keys).expect("decryptor");
    (encryptor, decryptor)
}

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

#[test]
fn application_stream_second_record_decrypt_after_partial_async_read() {
    block_on(async {
        let (mut client_io, server_io) = duplex(8192);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let record0_plaintext = b"vless-header-and-initial-payload-bytes";
        let record1_plaintext = b"extra-client-bytes-after-vless";

        let encrypted0 = client_encryptor
            .encrypt_application_data(record0_plaintext)
            .expect("encrypted record 0");
        let encrypted1 = client_encryptor
            .encrypt_application_data(record1_plaintext)
            .expect("encrypted record 1");
        client_io
            .write_all(&encrypted0)
            .await
            .expect("write record 0");
        client_io
            .write_all(&encrypted1)
            .await
            .expect("write record 1");

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let mut first_chunk = [0u8; 24];
        let read = stream
            .read(&mut first_chunk)
            .await
            .expect("read first plaintext chunk");
        assert_eq!(read, first_chunk.len());
        assert_eq!(&first_chunk[..read], &record0_plaintext[..read]);
        assert_eq!(stream.client_decrypt_sequence(), 1);

        let mut second_chunk = [0u8; 64];
        let read = stream
            .read(&mut second_chunk)
            .await
            .expect("read second plaintext chunk");
        assert_eq!(
            &second_chunk[..read],
            &record0_plaintext[first_chunk.len()..record0_plaintext.len()]
        );
        assert_eq!(stream.client_decrypt_sequence(), 1);

        let mut third_chunk = [0u8; 64];
        let read = stream
            .read(&mut third_chunk)
            .await
            .expect("read third plaintext chunk");
        assert_eq!(&third_chunk[..read], record1_plaintext);
        assert_eq!(stream.client_decrypt_sequence(), 2);
    });
}

#[test]
fn application_stream_does_not_reset_decrypt_sequence_between_reads() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let encrypted0 = client_encryptor
            .encrypt_application_data(b"record-zero")
            .expect("encrypted record 0");
        let encrypted1 = client_encryptor
            .encrypt_application_data(b"record-one")
            .expect("encrypted record 1");
        client_io.write_all(&encrypted0).await.expect("write 0");
        client_io.write_all(&encrypted1).await.expect("write 1");

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let mut buf = [0u8; 32];
        let read = stream.read(&mut buf).await.expect("first read");
        assert_eq!(&buf[..read], b"record-zero");
        assert_eq!(stream.client_decrypt_sequence(), 1);

        let read = stream.read(&mut buf).await.expect("second read");
        assert_eq!(&buf[..read], b"record-one");
        assert_eq!(stream.client_decrypt_sequence(), 2);
    });
}

#[test]
fn application_stream_vless_request_parse_then_second_record_decrypt() {
    block_on(async {
        let user_id = [0x11; 16];
        let second_record_plaintext = b"second-client-record-after-vless";
        let mut vless_packet = build_vless_request_wire(
            0,
            &user_id,
            &[],
            0x01,
            443,
            &build_vless_domain_address("example.com"),
        );
        vless_packet.extend_from_slice(b"TLS-INITIAL");

        let (mut client_io, server_io) = duplex(8192);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let encrypted0 = client_encryptor
            .encrypt_application_data(&vless_packet)
            .expect("encrypted vless record");
        let encrypted1 = client_encryptor
            .encrypt_application_data(second_record_plaintext)
            .expect("encrypted second record");
        client_io.write_all(&encrypted0).await.expect("write 0");
        client_io.write_all(&encrypted1).await.expect("write 1");

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let inbound = read_vless_request(&mut stream)
            .await
            .expect("vless request parsed from application stream");
        assert_eq!(inbound.request.version, 0);
        assert_eq!(inbound.initial_payload, b"TLS-INITIAL");
        assert_eq!(stream.client_decrypt_sequence(), 1);

        let mut second = [0u8; 64];
        let read = stream.read(&mut second).await.expect("second record read");
        assert_eq!(&second[..read], second_record_plaintext);
        assert_eq!(stream.client_decrypt_sequence(), 2);
    });
}

#[test]
fn read_plaintext_chunk_decrypts_one_record() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let encrypted = client_encryptor
            .encrypt_application_data(b"vless-payload")
            .expect("encrypted record");
        client_io.write_all(&encrypted).await.expect("write");

        let plaintext = stream
            .read_plaintext_chunk()
            .await
            .expect("decrypted plaintext");

        assert_eq!(plaintext, b"vless-payload");
        assert_eq!(stream.client_decrypt_sequence(), 1);
    });
}

#[test]
fn split_once_preserves_decrypt_sequence_after_initial_read() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let encrypted0 = client_encryptor
            .encrypt_application_data(b"before-split")
            .expect("encrypted record 0");
        let encrypted1 = client_encryptor
            .encrypt_application_data(b"after-split")
            .expect("encrypted record 1");
        client_io.write_all(&encrypted0).await.expect("write 0");
        client_io.write_all(&encrypted1).await.expect("write 1");

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let mut buf = [0u8; 32];
        let read = stream.read(&mut buf).await.expect("read before split");
        assert_eq!(&buf[..read], b"before-split");
        assert_eq!(stream.client_decrypt_sequence(), 1);

        let split = stream.split_for_relay().expect("split once");
        let mut reader = split.reader;
        assert_eq!(reader.client_decrypt_sequence(), 1);

        let read = reader.read(&mut buf).await.expect("read after split");
        assert_eq!(&buf[..read], b"after-split");
        assert_eq!(reader.client_decrypt_sequence(), 2);
    });
}

#[test]
fn split_does_not_clone_decrypt_sequence() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let encrypted = client_encryptor
            .encrypt_application_data(b"single-record")
            .expect("encrypted record");
        client_io.write_all(&encrypted).await.expect("write");

        let stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
        assert_eq!(stream.client_decrypt_sequence(), 0);

        let split = stream.split_for_relay().expect("split");
        let mut reader = split.reader;
        assert_eq!(reader.client_decrypt_sequence(), 0);

        let mut buf = [0u8; 32];
        let read = reader.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..read], b"single-record");
        assert_eq!(reader.client_decrypt_sequence(), 1);
    });
}

#[test]
fn two_records_after_split_decrypt_with_sequence_zero_then_one() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let encrypted0 = client_encryptor
            .encrypt_application_data(b"split-seq-0")
            .expect("encrypted record 0");
        let encrypted1 = client_encryptor
            .encrypt_application_data(b"split-seq-1")
            .expect("encrypted record 1");
        client_io.write_all(&encrypted0).await.expect("write 0");
        client_io.write_all(&encrypted1).await.expect("write 1");

        let stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
        let split = stream.split_for_relay().expect("split");
        let mut reader = split.reader;

        assert_eq!(reader.client_decrypt_sequence(), 0);

        let mut buf = [0u8; 32];
        let read = reader.read(&mut buf).await.expect("read seq 0");
        assert_eq!(&buf[..read], b"split-seq-0");
        assert_eq!(reader.client_decrypt_sequence(), 1);

        let read = reader.read(&mut buf).await.expect("read seq 1");
        assert_eq!(&buf[..read], b"split-seq-1");
        assert_eq!(reader.client_decrypt_sequence(), 2);
    });
}

#[test]
fn independent_application_streams_each_split_once_without_error() {
    block_on(async {
        let (_client_encryptor_a, server_decryptor_a) = client_to_server_keys();
        let (server_encryptor_a, _client_decryptor_a) = server_to_client_keys();
        let (_client_encryptor_b, server_decryptor_b) = client_to_server_keys();
        let (server_encryptor_b, _client_decryptor_b) = server_to_client_keys();

        let stream_a = RealityTls13ApplicationStream::new(
            duplex(4096).1,
            server_decryptor_a,
            server_encryptor_a,
        );
        let stream_b = RealityTls13ApplicationStream::new(
            duplex(4096).1,
            server_decryptor_b,
            server_encryptor_b,
        );

        stream_a.split_for_relay().expect("first stream split");
        stream_b.split_for_relay().expect("second stream split");
    });
}

#[test]
fn repeated_split_on_same_stream_instance_is_rejected() {
    let (_client_encryptor, server_decryptor) = client_to_server_keys();
    let (server_encryptor, _client_decryptor) = server_to_client_keys();

    let stream =
        RealityTls13ApplicationStream::new(duplex(4096).1, server_decryptor, server_encryptor);
    let split_flag = stream.relay_split_guard.split_flag();

    stream.split_for_relay().expect("first split succeeds");
    assert!(split_flag.load(Ordering::SeqCst));

    let err = ApplicationStreamRelaySplitGuard(split_flag)
        .mark_split()
        .expect_err("second split on same stream must fail");
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(err
        .to_string()
        .contains("TLS application stream relay split called more than once"));
}

#[test]
fn direct_relay_bypasses_tls_decrypt_on_reader() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (_client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
        let split = stream.split_for_relay().expect("split");
        split.direct_relay.enable_reader();
        let mut reader = split.reader;

        client_io
            .write_all(b"raw-after-direct")
            .await
            .expect("write raw");

        let mut buf = [0u8; 32];
        let read = reader.read(&mut buf).await.expect("read raw");
        assert_eq!(&buf[..read], b"raw-after-direct");
        assert_eq!(reader.client_decrypt_sequence(), 0);
    });
}

#[test]
fn direct_relay_bypasses_tls_encrypt_on_writer() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (_client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
        let split = stream.split_for_relay().expect("split");
        split.direct_relay.enable_writer();
        let mut writer = split.writer;

        writer.write_all(b"raw-downlink").await.expect("write raw");
        writer.flush().await.expect("flush");

        let mut client_buf = [0u8; 32];
        let read = client_io.read(&mut client_buf).await.expect("client read");
        assert_eq!(&client_buf[..read], b"raw-downlink");
        assert_eq!(writer.client_encrypt_sequence(), 0);
    });
}

#[test]
fn direct_relay_drains_buffered_ciphertext_before_raw_read() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (_client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
        let split = stream.split_for_relay().expect("split");
        let mut reader = split.reader;

        reader
            .read
            .ciphertext_read_buf
            .extend_from_slice(b"buffered-raw");
        split.direct_relay.enable_reader();

        let mut buf = [0u8; 32];
        let read = reader.read(&mut buf).await.expect("read buffered raw");
        assert_eq!(&buf[..read], b"buffered-raw");

        client_io
            .write_all(b"-from-socket")
            .await
            .expect("write socket");
        let read = reader.read(&mut buf).await.expect("read socket raw");
        assert_eq!(&buf[..read], b"-from-socket");
    });
}

#[test]
fn read_plaintext_chunk_then_async_read_continues_sequence() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let encrypted0 = client_encryptor
            .encrypt_application_data(b"chunk-read")
            .expect("encrypted record 0");
        let encrypted1 = client_encryptor
            .encrypt_application_data(b"async-read")
            .expect("encrypted record 1");
        client_io.write_all(&encrypted0).await.expect("write 0");
        client_io.write_all(&encrypted1).await.expect("write 1");

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let plaintext = stream
            .read_plaintext_chunk()
            .await
            .expect("decrypted plaintext");
        assert_eq!(plaintext, b"chunk-read");
        assert_eq!(stream.client_decrypt_sequence(), 1);

        let mut buf = [0u8; 32];
        let read = stream.read(&mut buf).await.expect("async read");
        assert_eq!(&buf[..read], b"async-read");
        assert_eq!(stream.client_decrypt_sequence(), 2);
    });
}

#[test]
fn async_write_produces_tls_application_record() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (_client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, mut client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        stream
            .write_all(b"server response")
            .await
            .expect("write plaintext");

        let mut encrypted = vec![0u8; 4096];
        let read = client_io
            .read(&mut encrypted)
            .await
            .expect("read encrypted record");
        encrypted.truncate(read);

        let records = parse_tls_records(&encrypted).expect("parsable record");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].content_type,
            TlsRecordContentType::ApplicationData
        );

        let plaintext = client_decryptor
            .decrypt_application_data_record(&records[0])
            .expect("decrypted application data");
        assert_eq!(plaintext, b"server response");
    });
}

#[test]
fn duplex_encrypt_decrypt_roundtrip() {
    block_on(async {
        let (mut client_io, server_io) = duplex(8192);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, mut client_decryptor) = server_to_client_keys();

        let mut server_stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let client_to_server = client_encryptor
            .encrypt_application_data(b"client->server")
            .expect("encrypted");
        client_io
            .write_all(&client_to_server)
            .await
            .expect("client write");

        let mut read_buf = [0u8; 64];
        let read = server_stream
            .read(&mut read_buf)
            .await
            .expect("server read");
        assert_eq!(&read_buf[..read], b"client->server");

        server_stream
            .write_all(b"server->client")
            .await
            .expect("server write");

        let mut encrypted = vec![0u8; 4096];
        let read = client_io
            .read(&mut encrypted)
            .await
            .expect("client read encrypted");
        encrypted.truncate(read);

        let records = parse_tls_records(&encrypted).expect("parsable record");
        let plaintext = client_decryptor
            .decrypt_application_data_record(&records[0])
            .expect("decrypted");
        assert_eq!(plaintext, b"server->client");
    });
}

#[test]
fn fragmented_tls_record_read_waits_for_full_record() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let encrypted = client_encryptor
            .encrypt_application_data(b"fragmented")
            .expect("encrypted record");
        let split_at = 3;
        client_io
            .write_all(&encrypted[..split_at])
            .await
            .expect("first fragment");
        client_io
            .write_all(&encrypted[split_at..])
            .await
            .expect("second fragment");

        let plaintext = stream
            .read_plaintext_chunk()
            .await
            .expect("decrypted plaintext");
        assert_eq!(plaintext, b"fragmented");
    });
}

#[test]
fn read_tls_record_from_stream_reads_one_record() {
    block_on(async {
        let record_bytes = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            b"payload",
        )
        .expect("valid record");
        let mut cursor = std::io::Cursor::new(record_bytes.clone());

        let record = read_tls_record_from_stream(&mut cursor)
            .await
            .expect("valid TLS record");

        assert_eq!(record.raw, record_bytes);
        assert_eq!(record.payload, b"payload");
        assert_eq!(record.content_type, TlsRecordContentType::ApplicationData);
    });
}

#[test]
fn read_client_finished_tls_record_skips_one_change_cipher_spec() {
    block_on(async {
        let mut input = build_change_cipher_spec_record();
        let app_data = build_application_data_record(b"client-finished")
            .expect("valid ApplicationData record");
        input.extend_from_slice(&app_data);
        let total_len = input.len();
        let mut cursor = std::io::Cursor::new(input);

        let record = read_client_finished_tls_record_from_stream(&mut cursor)
            .await
            .expect("client Finished record");

        assert_eq!(record.content_type, TlsRecordContentType::ApplicationData);
        assert_eq!(record.payload, b"client-finished");
        assert_eq!(cursor.position() as usize, total_len);
    });
}

#[test]
fn read_client_finished_tls_record_skips_two_change_cipher_spec_records() {
    block_on(async {
        let mut input = build_change_cipher_spec_record();
        input.extend_from_slice(&build_change_cipher_spec_record());
        let app_data = build_application_data_record(b"client-finished")
            .expect("valid ApplicationData record");
        input.extend_from_slice(&app_data);
        let mut cursor = std::io::Cursor::new(input);

        let record = read_client_finished_tls_record_from_stream(&mut cursor)
            .await
            .expect("client Finished record");

        assert_eq!(record.content_type, TlsRecordContentType::ApplicationData);
        assert_eq!(record.payload, b"client-finished");
    });
}

#[test]
fn read_client_finished_tls_record_rejects_too_many_change_cipher_spec_records() {
    block_on(async {
        let mut input = Vec::new();
        for _ in 0..MAX_DUMMY_CHANGE_CIPHER_SPEC_BEFORE_CLIENT_FINISHED + 1 {
            input.extend_from_slice(&build_change_cipher_spec_record());
        }
        let mut cursor = std::io::Cursor::new(input);

        let err = read_client_finished_tls_record_from_stream(&mut cursor)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("too many ChangeCipherSpec records before client Finished"));
    });
}

#[test]
fn read_client_finished_tls_record_rejects_alert_before_finished() {
    block_on(async {
        let alert = build_tls_record(TLS_RECORD_ALERT, TLS_LEGACY_VERSION_1_2, &[0x02, 0x28])
            .expect("valid alert record");
        let mut cursor = std::io::Cursor::new(alert);

        let err = read_client_finished_tls_record_from_stream(&mut cursor)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("client sent TLS alert before Finished"));
        assert!(err.to_string().contains("0228"));
        assert!(err.to_string().contains(stages::TLS13_CLIENT_FINISHED_READ));
    });
}

#[test]
fn read_client_finished_tls_record_eof_includes_stage_phrase() {
    block_on(async {
        let mut cursor = std::io::Cursor::new(Vec::new());

        let err = read_client_finished_tls_record_from_stream(&mut cursor)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains(stages::TLS13_CLIENT_FINISHED_READ));
        assert!(err
            .to_string()
            .contains("client closed connection before client Finished"));
    });
}

#[test]
fn read_client_finished_tls_record_errors_do_not_include_secret_field_names() {
    block_on(async {
        let alert = build_tls_record(TLS_RECORD_ALERT, TLS_LEGACY_VERSION_1_2, &[0x02, 0x28])
            .expect("valid alert record");
        let mut cursor = std::io::Cursor::new(alert);

        let err = read_client_finished_tls_record_from_stream(&mut cursor)
            .await
            .unwrap_err();
        let message = err.to_string().to_ascii_lowercase();

        assert!(!message.contains("privatekey"));
        assert!(!message.contains("auth_key"));
        assert!(!message.contains("traffic_secret"));
        assert!(!message.contains("handshake_secret"));
    });
}

#[test]
fn read_client_finished_tls_record_rejects_invalid_change_cipher_spec_payload() {
    block_on(async {
        let invalid_ccs = build_tls_record(
            TLS_RECORD_CHANGE_CIPHER_SPEC,
            TLS_LEGACY_VERSION_1_2,
            &[0x02],
        )
        .expect("valid CCS record framing");
        let mut cursor = std::io::Cursor::new(invalid_ccs);

        let err = read_client_finished_tls_record_from_stream(&mut cursor)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("invalid ChangeCipherSpec payload before client Finished"));
    });
}

#[test]
fn read_client_finished_tls_record_rejects_unexpected_handshake_record() {
    block_on(async {
        let handshake = build_tls_record(TLS_RECORD_HANDSHAKE, TLS_LEGACY_VERSION_1_2, &[0x01])
            .expect("valid handshake record");
        let mut cursor = std::io::Cursor::new(handshake);

        let err = read_client_finished_tls_record_from_stream(&mut cursor)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("unexpected TLS record before client Finished: Handshake"));
    });
}

#[test]
fn try_take_tls_record_requires_complete_record() {
    let mut buf = BytesMut::from(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x02][..]);
    assert!(try_take_tls_record(&mut buf)
        .expect("valid parse")
        .is_none());

    buf.extend_from_slice(&[0x01, 0x02]);
    let record = try_take_tls_record(&mut buf)
        .expect("valid parse")
        .expect("complete record");
    assert_eq!(record.payload, vec![0x01, 0x02]);
    assert!(buf.is_empty());
}

#[test]
fn vless_appdata_decrypt_failure_error_contains_sequence_and_len() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, mut server_decryptor) = client_to_server_keys();
        server_decryptor.keys.key[0] ^= 0x01;
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let encrypted = client_encryptor
            .encrypt_application_data(b"secret-vless-payload")
            .expect("encrypted record");
        let records = parse_tls_records(&encrypted).expect("parsable record");
        let record_payload_len = records[0].payload.len();
        client_io.write_all(&encrypted).await.expect("write");

        let err = stream.read_plaintext_chunk().await.unwrap_err();
        let message = err.to_string();

        assert!(message.contains("decrypt_sequence=0"));
        assert!(message.contains(&format!("record_payload_len={record_payload_len}")));
        assert!(message.contains("record_content_type=ApplicationData"));
        assert!(message.contains("legacy_version_hex=0303"));
        assert!(message.contains(stages::TLS13_APPLICATION_STREAM_DECRYPT));
        assert!(message.contains("TLS_AES_128_GCM_SHA256"));
        assert!(message.contains("AES-128-GCM decrypt failed"));
    });
}

#[test]
fn short_encrypted_application_record_rejected_before_aead() {
    block_on(async {
        let short_record = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            &[0u8; 8],
        )
        .expect("valid short record");

        let (mut client_io, server_io) = duplex(4096);
        let (_client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        client_io
            .write_all(&short_record)
            .await
            .expect("write short record");

        let err = stream.read_plaintext_chunk().await.unwrap_err();
        let message = err.to_string();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(message.contains("TLS application record too short for AEAD tag"));
        assert!(message.contains("decrypt_sequence=0"));
        assert!(message.contains("record_payload_len=8"));
        assert!(!message.contains("AES-128-GCM decrypt failed"));
        assert!(!message.contains("AES-256-GCM decrypt failed"));
    });
}

#[test]
fn tls_record_debug_prefix_helpers_cap_at_32_bytes() {
    let payload: Vec<u8> = (0..64).collect();
    assert_eq!(
        encrypted_payload_prefix_hex(&payload).len(),
        MAX_DEBUG_TLS_RECORD_PREFIX_BYTES * 2
    );
    assert_eq!(
        encrypted_payload_suffix_hex(&payload).len(),
        MAX_DEBUG_TLS_RECORD_PREFIX_BYTES * 2
    );

    let record = build_tls_record(
        TLS_RECORD_APPLICATION_DATA,
        TLS_LEGACY_VERSION_1_2,
        &payload,
    )
    .expect("valid record");
    assert_eq!(
        tls_record_header_hex(&record).len(),
        TLS_RECORD_HEADER_LEN * 2
    );
    assert_eq!(tls_record_header_hex(&record), "1703030040");
}

#[test]
fn debug_tls_record_prefix_enabled_requires_exact_one() {
    let key = "RUST_XRAY_DEBUG_TLS_RECORD_PREFIX";
    let previous = std::env::var(key).ok();

    std::env::set_var(key, "1");
    assert!(debug_tls_record_prefix_enabled());

    std::env::set_var(key, "true");
    assert!(!debug_tls_record_prefix_enabled());

    match previous {
        Some(value) => std::env::set_var(key, value),
        None => std::env::remove_var(key),
    }
}

#[test]
fn vless_appdata_decrypt_failure_does_not_contain_plaintext() {
    block_on(async {
        let payload = b"secret-vless-payload";
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, mut server_decryptor) = client_to_server_keys();
        server_decryptor.keys.key[0] ^= 0x01;
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let encrypted = client_encryptor
            .encrypt_application_data(payload)
            .expect("encrypted record");
        client_io.write_all(&encrypted).await.expect("write");

        let err = stream.read_plaintext_chunk().await.unwrap_err();
        let message = err.to_string().to_ascii_lowercase();

        assert!(!message.contains("secret-vless-payload"));
        assert!(!message.contains("736563726574")); // "secret" hex
        assert!(!message.contains("traffic_secret"));
        assert!(!message.contains("auth_key"));
    });
}

#[test]
fn vless_plaintext_debug_preview_caps_at_64_bytes() {
    let plaintext = vec![0xAB; 128];
    let (preview_hex, preview_len) = vless_plaintext_debug_preview(&plaintext);

    assert_eq!(preview_len, 64);
    assert_eq!(preview_hex.len(), 128);
    assert_eq!(preview_hex, "ab".repeat(64));
}

#[test]
fn decrypted_close_notify_alert_maps_to_eof() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let encrypted = client_encryptor
            .encrypt_application_record_with_inner_content_type(
                &[TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY],
                TLS_RECORD_ALERT,
            )
            .expect("encrypted close_notify alert");
        client_io.write_all(&encrypted).await.expect("write");

        let plaintext = stream
            .read_plaintext_chunk()
            .await
            .expect("close_notify maps to EOF");
        assert!(plaintext.is_empty());

        let mut read_buf = [0u8; 8];
        let read = stream.read(&mut read_buf).await.expect("async EOF");
        assert_eq!(read, 0);
        assert!(stream.read.read_eof);
    });
}

#[test]
fn decrypted_fatal_alert_maps_to_connection_aborted_with_description() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let encrypted = client_encryptor
            .encrypt_application_record_with_inner_content_type(
                &[TLS_ALERT_LEVEL_FATAL, 0x28],
                TLS_RECORD_ALERT,
            )
            .expect("encrypted fatal alert");
        client_io.write_all(&encrypted).await.expect("write");

        let err = stream.read_plaintext_chunk().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionAborted);
        assert!(err.to_string().contains("level=fatal"));
        assert!(err.to_string().contains("description=40"));
    });
}

#[test]
fn unexpected_inner_content_type_maps_to_invalid_data() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let encrypted = client_encryptor
            .encrypt_handshake_message(&[0x01, 0x00, 0x00, 0x01, 0x00])
            .expect("encrypted handshake inner record");
        client_io.write_all(&encrypted).await.expect("write");

        let err = stream.read_plaintext_chunk().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("unsupported post-handshake message type: 0x01"));
    });
}

fn sample_traffic_secret(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn client_to_server_keys_with_traffic_secret() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    use crate::reality::tls13::key_schedule::derive_traffic_key;

    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let traffic_secret = sample_traffic_secret(0xAA);
    let keys = derive_traffic_key(suite, &traffic_secret).expect("traffic keys");
    let encryptor =
        Tls13RecordEncryptor::with_traffic_secret(suite, keys.clone(), traffic_secret.clone())
            .expect("encryptor");
    let decryptor =
        Tls13RecordDecryptor::with_traffic_secret(suite, keys, traffic_secret).expect("decryptor");
    (encryptor, decryptor)
}

#[test]
fn key_update_record_is_consumed_and_next_appdata_decrypts_with_updated_key() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys_with_traffic_secret();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let key_update = client_encryptor
            .encrypt_key_update(crate::reality::tls13::messages::KEY_UPDATE_NOT_REQUESTED)
            .expect("encrypted key update");
        client_encryptor
            .apply_sending_traffic_key_update()
            .expect("client sending key update");
        let encrypted_app = client_encryptor
            .encrypt_application_data(b"after-key-update")
            .expect("encrypted app data after key update");

        client_io
            .write_all(&key_update)
            .await
            .expect("write key update");
        client_io
            .write_all(&encrypted_app)
            .await
            .expect("write app data");

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let mut buf = [0u8; 32];
        let read = stream.read(&mut buf).await.expect("read after key update");
        assert_eq!(&buf[..read], b"after-key-update");
        assert_eq!(stream.client_decrypt_sequence(), 1);
    });
}

#[test]
fn key_update_resets_record_sequence_after_traffic_key_change() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys_with_traffic_secret();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let encrypted0 = client_encryptor
            .encrypt_application_data(b"before-key-update")
            .expect("encrypted record 0");
        assert_eq!(client_encryptor.sequence, 1);

        let key_update = client_encryptor
            .encrypt_key_update(crate::reality::tls13::messages::KEY_UPDATE_NOT_REQUESTED)
            .expect("encrypted key update");
        assert_eq!(client_encryptor.sequence, 2);
        client_encryptor
            .apply_sending_traffic_key_update()
            .expect("client sending key update");

        let encrypted1 = client_encryptor
            .encrypt_application_data(b"after-key-update")
            .expect("encrypted record 1");
        assert_eq!(client_encryptor.sequence, 1);

        client_io.write_all(&encrypted0).await.expect("write 0");
        client_io
            .write_all(&key_update)
            .await
            .expect("write key update");
        client_io.write_all(&encrypted1).await.expect("write 1");

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let mut buf = [0u8; 32];
        let read = stream.read(&mut buf).await.expect("read first");
        assert_eq!(&buf[..read], b"before-key-update");
        assert_eq!(stream.client_decrypt_sequence(), 1);

        let read = stream.read(&mut buf).await.expect("read second");
        assert_eq!(&buf[..read], b"after-key-update");
        assert_eq!(stream.client_decrypt_sequence(), 1);
    });
}

#[test]
fn unsupported_post_handshake_message_returns_invalid_data() {
    block_on(async {
        let (mut client_io, server_io) = duplex(4096);
        let (mut client_encryptor, server_decryptor) = client_to_server_keys_with_traffic_secret();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let mut stream =
            RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

        let encrypted = client_encryptor
            .encrypt_handshake_message(&[0x08, 0x00, 0x00, 0x00])
            .expect("encrypted encrypted extensions inner record");
        client_io.write_all(&encrypted).await.expect("write");

        let err = stream.read_plaintext_chunk().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("unsupported post-handshake message type: 0x08"));
    });
}

#[test]
fn parse_application_stream_tls_alert_rejects_short_alert_body() {
    let err = parse_application_stream_tls_alert(&[TLS_ALERT_LEVEL_FATAL], 3).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("too short"));
}

struct ShutdownTrackingWriter {
    written: Vec<u8>,
    shutdown_calls: u32,
    block_next_write: bool,
}

impl ShutdownTrackingWriter {
    fn new() -> Self {
        Self {
            written: Vec::new(),
            shutdown_calls: 0,
            block_next_write: false,
        }
    }

    fn block_next_write(mut self) -> Self {
        self.block_next_write = true;
        self
    }
}

impl AsyncWrite for ShutdownTrackingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.block_next_write {
            self.block_next_write = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        self.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown_calls += 1;
        Poll::Ready(Ok(()))
    }
}

fn noop_waker() -> Waker {
    static VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

fn client_writer_for_test(
    inner: ShutdownTrackingWriter,
) -> RealityTls13ClientWriter<ShutdownTrackingWriter> {
    let (write_encryptor, _) = server_to_client_keys();
    let (_reader_direct, writer_direct) = ApplicationStreamDirectRelay::new_shared();
    RealityTls13ClientWriter {
        inner,
        write: Tls13ClientWriteState::new(write_encryptor, Arc::new(AtomicBool::new(false))),
        direct_relay: writer_direct,
    }
}

#[test]
fn client_writer_poll_shutdown_flushes_pending_encrypted_bytes() {
    let inner = ShutdownTrackingWriter::new().block_next_write();
    let mut writer = client_writer_for_test(inner);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    match Pin::new(&mut writer).poll_write(&mut cx, b"pending-shutdown-flush") {
        Poll::Pending => {}
        Poll::Ready(result) => panic!("expected pending write, got {result:?}"),
    }
    assert!(!writer.write.ciphertext_write_buf.is_empty());

    match Pin::new(&mut writer).poll_shutdown(&mut cx) {
        Poll::Ready(Ok(())) => {}
        other => panic!("expected shutdown ready Ok(()), got {other:?}"),
    }

    assert!(writer.write.ciphertext_write_buf.is_empty());
    assert!(!writer.inner.written.is_empty());
    assert_eq!(writer.inner.written[0], TLS_RECORD_APPLICATION_DATA);
    assert_eq!(writer.inner.shutdown_calls, 0);
}

#[test]
fn client_writer_poll_shutdown_does_not_shutdown_underlying_transport() {
    let inner = ShutdownTrackingWriter::new();
    let mut writer = client_writer_for_test(inner);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    match Pin::new(&mut writer).poll_shutdown(&mut cx) {
        Poll::Ready(Ok(())) => {}
        other => panic!("expected shutdown ready Ok(()), got {other:?}"),
    }

    assert_eq!(writer.inner.shutdown_calls, 0);
}
