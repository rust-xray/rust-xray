use super::*;
use crate::protocol::enums::{NamedGroup, ProtocolVersion};
use crate::protocol::structs::{
    ClientExtension, ClientHelloPayload, KeyShareEntry, Random, SessionId,
};
use crate::reality::auth::RealityAuthResult;
use crate::reality::decision::RealityAccepted;
use crate::reality::key_share::{
    NAMED_GROUP_X25519MLKEM768, X25519_MLKEM768_SERVER_KEY_SHARE_LEN, X25519_PUBLIC_KEY_LEN,
};
use crate::reality::session::RealityClientAuth;
use crate::reality::tls13::{Tls13HashAlgorithm, TLS_AES_128_GCM_SHA256};
use crate::tls::TlsRecordContentType;
use crate::tls::{build_change_cipher_spec_record, TlsRecord, TLS_LEGACY_VERSION_1_2};
use std::io::ErrorKind;

const X25519_KEY_EXCHANGE_LEN: usize = X25519_PUBLIC_KEY_LEN;

fn build_server_hello_handshake_message(extensions: &[(u16, &[u8])]) -> Vec<u8> {
    build_server_hello_handshake_message_with_cipher(extensions, TLS_AES_128_GCM_SHA256)
}

fn build_server_hello_handshake_message_with_cipher(
    extensions: &[(u16, &[u8])],
    cipher_suite: u16,
) -> Vec<u8> {
    let random = [0x11; 32];
    let mut body = Vec::new();
    body.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
    body.extend_from_slice(&random);
    body.push(0); // session_id_echo length
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(0); // compression_method

    let mut extension_bytes = Vec::new();
    for (extension_type, data) in extensions {
        extension_bytes.extend_from_slice(&extension_type.to_be_bytes());
        extension_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extension_bytes.extend_from_slice(data);
    }
    body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&extension_bytes);

    let mut message = Vec::with_capacity(4 + body.len());
    message.push(0x02);
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    message
}

fn x25519_key_share_bytes(key_exchange: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
    data.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
    data.extend_from_slice(key_exchange);
    data
}

fn x25519mlkem768_key_share_bytes(key_exchange: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&NAMED_GROUP_X25519MLKEM768.to_be_bytes());
    data.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
    data.extend_from_slice(key_exchange);
    data
}

fn valid_tls13_x25519_server_hello_message() -> Vec<u8> {
    build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
        (
            EXTENSION_KEY_SHARE,
            &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
        ),
    ])
}

fn valid_tls13_x25519mlkem768_server_hello_message() -> Vec<u8> {
    build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
        (
            EXTENSION_KEY_SHARE,
            &x25519mlkem768_key_share_bytes(&vec![0xA5; X25519_MLKEM768_SERVER_KEY_SHARE_LEN]),
        ),
    ])
}

fn dest_handshake_from_server_hello_message(message: &[u8]) -> RealityDestHandshake {
    let record = handshake_record(message);
    RealityDestHandshake::try_from_records(record.raw.clone(), vec![record])
        .expect("valid single-record dest handshake")
}

/// Builds a dest handshake container without positional flight validation.
///
/// Used by negative ServerHello semantic tests that expect [`extract_observed_server_hello`]
/// to reject malformed handshake messages.
fn dest_handshake_from_server_hello_message_unvalidated(message: &[u8]) -> RealityDestHandshake {
    let record = handshake_record(message);
    RealityDestHandshake {
        raw_server_bytes: record.raw.clone(),
        records: vec![record.clone()],
        server_flight: ObservedTargetTls13ServerFlight {
            server_hello_wire_len: record.raw.len(),
            ..ObservedTargetTls13ServerFlight::default()
        },
    }
}

fn handshake_record(payload: &[u8]) -> TlsRecord {
    let mut raw = Vec::with_capacity(5 + payload.len());
    raw.push(0x16);
    raw.extend_from_slice(&[0x03, 0x03]);
    raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    raw.extend_from_slice(payload);
    TlsRecord {
        content_type: TlsRecordContentType::Handshake,
        legacy_version: [0x03, 0x03],
        payload: payload.to_vec(),
        raw,
    }
}

fn application_data_record(payload: &[u8]) -> TlsRecord {
    let mut raw = Vec::with_capacity(5 + payload.len());
    raw.push(0x17);
    raw.extend_from_slice(&[0x03, 0x03]);
    raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    raw.extend_from_slice(payload);
    TlsRecord {
        content_type: TlsRecordContentType::ApplicationData,
        legacy_version: [0x03, 0x03],
        payload: payload.to_vec(),
        raw,
    }
}

fn sample_accepted() -> RealityAccepted {
    RealityAccepted {
        auth: RealityAuthResult {
            auth_key: [0u8; 32],
            client_public_key: [0u8; 32],
        },
        client: RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: [0xAB, 0xCD, 0, 0, 0, 0, 0, 0],
        },
        sni: Some("example.com".to_string()),
    }
}

#[test]
fn contains_tls13_server_hello_true_for_server_hello_payload() {
    let records = vec![handshake_record(&[0x02, 0x00, 0x00, 0x01])];
    assert!(contains_tls13_server_hello(&records));
}

#[test]
fn contains_tls13_server_hello_false_for_client_hello_payload() {
    let records = vec![handshake_record(&[0x01, 0x00, 0x00, 0x01])];
    assert!(!contains_tls13_server_hello(&records));
}

#[test]
fn contains_tls13_server_hello_false_for_application_data() {
    let records = vec![application_data_record(&[0xde, 0xad])];
    assert!(!contains_tls13_server_hello(&records));
}

#[test]
fn reality_dest_handshake_stores_records() {
    let sh_record = handshake_record(&valid_tls13_x25519_server_hello_message());
    let ccs = build_change_cipher_spec_record();
    let app_data = application_data_record(&[0xaa, 0xbb]);
    let mut raw_server_bytes = sh_record.raw.clone();
    raw_server_bytes.extend_from_slice(&ccs);
    raw_server_bytes.extend_from_slice(&app_data.raw);

    let dest_handshake = RealityDestHandshake::try_from_records(
        raw_server_bytes.clone(),
        vec![
            sh_record,
            {
                TlsRecord {
                    content_type: TlsRecordContentType::ChangeCipherSpec,
                    legacy_version: TLS_LEGACY_VERSION_1_2,
                    payload: vec![0x01],
                    raw: ccs,
                }
            },
            app_data,
        ],
    )
    .expect("valid dest handshake prefix");

    assert_eq!(dest_handshake.raw_server_bytes, raw_server_bytes);
    assert_eq!(dest_handshake.records.len(), 3);
    assert_eq!(
        dest_handshake.server_flight.encrypted_extensions_wire_len,
        Some(7)
    );
}

#[test]
fn extract_observed_server_hello_accepts_valid_tls13_x25519() {
    let message = valid_tls13_x25519_server_hello_message();
    let dest_handshake = dest_handshake_from_server_hello_message(&message);

    let observed = extract_observed_server_hello(&dest_handshake).expect("valid ServerHello");

    assert_eq!(observed.raw_handshake_message, message);
    assert_eq!(
        observed.server_hello.legacy_version,
        TLS_RECORD_LEGACY_VERSION
    );
    assert_eq!(observed.server_hello.compression_method, 0);
    assert_eq!(
        observed
            .server_hello
            .get_extension(EXTENSION_SUPPORTED_VERSIONS),
        Some(TLS13_VERSION.as_slice())
    );
    assert_eq!(
        observed
            .server_hello
            .get_extension(EXTENSION_KEY_SHARE)
            .map(parse_server_hello_key_share)
            .transpose()
            .expect("valid key_share")
            .expect("key_share present")
            .group,
        NAMED_GROUP_X25519
    );
    assert_eq!(observed.selected_key_share_group, NamedGroup::X25519);
}

#[test]
fn extract_observed_server_hello_accepts_valid_tls13_x25519mlkem768() {
    let message = valid_tls13_x25519mlkem768_server_hello_message();
    let dest_handshake = dest_handshake_from_server_hello_message(&message);

    let observed =
        extract_observed_server_hello(&dest_handshake).expect("valid hybrid ServerHello");

    assert_eq!(
        observed.selected_key_share_group,
        NamedGroup::X25519MLKEM768
    );
    let key_share = parse_server_hello_key_share(
        observed
            .server_hello
            .get_extension(EXTENSION_KEY_SHARE)
            .expect("key_share present"),
    )
    .expect("valid key_share");
    assert_eq!(key_share.group, NAMED_GROUP_X25519MLKEM768);
    assert_eq!(
        key_share.key_exchange.len(),
        X25519_MLKEM768_SERVER_KEY_SHARE_LEN
    );
}

#[test]
fn extract_observed_server_hello_rejects_missing_supported_versions() {
    let message = build_server_hello_handshake_message(&[(
        EXTENSION_KEY_SHARE,
        &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
    )]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("supported_versions"));
}

#[test]
fn extract_observed_server_hello_rejects_non_tls13_supported_versions() {
    let message = build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &[0x03, 0x03]),
        (
            EXTENSION_KEY_SHARE,
            &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
        ),
    ]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("TLS 1.3"));
}

#[test]
fn extract_observed_server_hello_rejects_missing_key_share() {
    let message =
        build_server_hello_handshake_message(&[(EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION)]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("key_share"));
}

#[test]
fn extract_observed_server_hello_rejects_non_x25519_key_share() {
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&0x0017u16.to_be_bytes()); // secp256r1
    key_share.extend_from_slice(&65u16.to_be_bytes());
    key_share.extend_from_slice(&[0x33; 65]);

    let message = build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
        (EXTENSION_KEY_SHARE, &key_share),
    ]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.to_string().contains("0x0017"));
}

#[test]
fn extract_observed_server_hello_rejects_x25519_key_share_len_31() {
    let message = build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
        (EXTENSION_KEY_SHARE, &x25519_key_share_bytes(&[0x22; 31])),
    ]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("32 bytes"));
}

#[test]
fn extract_observed_server_hello_rejects_x25519_key_share_len_33() {
    let message = build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
        (EXTENSION_KEY_SHARE, &x25519_key_share_bytes(&[0x22; 33])),
    ]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("32 bytes"));
}

#[test]
fn extract_observed_server_hello_rejects_hybrid_key_share_len_1119() {
    let message = build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
        (
            EXTENSION_KEY_SHARE,
            &x25519mlkem768_key_share_bytes(&vec![0xA5; X25519_MLKEM768_SERVER_KEY_SHARE_LEN - 1]),
        ),
    ]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("1120"));
}

#[test]
fn extract_observed_server_hello_rejects_hybrid_key_share_len_1121() {
    let message = build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
        (
            EXTENSION_KEY_SHARE,
            &x25519mlkem768_key_share_bytes(&vec![0xA5; X25519_MLKEM768_SERVER_KEY_SHARE_LEN + 1]),
        ),
    ]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("1120"));
}

#[test]
fn extract_observed_server_hello_rejects_truncated_key_share_extension() {
    let mut key_share = x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]);
    key_share.pop();

    let message = build_server_hello_handshake_message(&[
        (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
        (EXTENSION_KEY_SHARE, &key_share),
    ]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            ErrorKind::InvalidData | ErrorKind::UnexpectedEof
        ),
        "unexpected error kind: {:?}",
        err.kind()
    );
}

#[test]
fn prepare_reality_tls13_state_creates_state_for_valid_observed_server_hello() {
    let dest_handshake =
        dest_handshake_from_server_hello_message(&valid_tls13_x25519_server_hello_message());
    let state = prepare_reality_tls13_state(dest_handshake, sample_accepted())
        .expect("valid TLS 1.3 state");

    assert_eq!(state.suite.id, TLS_AES_128_GCM_SHA256);
    assert_eq!(state.suite.name, "TLS_AES_128_GCM_SHA256");
    assert_eq!(state.transcript.algorithm(), Tls13HashAlgorithm::Sha256);
    assert_eq!(state.accepted.sni, Some("example.com".to_string()));
    assert_eq!(
        state.observed_server_hello.selected_key_share_group,
        NamedGroup::X25519
    );
}

#[test]
fn prepare_reality_tls13_state_stores_hybrid_selected_key_share_group() {
    let dest_handshake = dest_handshake_from_server_hello_message(
        &valid_tls13_x25519mlkem768_server_hello_message(),
    );
    let state = prepare_reality_tls13_state(dest_handshake, sample_accepted())
        .expect("valid TLS 1.3 state with hybrid dest");

    assert_eq!(
        state.observed_server_hello.selected_key_share_group,
        NamedGroup::X25519MLKEM768
    );
}

#[test]
fn prepare_reality_tls13_state_rejects_invalid_server_hello() {
    let message =
        build_server_hello_handshake_message(&[(EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION)]);
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = prepare_reality_tls13_state(dest_handshake, sample_accepted()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("key_share"));
}

#[test]
fn prepare_reality_tls13_state_rejects_unknown_cipher_suite() {
    let message = build_server_hello_handshake_message_with_cipher(
        &[
            (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
            (
                EXTENSION_KEY_SHARE,
                &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
            ),
        ],
        0x1304,
    );
    let dest_handshake = dest_handshake_from_server_hello_message_unvalidated(&message);

    let err = prepare_reality_tls13_state(dest_handshake, sample_accepted()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.to_string().contains("0x1304"));
}

fn client_hello_with_x25519_keyshare() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0x33; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: vec![ClientExtension::KeyShare(vec![KeyShareEntry::new(
            NamedGroup::X25519,
            (0u8..32).collect::<Vec<u8>>(),
        )])],
    }
}

fn sample_client_handshake_message() -> Vec<u8> {
    vec![0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00]
}

#[test]
fn prepare_reality_tls13_state_produces_server_handshake_records() {
    use crate::reality::RealityCertificatePatchMode;
    use crate::tls::records::build_handshake_record;

    let dest_handshake =
        dest_handshake_from_server_hello_message(&valid_tls13_x25519_server_hello_message());
    let mut state = prepare_reality_tls13_state(dest_handshake, sample_accepted())
        .expect("valid TLS 1.3 state");
    let client_hello = client_hello_with_x25519_keyshare();
    let client_handshake_message = sample_client_handshake_message();

    state
        .prepare_server_hello(&client_hello)
        .expect("ServerHello message");
    let server_hello_record = build_handshake_record(
        state
            .server_hello_message
            .as_ref()
            .expect("ServerHello message"),
    )
    .expect("ServerHello record");
    let transcript_hash = state
        .update_transcript_client_server_hello(&client_handshake_message)
        .expect("transcript hash");
    state
        .derive_handshake_secrets(&transcript_hash)
        .expect("handshake secrets");
    let encrypted_handshake_records = state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("encrypted server handshake records");

    assert!(!server_hello_record.is_empty());
    assert_eq!(server_hello_record[0], 0x16);
    assert!(!encrypted_handshake_records.is_empty());
    assert_eq!(encrypted_handshake_records[0], 0x17);
    assert!(
        server_hello_record.len() + encrypted_handshake_records.len() > server_hello_record.len()
    );
}
