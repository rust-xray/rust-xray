use super::*;
use crate::protocol::enums::{NamedGroup, ProtocolVersion};
use crate::protocol::structs::{
    ClientExtension, ClientHelloPayload, KeyShareEntry, Random, SessionId,
};
use crate::reality::auth::RealityAuthResult;
use crate::reality::handshake::{
    extract_observed_server_hello, RealityDestHandshake, RealityObservedServerHello,
};
use crate::reality::key_share::build_x25519mlkem768_client_key_share;
use crate::reality::session::RealityClientAuth;
use crate::reality::tls13::cipher_suite::{TLS_AES_128_CCM_SHA256, TLS_AES_128_GCM_SHA256};
use crate::reality::tls13::hash_len;
use crate::reality::tls13::key_share::NAMED_GROUP_X25519 as TLS13_NAMED_GROUP_X25519;
use crate::reality::tls13::messages::build_encrypted_extensions_empty;
use crate::reality::tls13::transcript::Tls13HashAlgorithm;
use crate::tls::records::{parse_tls_records, TLS_RECORD_APPLICATION_DATA};
use crate::tls::{
    parse_tls_server_hello_handshake, TlsRecord, TlsRecordContentType, EXTENSION_KEY_SHARE,
    EXTENSION_SUPPORTED_VERSIONS, NAMED_GROUP_X25519,
};

const TLS_RECORD_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
const X25519_KEY_EXCHANGE_LEN: usize = 32;

fn build_server_hello_handshake_message(cipher_suite: u16, extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let random = [0x11; 32];
    let mut body = Vec::new();
    body.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
    body.extend_from_slice(&random);
    body.push(0);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(0);

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

fn valid_observed_server_hello(cipher_suite: u16) -> RealityObservedServerHello {
    let message = build_server_hello_handshake_message(
        cipher_suite,
        &[
            (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
            (
                EXTENSION_KEY_SHARE,
                &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
            ),
        ],
    );
    let mut raw = Vec::with_capacity(5 + message.len());
    raw.push(0x16);
    raw.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
    raw.extend_from_slice(&(message.len() as u16).to_be_bytes());
    raw.extend_from_slice(&message);

    let dest_handshake = RealityDestHandshake {
        raw_server_bytes: raw.clone(),
        records: vec![TlsRecord {
            content_type: TlsRecordContentType::Handshake,
            legacy_version: TLS_RECORD_LEGACY_VERSION,
            payload: message.clone(),
            raw,
        }],
    };

    extract_observed_server_hello(&dest_handshake).expect("valid observed ServerHello")
}

fn sample_accepted() -> RealityAccepted {
    RealityAccepted {
        auth: RealityAuthResult {
            auth_key: [0xde; 32],
            client_public_key: [0xad; 32],
        },
        client: RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: [0xAB, 0xCD, 0, 0, 0, 0, 0, 0],
        },
        sni: Some("example.com".to_string()),
    }
}

fn client_hello_with_x25519_keyshare(
    payload: Vec<u8>,
    session_id: SessionId,
) -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0x33; 32]),
        session_id,
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: vec![ClientExtension::KeyShare(vec![KeyShareEntry::new(
            NamedGroup::X25519,
            payload,
        )])],
    }
}

fn client_hello_without_keyshare() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0x33; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: Vec::new(),
    }
}

#[test]
fn new_works_with_observed_server_hello_cipher_suite_0x1301() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = RealityTls13ServerState::new(sample_accepted(), observed).expect("valid state");

    assert_eq!(state.suite.id, TLS_AES_128_GCM_SHA256);
    assert_eq!(state.suite.name, "TLS_AES_128_GCM_SHA256");
    assert_eq!(state.transcript.algorithm(), Tls13HashAlgorithm::Sha256);
    assert_eq!(state.accepted.sni, Some("example.com".to_string()));
    assert!(state.server_key_share.is_none());
    assert!(state.server_hello_message.is_none());
    assert!(state.handshake_secrets.is_none());
    assert!(state.server_finished_message.is_none());
    assert!(!state.client_finished_verified);
    assert!(state.application_secrets.is_none());
    assert!(state.application_secret_transcript_hash.is_none());
}

#[test]
fn new_rejects_ccm_cipher_suite_with_explicit_message() {
    let observed = valid_observed_server_hello(TLS_AES_128_CCM_SHA256);
    let err = RealityTls13ServerState::new(sample_accepted(), observed).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    let message = err.to_string();
    assert!(message.contains("CCM"), "{message}");
    assert!(message.contains("0x1304"), "{message}");
    assert!(message.contains("TLS_AES_128_GCM_SHA256"), "{message}");
}

#[test]
fn debug_does_not_include_auth_key_or_raw_handshake_bytes() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = RealityTls13ServerState::new(sample_accepted(), observed.clone()).unwrap();
    let debug = format!("{state:?}");

    assert!(!debug.contains("auth_key"));
    assert!(!debug.contains("0xde"));
    assert!(!debug.contains(&format!("{:?}", observed.raw_handshake_message)));
    assert!(debug.contains("TLS_AES_128_GCM_SHA256"));
    assert!(debug.contains("example.com"));
    assert!(debug.contains("[1, 8, 0, 0]"));
    assert!(debug.contains("raw_handshake_message_len"));
}

#[test]
fn prepare_server_hello_builds_handshake_message_and_stores_state() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
    let client_key: [u8; 32] = core::array::from_fn(|i| 0x44 + i as u8);
    let client_hello = client_hello_with_x25519_keyshare(client_key.to_vec(), SessionId::empty());

    let message = state
        .prepare_server_hello(&client_hello)
        .expect("valid ServerHello plan")
        .to_vec();

    assert_eq!(message[0], HANDSHAKE_TYPE_SERVER_HELLO);
    assert!(state.server_key_share.is_some());
    assert_eq!(
        state.server_hello_message.as_deref(),
        Some(message.as_slice())
    );
}

#[test]
fn prepare_server_hello_requires_client_x25519_key_share() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();

    let err = state
        .prepare_server_hello(&client_hello_without_keyshare())
        .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.to_string().contains("X25519 key_share"));
    assert!(state.server_key_share.is_none());
    assert!(state.server_hello_message.is_none());
}

#[test]
fn prepare_server_hello_with_hybrid_and_standalone_client_keyshares_stays_x25519_only() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();

    let hybrid_tail: [u8; 32] = [0xAA; 32];
    let standalone: [u8; 32] = core::array::from_fn(|i| 0x44 + i as u8);
    assert_ne!(hybrid_tail, standalone);

    let client_hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0x33; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: vec![ClientExtension::KeyShare(vec![
            KeyShareEntry::new(
                NamedGroup::X25519MLKEM768,
                build_x25519mlkem768_client_key_share(hybrid_tail),
            ),
            KeyShareEntry::new(NamedGroup::X25519, standalone.to_vec()),
        ])],
    };

    state
        .prepare_server_hello(&client_hello)
        .expect("Stage 2 accepted TLS path still uses standalone X25519");

    let server_share = state.server_key_share.as_ref().expect("server key share");
    assert_eq!(server_share.group, TLS13_NAMED_GROUP_X25519);
    assert_eq!(server_share.key_exchange().len(), X25519_KEY_EXCHANGE_LEN);
    assert_eq!(server_share.shared_secret().len(), X25519_KEY_EXCHANGE_LEN);
}

#[test]
fn prepare_server_hello_rejects_hybrid_only_client_key_share() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();

    let hybrid_tail: [u8; 32] = core::array::from_fn(|i| i as u8);
    let client_hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0x33; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: vec![ClientExtension::KeyShare(vec![KeyShareEntry::new(
            NamedGroup::X25519MLKEM768,
            build_x25519mlkem768_client_key_share(hybrid_tail),
        )])],
    };

    let err = state.prepare_server_hello(&client_hello).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.to_string().contains("X25519 key_share"));
    assert!(state.server_key_share.is_none());
}

#[test]
fn prepare_server_hello_message_parses_as_tls13_server_hello() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
    let client_key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let client_hello = client_hello_with_x25519_keyshare(client_key.to_vec(), SessionId::empty());

    let message = state
        .prepare_server_hello(&client_hello)
        .expect("valid ServerHello plan")
        .to_vec();
    let parsed = parse_tls_server_hello_handshake(&message).expect("parsable ServerHello");

    assert_eq!(parsed.cipher_suite, TLS_AES_128_GCM_SHA256);
    assert_eq!(parsed.random, [0x11; 32]);
    assert_eq!(parsed.session_id_echo, client_hello.session_id.as_bytes());
    assert!(parsed.get_extension(EXTENSION_SUPPORTED_VERSIONS).is_some());
    assert!(parsed.get_extension(EXTENSION_KEY_SHARE).is_some());
}

fn sample_client_hello_handshake_message() -> Vec<u8> {
    vec![0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00]
}

fn state_with_prepared_server_hello() -> RealityTls13ServerState {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
    let client_key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let client_hello = client_hello_with_x25519_keyshare(client_key.to_vec(), SessionId::empty());
    state
        .prepare_server_hello(&client_hello)
        .expect("valid ServerHello plan");
    state
}

fn state_with_fixed_server_hello_message(server_hello_message: Vec<u8>) -> RealityTls13ServerState {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
    state.server_hello_message = Some(server_hello_message);
    state
}

#[test]
fn update_transcript_client_server_hello_changes_digest() {
    let mut state = state_with_prepared_server_hello();
    let empty_digest = state.transcript.digest();
    let client_hello_message = sample_client_hello_handshake_message();

    let digest = state
        .update_transcript_client_server_hello(&client_hello_message)
        .expect("valid transcript update");

    assert_ne!(digest, empty_digest);
    assert_eq!(digest.len(), 32);
    assert_eq!(
        state.transcript.len(),
        client_hello_message.len()
            + state
                .server_hello_message
                .as_ref()
                .expect("server hello stored")
                .len()
    );
}

#[test]
fn update_transcript_client_server_hello_is_deterministic() {
    let client_hello_message = sample_client_hello_handshake_message();
    let server_hello_message = vec![0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00];

    let mut first = state_with_fixed_server_hello_message(server_hello_message.clone());
    let first_digest = first
        .update_transcript_client_server_hello(&client_hello_message)
        .expect("valid transcript update");

    let mut second = state_with_fixed_server_hello_message(server_hello_message);
    let second_digest = second
        .update_transcript_client_server_hello(&client_hello_message)
        .expect("valid transcript update");

    assert_eq!(first_digest, second_digest);
}

#[test]
fn update_transcript_client_server_hello_rejects_wrong_client_handshake_type() {
    let mut state = state_with_prepared_server_hello();
    let err = state
        .update_transcript_client_server_hello(&[0x02, 0x00, 0x00, 0x01, 0x00])
        .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("0x01"));
}

#[test]
fn update_transcript_client_server_hello_requires_server_hello_message() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();

    let err = state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("ServerHello message"));
}

#[test]
fn derive_handshake_secrets_stores_traffic_secrets() {
    let mut state = state_with_prepared_server_hello();
    let transcript_hash = state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("valid transcript update");

    state
        .derive_handshake_secrets(&transcript_hash)
        .expect("valid handshake secret derivation");

    let secrets = state
        .handshake_secrets
        .as_ref()
        .expect("handshake secrets stored");
    assert_eq!(secrets.handshake_secret.len(), 32);
    assert_eq!(secrets.client_handshake_traffic_secret.len(), 32);
    assert_eq!(secrets.server_handshake_traffic_secret.len(), 32);
    assert_ne!(
        secrets.client_handshake_traffic_secret,
        secrets.server_handshake_traffic_secret
    );
}

#[test]
fn derive_handshake_secrets_requires_server_key_share() {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();

    let err = state.derive_handshake_secrets(&[0x01; 32]).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("ECDHE key share"));
    assert!(state.handshake_secrets.is_none());
}

fn state_with_handshake_secrets() -> RealityTls13ServerState {
    let mut state = state_with_prepared_server_hello();
    let transcript_hash = state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("valid transcript update");
    state
        .derive_handshake_secrets(&transcript_hash)
        .expect("valid handshake secret derivation");
    state
}

#[test]
fn build_encrypted_server_handshake_records_uses_patched_certificate() {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    use crate::reality::tls13::derive_traffic_key;
    use crate::reality::tls13::messages::HANDSHAKE_TYPE_CERTIFICATE;
    use crate::reality::tls13::record_crypto::{
        parse_tls13_handshake_inner_plaintext, Tls13RecordDecryptor,
    };

    let mut state = state_with_handshake_secrets();
    let auth_key = state.accepted.auth.auth_key;
    let server_handshake_traffic_secret = state
        .handshake_secrets
        .as_ref()
        .expect("handshake secrets")
        .server_handshake_traffic_secret
        .clone();
    let records = state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("valid encrypted handshake records");
    let parsed = parse_tls_records(&records).expect("parsable encrypted records");
    assert_eq!(parsed.len(), 4);

    let traffic_keys =
        derive_traffic_key(state.suite, &server_handshake_traffic_secret).expect("traffic keys");
    let mut decryptor =
        Tls13RecordDecryptor::new(state.suite, traffic_keys).expect("valid decryptor");
    decryptor
        .decrypt_record_payload(&parsed[0])
        .expect("decrypt EncryptedExtensions");
    let certificate_inner = decryptor
        .decrypt_record_payload(&parsed[1])
        .expect("decrypt Certificate");
    let certificate_message =
        parse_tls13_handshake_inner_plaintext(&certificate_inner).expect("certificate message");

    assert_eq!(certificate_message[0], HANDSHAKE_TYPE_CERTIFICATE);
    let cert_der_len = u32::from_be_bytes([
        0,
        certificate_message[8],
        certificate_message[9],
        certificate_message[10],
    ]) as usize;
    let cert_der = &certificate_message[11..11 + cert_der_len];
    let public_key_raw = ed25519_public_key_bytes_in_rcgen_der(cert_der);

    let mut mac = Hmac::<Sha512>::new_from_slice(&auth_key).expect("valid HMAC key");
    mac.update(&public_key_raw);
    let expected_tail = mac.finalize().into_bytes();

    assert_eq!(&cert_der[cert_der.len() - 64..], expected_tail.as_slice());
}

fn ed25519_public_key_bytes_in_rcgen_der(der: &[u8]) -> [u8; 32] {
    const SUBJECT_PUBLIC_KEY_BIT_STRING: [u8; 3] = [0x03, 0x21, 0x00];
    let start = der
        .windows(SUBJECT_PUBLIC_KEY_BIT_STRING.len())
        .position(|window| window == SUBJECT_PUBLIC_KEY_BIT_STRING)
        .expect("Ed25519 subject public key BIT STRING")
        + SUBJECT_PUBLIC_KEY_BIT_STRING.len();
    der[start..start + 32]
        .try_into()
        .expect("Ed25519 public key is 32 bytes")
}

#[test]
fn build_encrypted_server_handshake_records_non_empty() {
    let mut state = state_with_handshake_secrets();
    let records = state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("valid encrypted handshake records");

    assert!(!records.is_empty());
}

#[test]
fn build_encrypted_server_handshake_records_first_record_is_application_data() {
    let mut state = state_with_handshake_secrets();
    let records = state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("valid encrypted handshake records");

    assert_eq!(records[0], TLS_RECORD_APPLICATION_DATA);
    let parsed = parse_tls_records(&records).expect("parsable encrypted records");
    assert_eq!(parsed.len(), 4);
    assert_eq!(
        parsed[0].content_type,
        TlsRecordContentType::ApplicationData
    );
}

#[test]
fn build_encrypted_server_handshake_records_updates_transcript_with_plaintext_messages() {
    let mut state = state_with_handshake_secrets();
    let transcript_len_before = state.transcript.len();

    state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("valid encrypted handshake records");

    assert!(state.transcript.len() > transcript_len_before);
    assert!(state.server_finished_message.is_some());
}

#[test]
fn build_encrypted_server_handshake_records_requires_handshake_secrets() {
    let mut state = state_with_prepared_server_hello();
    state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("valid transcript update");

    let err = state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("handshake secrets"));
}

fn state_ready_for_server_finished() -> RealityTls13ServerState {
    let mut state = state_with_handshake_secrets();
    let encrypted_extensions = build_encrypted_extensions_empty().expect("valid EE");
    state.transcript.update(&encrypted_extensions);
    state
}

fn build_valid_client_finished_message(state: &RealityTls13ServerState) -> Vec<u8> {
    let secrets = state.handshake_secrets.as_ref().expect("handshake secrets");
    let finished_key = derive_finished_key(state.suite, &secrets.client_handshake_traffic_secret)
        .expect("client finished key");
    let transcript_hash = state.transcript.digest();
    let verify_data = compute_finished_verify_data(state.suite, &finished_key, &transcript_hash)
        .expect("client verify_data");
    build_finished(&verify_data).expect("client Finished message")
}

#[test]
fn build_server_finished_message_length_matches_hash_len() {
    let mut state = state_ready_for_server_finished();
    let finished = state
        .build_server_finished_message()
        .expect("valid server Finished message");

    assert_eq!(finished[0], HANDSHAKE_TYPE_FINISHED);
    assert_eq!(finished.len(), 4 + hash_len(state.suite.hash));
    assert_eq!(
        state.server_finished_message.as_deref(),
        Some(finished.as_slice())
    );
}

#[test]
fn build_server_finished_message_requires_handshake_secrets() {
    let mut state = state_with_prepared_server_hello();
    state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("valid transcript update");

    let err = state.build_server_finished_message().unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("handshake secrets"));
    assert!(state.server_finished_message.is_none());
}

#[test]
fn verify_client_finished_message_accepts_valid_data() {
    let mut state = state_ready_for_server_finished();
    state
        .build_server_finished_message()
        .expect("valid server Finished message");
    let client_finished = build_valid_client_finished_message(&state);

    let verified = state
        .verify_client_finished_message(&client_finished)
        .expect("valid client Finished verification");

    assert!(verified);
    assert!(state.client_finished_verified);
    assert!(state.application_secret_transcript_hash.is_some());
}

#[test]
fn verify_client_finished_message_rejects_wrong_data() {
    let mut state = state_ready_for_server_finished();
    state
        .build_server_finished_message()
        .expect("valid server Finished message");
    let mut client_finished = build_valid_client_finished_message(&state);
    client_finished[7] ^= 0x01;

    let verified = state
        .verify_client_finished_message(&client_finished)
        .expect("client Finished verification result");

    assert!(!verified);
    assert!(!state.client_finished_verified);
    assert!(state.application_secret_transcript_hash.is_none());
}

#[test]
fn verify_client_finished_message_updates_transcript_only_on_success() {
    let mut state = state_ready_for_server_finished();
    state
        .build_server_finished_message()
        .expect("valid server Finished message");
    let transcript_len_before = state.transcript.len();
    let mut invalid_finished = build_valid_client_finished_message(&state);
    invalid_finished[8] ^= 0x02;

    let verified = state
        .verify_client_finished_message(&invalid_finished)
        .expect("client Finished verification result");
    assert!(!verified);
    assert_eq!(state.transcript.len(), transcript_len_before);
    assert!(state.application_secret_transcript_hash.is_none());

    let valid_finished = build_valid_client_finished_message(&state);
    let verified = state
        .verify_client_finished_message(&valid_finished)
        .expect("client Finished verification result");
    assert!(verified);
    assert_eq!(
        state.transcript.len(),
        transcript_len_before + valid_finished.len()
    );
    assert!(state.application_secret_transcript_hash.is_some());
}

#[test]
fn verify_client_finished_message_requires_handshake_secrets() {
    let mut state = state_with_prepared_server_hello();
    let err = state
        .verify_client_finished_message(&[0x14, 0x00, 0x00, 0x20])
        .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("handshake secrets"));
    assert!(!state.client_finished_verified);
}

fn state_with_verified_client_finished() -> RealityTls13ServerState {
    let mut state = state_ready_for_server_finished();
    state
        .build_server_finished_message()
        .expect("valid server Finished message");
    let client_finished = build_valid_client_finished_message(&state);
    assert!(state
        .verify_client_finished_message(&client_finished)
        .expect("client Finished verification result"));
    state
}

#[test]
fn derive_application_secrets_stores_traffic_secrets() {
    let mut state = state_with_verified_client_finished();
    state
        .derive_application_secrets()
        .expect("valid application secret derivation");

    let secrets = state
        .application_secrets
        .as_ref()
        .expect("application secrets stored");
    assert_eq!(secrets.master_secret.len(), hash_len(state.suite.hash));
    assert_eq!(
        secrets.client_application_traffic_secret.len(),
        hash_len(state.suite.hash)
    );
    assert_eq!(
        secrets.server_application_traffic_secret.len(),
        hash_len(state.suite.hash)
    );
    assert_ne!(
        secrets.client_application_traffic_secret,
        secrets.server_application_traffic_secret
    );
}

#[test]
fn derive_application_secrets_uses_transcript_before_client_finished() {
    let mut state = state_ready_for_server_finished();
    state
        .build_server_finished_message()
        .expect("valid server Finished message");

    let handshake_secret = state
        .handshake_secrets
        .as_ref()
        .expect("handshake secrets")
        .handshake_secret
        .clone();
    let transcript_hash_before = state.transcript.digest();
    let expected_secrets =
        derive_application_traffic_secrets(state.suite, &handshake_secret, &transcript_hash_before)
            .expect("expected application secrets");

    let client_finished = build_valid_client_finished_message(&state);
    assert!(state
        .verify_client_finished_message(&client_finished)
        .expect("client Finished verification result"));

    let transcript_hash_after = state.transcript.digest();
    assert_ne!(transcript_hash_before, transcript_hash_after);

    state
        .derive_application_secrets()
        .expect("valid application secret derivation");

    let secrets = state
        .application_secrets
        .as_ref()
        .expect("application secrets stored");
    assert_eq!(secrets, &expected_secrets);

    let wrong_secrets =
        derive_application_traffic_secrets(state.suite, &handshake_secret, &transcript_hash_after)
            .expect("secrets from post-client-finished transcript");
    assert_ne!(secrets, &wrong_secrets);
}

#[test]
fn failed_client_finished_does_not_store_application_secret_transcript_hash() {
    let mut state = state_ready_for_server_finished();
    state
        .build_server_finished_message()
        .expect("valid server Finished message");
    let mut invalid_finished = build_valid_client_finished_message(&state);
    invalid_finished[7] ^= 0x01;

    let verified = state
        .verify_client_finished_message(&invalid_finished)
        .expect("client Finished verification result");

    assert!(!verified);
    assert!(state.application_secret_transcript_hash.is_none());
    assert!(!state.client_finished_verified);
}

#[test]
fn derive_application_secrets_requires_verified_client_finished() {
    let mut state = state_ready_for_server_finished();
    state
        .build_server_finished_message()
        .expect("valid server Finished message");

    let err = state.derive_application_secrets().unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("client Finished"));
    assert!(state.application_secrets.is_none());
}

#[test]
fn derive_application_secrets_requires_application_secret_transcript_hash() {
    let mut state = state_ready_for_server_finished();
    state
        .build_server_finished_message()
        .expect("valid server Finished message");
    state.client_finished_verified = true;

    let err = state.derive_application_secrets().unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("before client Finished"));
    assert!(state.application_secrets.is_none());
}

#[test]
fn derive_application_secrets_requires_handshake_secrets() {
    let mut state = state_with_prepared_server_hello();
    state.client_finished_verified = true;

    let err = state.derive_application_secrets().unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("handshake secrets"));
    assert!(state.application_secrets.is_none());
}

#[test]
fn decrypt_client_finished_handshake_message_reports_decrypt_failure_context() {
    use crate::reality::tls13::record_crypto::Tls13RecordEncryptor;
    use crate::reality::tls13::{tls13_cipher_suite, Tls13TrafficKeys, TLS_AES_128_GCM_SHA256};
    use crate::tls::records::parse_tls_records;

    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let encrypt_keys = Tls13TrafficKeys {
        key: (0x10..0x20).collect(),
        iv: (0x01..0x0d).collect(),
    };
    let decrypt_keys = Tls13TrafficKeys {
        key: (0x20..0x30).collect(),
        iv: (0x01..0x0d).collect(),
    };

    let mut encryptor = Tls13RecordEncryptor::new(suite, encrypt_keys).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_handshake_message(&[HANDSHAKE_TYPE_FINISHED, 0x00, 0x00, 0x20])
        .expect("valid encrypted record");
    let record = parse_tls_records(&record_bytes)
        .expect("parsable record")
        .swap_remove(0);

    let mut decryptor = Tls13RecordDecryptor::new(suite, decrypt_keys).expect("valid decryptor");
    let err = decrypt_client_finished_handshake_message(&mut decryptor, &record).unwrap_err();

    assert!(err.to_string().contains("client Finished decrypt failed"));
    assert!(err.to_string().contains("encrypted_record_len="));
    assert!(err.to_string().contains("sequence=0"));
    assert!(!err.to_string().contains("101112131415161718191a1b1c1d1e1f"));
}

#[test]
fn decrypt_client_finished_handshake_message_accepts_non_finished_handshake_type() {
    use crate::reality::tls13::record_crypto::Tls13RecordEncryptor;
    use crate::reality::tls13::{tls13_cipher_suite, Tls13TrafficKeys, TLS_AES_128_GCM_SHA256};
    use crate::tls::records::parse_tls_records;

    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = Tls13TrafficKeys {
        key: (0x10..0x20).collect(),
        iv: (0x01..0x0d).collect(),
    };
    let server_hello = vec![HANDSHAKE_TYPE_SERVER_HELLO, 0x00, 0x00, 0x01, 0x00];

    let mut encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor");
    let record_bytes = encryptor
        .encrypt_handshake_message(&server_hello)
        .expect("valid encrypted record");
    let record = parse_tls_records(&record_bytes)
        .expect("parsable record")
        .swap_remove(0);

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("decryptor");
    let decrypted =
        decrypt_client_finished_handshake_message(&mut decryptor, &record).expect("decrypt");

    assert_eq!(decrypted, server_hello);
}

#[test]
fn client_finished_decrypt_errors_do_not_include_secret_field_names() {
    use crate::reality::tls13::record_crypto::Tls13RecordEncryptor;
    use crate::reality::tls13::{tls13_cipher_suite, Tls13TrafficKeys, TLS_AES_128_GCM_SHA256};
    use crate::tls::records::parse_tls_records;

    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let encrypt_keys = Tls13TrafficKeys {
        key: (0x10..0x20).collect(),
        iv: (0x01..0x0d).collect(),
    };
    let decrypt_keys = Tls13TrafficKeys {
        key: (0x20..0x30).collect(),
        iv: (0x01..0x0d).collect(),
    };

    let mut encryptor = Tls13RecordEncryptor::new(suite, encrypt_keys).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_handshake_message(&[HANDSHAKE_TYPE_FINISHED, 0x00, 0x00, 0x20])
        .expect("valid encrypted record");
    let record = parse_tls_records(&record_bytes)
        .expect("parsable record")
        .swap_remove(0);

    let mut decryptor = Tls13RecordDecryptor::new(suite, decrypt_keys).expect("valid decryptor");
    let err = decrypt_client_finished_handshake_message(&mut decryptor, &record).unwrap_err();
    let message = err.to_string().to_ascii_lowercase();

    assert!(!message.contains("privatekey"));
    assert!(!message.contains("auth_key"));
    assert!(!message.contains("traffic_secret"));
    assert!(!message.contains("handshake_secret"));
}
