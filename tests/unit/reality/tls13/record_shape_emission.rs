use super::*;
use crate::protocol::structs::SessionId;
use crate::reality::target_server_flight::{
    ObservedEncryptedHandshakeSlot, ObservedTargetTls13ServerFlight,
};
use crate::reality::tls13::record_crypto::{
    minimum_tls13_encrypted_handshake_record_wire_len, parse_tls13_handshake_inner_plaintext,
    tls13_inner_plaintext_metadata, Tls13RecordDecryptor, Tls13RecordEncryptor,
};
use crate::reality::tls13::state::assemble_server_handshake_flight_out;
use crate::reality::tls13::{
    build_encrypted_extensions_empty, derive_traffic_key, tls13_cipher_suite,
    TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
};
use crate::reality::RealityCertificatePatchMode;
use crate::tls::records::{
    build_change_cipher_spec_record, build_handshake_record, parse_tls_records,
    TlsRecordContentType, TLS_LEGACY_VERSION_1_2, TLS_RECORD_HANDSHAKE,
};

fn flight_with_encrypted_lens(
    ee: usize,
    cert: usize,
    cert_verify: usize,
    finished: usize,
) -> ObservedTargetTls13ServerFlight {
    ObservedTargetTls13ServerFlight {
        encrypted_extensions_wire_len: Some(ee),
        certificate_wire_len: Some(cert),
        certificate_verify_wire_len: Some(cert_verify),
        finished_wire_len: Some(finished),
        ..ObservedTargetTls13ServerFlight::default()
    }
}

fn state_with_flight_and_suite(
    flight: ObservedTargetTls13ServerFlight,
    cipher_suite: u16,
) -> RealityTls13ServerState {
    let observed = valid_observed_server_hello(cipher_suite);
    let mut state =
        RealityTls13ServerState::new(sample_accepted(), observed, flight).expect("valid state");
    let client_key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let client_hello = client_hello_with_x25519_keyshare(client_key.to_vec(), SessionId::empty());
    state
        .prepare_server_hello(&client_hello)
        .expect("ServerHello");
    let transcript_hash = state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("transcript");
    state
        .derive_handshake_secrets(&transcript_hash)
        .expect("handshake secrets");
    state
}

fn build_encrypted_records(state: &mut RealityTls13ServerState) -> Vec<u8> {
    state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("encrypted records")
}

fn build_encrypted_records_result(state: &mut RealityTls13ServerState) -> std::io::Result<Vec<u8>> {
    state.build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
}

fn parsed_encrypted_records(records: &[u8]) -> Vec<crate::tls::TlsRecord> {
    parse_tls_records(records).expect("parsable encrypted records")
}

#[test]
fn server_handshake_flight_order_is_server_hello_ccs_then_encrypted() {
    let mut state = state_with_handshake_secrets();
    let server_hello_record =
        build_handshake_record(state.server_hello_message.as_ref().expect("sh")).expect("record");
    let encrypted = build_encrypted_records(&mut state);
    let flight = assemble_server_handshake_flight_out(&server_hello_record, &encrypted);
    let parsed = parse_tls_records(&flight).expect("parsable flight");

    assert_eq!(parsed.len(), 6);
    assert_eq!(parsed[0].content_type, TlsRecordContentType::Handshake);
    assert_eq!(
        parsed[1].content_type,
        TlsRecordContentType::ChangeCipherSpec
    );
    assert_eq!(parsed[1].raw, build_change_cipher_spec_record());
    for record in &parsed[2..] {
        assert_eq!(record.content_type, TlsRecordContentType::ApplicationData);
        assert_eq!(record.legacy_version, TLS_LEGACY_VERSION_1_2);
        assert_eq!(record.raw[0], 0x17);
    }
}

#[test]
fn transcript_unaffected_by_record_layer_padding() {
    let mut state = state_with_handshake_secrets();
    let ee = build_encrypted_extensions_empty().expect("ee");
    state.transcript.update(&ee);
    let digest_before = state.transcript.digest();

    let secrets = state.handshake_secrets.as_ref().expect("handshake secrets");
    let traffic_keys =
        derive_traffic_key(state.suite, &secrets.server_handshake_traffic_secret).expect("keys");
    let mut padded_encryptor =
        Tls13RecordEncryptor::new(state.suite, traffic_keys.clone()).expect("encryptor");
    let mut unpadded_encryptor =
        Tls13RecordEncryptor::new(state.suite, traffic_keys).expect("encryptor");
    padded_encryptor
        .encrypt_handshake_message_with_desired_wire_len(&ee, Some(200))
        .expect("padded record");
    unpadded_encryptor
        .encrypt_handshake_message_with_desired_wire_len(&ee, None)
        .expect("unpadded record");

    assert_eq!(state.transcript.digest(), digest_before);
}

#[test]
fn padded_and_unpadded_records_share_same_handshake_plaintext() {
    let ee = build_encrypted_extensions_empty().expect("ee");
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let min_wire =
        minimum_tls13_encrypted_handshake_record_wire_len(suite, ee.len()).expect("min wire");
    let target_len = min_wire + 37;

    let secrets = state_with_handshake_secrets()
        .handshake_secrets
        .clone()
        .expect("secrets");
    let traffic_keys =
        derive_traffic_key(suite, &secrets.server_handshake_traffic_secret).expect("keys");
    let mut padded_encryptor =
        Tls13RecordEncryptor::new(suite, traffic_keys.clone()).expect("encryptor");
    let mut unpadded_encryptor = Tls13RecordEncryptor::new(suite, traffic_keys).expect("encryptor");
    let padded_record = padded_encryptor
        .encrypt_handshake_message_with_desired_wire_len(&ee, Some(target_len))
        .expect("padded record");
    let unpadded_record = unpadded_encryptor
        .encrypt_handshake_message_with_desired_wire_len(&ee, None)
        .expect("unpadded record");
    assert_eq!(unpadded_record.len(), min_wire);
    assert_eq!(padded_record.len(), target_len);

    let mut padded_decryptor =
        Tls13RecordDecryptor::new(suite, padded_encryptor.keys).expect("decryptor");
    let mut unpadded_decryptor =
        Tls13RecordDecryptor::new(suite, unpadded_encryptor.keys).expect("decryptor");
    let padded_parsed = parse_tls_records(&padded_record).expect("record")[0].clone();
    let unpadded_parsed = parse_tls_records(&unpadded_record).expect("record")[0].clone();
    let padded_handshake = padded_decryptor
        .decrypt_handshake_record(&padded_parsed)
        .expect("decrypted padded handshake");
    let unpadded_handshake = unpadded_decryptor
        .decrypt_handshake_record(&unpadded_parsed)
        .expect("decrypted unpadded handshake");
    assert_eq!(padded_handshake, ee);
    assert_eq!(unpadded_handshake, ee);
}

#[test]
fn encrypted_extensions_record_matches_observed_wire_length() {
    let target_len = 200;
    let mut state = state_with_flight_and_suite(
        flight_with_encrypted_lens(target_len, 900, 320, 128),
        TLS_AES_128_GCM_SHA256,
    );
    let records = parsed_encrypted_records(&build_encrypted_records(&mut state));
    assert_eq!(records[0].raw.len(), target_len);
    assert_wire_application_data_header(&records[0].raw, target_len);
}

#[test]
fn certificate_record_matches_observed_wire_length() {
    let target_len = 900;
    let mut state = state_with_flight_and_suite(
        flight_with_encrypted_lens(200, target_len, 320, 128),
        TLS_AES_128_GCM_SHA256,
    );
    let records = parsed_encrypted_records(&build_encrypted_records(&mut state));
    assert_eq!(records[1].raw.len(), target_len);
    assert_wire_application_data_header(&records[1].raw, target_len);
}

#[test]
fn certificate_verify_record_matches_observed_wire_length() {
    let target_len = 320;
    let mut state = state_with_flight_and_suite(
        flight_with_encrypted_lens(200, 900, target_len, 128),
        TLS_AES_128_GCM_SHA256,
    );
    let records = parsed_encrypted_records(&build_encrypted_records(&mut state));
    assert_eq!(records[2].raw.len(), target_len);
    assert_wire_application_data_header(&records[2].raw, target_len);
}

#[test]
fn finished_record_matches_observed_wire_length() {
    let target_len = 128;
    let mut state = state_with_flight_and_suite(
        flight_with_encrypted_lens(200, 900, 320, target_len),
        TLS_AES_128_GCM_SHA256,
    );
    let records = parsed_encrypted_records(&build_encrypted_records(&mut state));
    assert_eq!(records[3].raw.len(), target_len);
    assert_wire_application_data_header(&records[3].raw, target_len);
}

#[test]
fn desired_wire_length_equal_to_minimum_has_no_extra_padding() {
    let ee = build_encrypted_extensions_empty().expect("ee");
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let min_wire =
        minimum_tls13_encrypted_handshake_record_wire_len(suite, ee.len()).expect("min wire");

    let mut state = state_with_flight_and_suite(
        flight_with_encrypted_lens(min_wire, 900, 320, 128),
        TLS_AES_128_GCM_SHA256,
    );
    let records = parsed_encrypted_records(&build_encrypted_records(&mut state));
    assert_eq!(records[0].raw.len(), min_wire);
}

#[test]
fn desired_wire_length_greater_than_minimum_adds_zero_padding() {
    let ee = build_encrypted_extensions_empty().expect("ee");
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let min_wire =
        minimum_tls13_encrypted_handshake_record_wire_len(suite, ee.len()).expect("min wire");
    let target_len = min_wire + 37;

    let secrets = state_with_flight_and_suite(
        ObservedTargetTls13ServerFlight::default(),
        TLS_AES_128_GCM_SHA256,
    )
    .handshake_secrets
    .clone()
    .expect("secrets");
    let traffic_keys =
        derive_traffic_key(suite, &secrets.server_handshake_traffic_secret).expect("keys");
    let mut encryptor = Tls13RecordEncryptor::new(suite, traffic_keys).expect("encryptor");
    let record = encryptor
        .encrypt_handshake_message_with_desired_wire_len(&ee, Some(target_len))
        .expect("padded record");
    assert_eq!(record.len(), target_len);

    let mut decryptor = Tls13RecordDecryptor::new(suite, encryptor.keys).expect("decryptor");
    let parsed = parse_tls_records(&record).expect("record")[0].clone();
    let inner_plaintext = decryptor
        .decrypt_record_payload(&parsed)
        .expect("decrypted inner plaintext");
    let handshake =
        parse_tls13_handshake_inner_plaintext(&inner_plaintext).expect("handshake body");
    assert_eq!(handshake, ee);
    let (body, content_type, padding_len) =
        tls13_inner_plaintext_metadata(&inner_plaintext).expect("inner metadata");
    assert_eq!(body, ee);
    assert_eq!(content_type, TLS_RECORD_HANDSHAKE);
    assert_eq!(padding_len, target_len - min_wire);
}

#[test]
fn desired_wire_length_smaller_than_minimum_returns_error() {
    let ee = build_encrypted_extensions_empty().expect("ee");
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let min_wire =
        minimum_tls13_encrypted_handshake_record_wire_len(suite, ee.len()).expect("min wire");

    let mut state = state_with_flight_and_suite(
        flight_with_encrypted_lens(min_wire.saturating_sub(1), 900, 320, 128),
        TLS_AES_128_GCM_SHA256,
    );
    let err = build_encrypted_records_result(&mut state).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("smaller than minimum"));
}

#[test]
fn missing_observed_lengths_keep_unpadded_minimum_records() {
    let mut state = state_with_flight_and_suite(
        ObservedTargetTls13ServerFlight::default(),
        TLS_AES_128_GCM_SHA256,
    );
    let records = parsed_encrypted_records(&build_encrypted_records(&mut state));
    let ee = build_encrypted_extensions_empty().expect("ee");
    let suite = state.suite;
    let min_wire =
        minimum_tls13_encrypted_handshake_record_wire_len(suite, ee.len()).expect("min wire");
    assert_eq!(records[0].raw.len(), min_wire);
}

#[test]
fn aes128_gcm_record_shape_padding_emission() {
    assert_cipher_suite_padded_emission(TLS_AES_128_GCM_SHA256);
}

#[test]
fn aes256_gcm_record_shape_padding_emission() {
    assert_cipher_suite_padded_emission(TLS_AES_256_GCM_SHA384);
}

#[test]
fn chacha20_poly1305_record_shape_padding_emission() {
    assert_cipher_suite_padded_emission(TLS_CHACHA20_POLY1305_SHA256);
}

fn assert_cipher_suite_padded_emission(cipher_suite: u16) {
    let mut state =
        state_with_flight_and_suite(flight_with_encrypted_lens(220, 950, 340, 140), cipher_suite);
    let records = parsed_encrypted_records(&build_encrypted_records(&mut state));
    assert_eq!(records[0].raw.len(), 220);
    assert_eq!(records[1].raw.len(), 950);
    assert_eq!(records[2].raw.len(), 340);
    assert_eq!(records[3].raw.len(), 140);
}

#[test]
fn x25519_handshake_unaffected_by_record_shape_padding() {
    let mut state = state_with_flight_and_suite(
        flight_with_encrypted_lens(200, 900, 320, 128),
        TLS_AES_128_GCM_SHA256,
    );
    build_encrypted_records(&mut state);
    assert_eq!(
        state.observed_server_hello.selected_key_share_group,
        NamedGroup::X25519
    );
    let message = state.server_hello_message.as_ref().expect("sh");
    assert!(message.windows(4).any(|w| w == [0x00, 0x1d, 0x00, 0x20]));
}

#[test]
fn hybrid_x25519mlkem768_handshake_unaffected_by_record_shape_padding() {
    let (client_hybrid, _, _) = build_valid_client_hybrid_share();
    let observed = valid_observed_hybrid_server_hello(TLS_AES_128_GCM_SHA256, &[0xA5; 1120]);
    let flight = flight_with_encrypted_lens(200, 900, 320, 128);
    let mut state =
        RealityTls13ServerState::new(sample_accepted(), observed, flight).expect("valid state");
    state
        .prepare_server_hello(&client_hello_with_hybrid_keyshare(client_hybrid))
        .expect("hybrid ServerHello");
    assert_eq!(
        state.observed_server_hello.selected_key_share_group,
        NamedGroup::X25519MLKEM768
    );
    let message = state.server_hello_message.as_ref().expect("sh");
    assert!(message.windows(4).any(|w| w == [0x11, 0xec, 0x04, 0x60]));
}

#[test]
fn certificate_target_length_too_small_returns_diagnostic_error() {
    let mut state = state_with_flight_and_suite(
        flight_with_encrypted_lens(200, 64, 320, 128),
        TLS_AES_128_GCM_SHA256,
    );
    let err = build_encrypted_records_result(&mut state).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("smaller than minimum"));
    assert!(err.to_string().contains("handshake_message_len"));
}

fn assert_wire_application_data_header(record: &[u8], expected_total_len: usize) {
    assert_eq!(record.len(), expected_total_len);
    assert_eq!(record[0], 0x17);
    assert_eq!(record[1], 0x03);
    assert_eq!(record[2], 0x03);
    let declared_payload_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    assert_eq!(declared_payload_len + 5, expected_total_len);
}

#[test]
fn observed_slot_mapping_is_typed() {
    let flight = flight_with_encrypted_lens(10, 20, 30, 40);
    assert_eq!(
        flight.observed_wire_len_for_encrypted_handshake_slot(
            ObservedEncryptedHandshakeSlot::EncryptedExtensions
        ),
        Some(10)
    );
    assert_eq!(
        flight.observed_wire_len_for_encrypted_handshake_slot(
            ObservedEncryptedHandshakeSlot::Certificate
        ),
        Some(20)
    );
    assert_eq!(
        flight.observed_wire_len_for_encrypted_handshake_slot(
            ObservedEncryptedHandshakeSlot::CertificateVerify
        ),
        Some(30)
    );
    assert_eq!(
        flight.observed_wire_len_for_encrypted_handshake_slot(
            ObservedEncryptedHandshakeSlot::Finished
        ),
        Some(40)
    );
}
