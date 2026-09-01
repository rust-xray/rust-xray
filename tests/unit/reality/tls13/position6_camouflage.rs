use super::*;
use crate::protocol::structs::SessionId;
use crate::reality::target_server_flight::ObservedTargetTls13ServerFlight;
use crate::reality::tls13::key_schedule::derive_application_traffic_secrets;
use crate::reality::tls13::record_crypto::{
    minimum_tls13_encrypted_application_record_wire_len, parse_tls13_application_inner_plaintext,
    tls13_inner_plaintext_metadata, Tls13RecordDecryptor, Tls13RecordEncryptor,
};
use crate::reality::tls13::state::assemble_server_handshake_flight_out;
use crate::reality::tls13::{derive_traffic_key, TLS_AES_128_GCM_SHA256};
use crate::reality::RealityCertificatePatchMode;
use crate::tls::records::{
    build_handshake_record, parse_tls_records, TlsRecordContentType, TLS_LEGACY_VERSION_1_2,
    TLS_RECORD_APPLICATION_DATA,
};

pub(super) fn flight_with_encrypted_lens(
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

pub(super) fn flight_with_position6(
    ee: usize,
    cert: usize,
    cert_verify: usize,
    finished: usize,
    position6: usize,
) -> ObservedTargetTls13ServerFlight {
    ObservedTargetTls13ServerFlight {
        encrypted_extensions_wire_len: Some(ee),
        certificate_wire_len: Some(cert),
        certificate_verify_wire_len: Some(cert_verify),
        finished_wire_len: Some(finished),
        next_encrypted_record_wire_len: Some(position6),
        ..ObservedTargetTls13ServerFlight::default()
    }
}

fn state_with_flight(flight: ObservedTargetTls13ServerFlight) -> RealityTls13ServerState {
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
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

fn server_application_traffic_secret_at_server_finished(
    state: &RealityTls13ServerState,
) -> Vec<u8> {
    let handshake_secret = state
        .handshake_secrets
        .as_ref()
        .expect("handshake secrets")
        .handshake_secret
        .clone();
    let transcript_hash = state.transcript.digest();
    derive_application_traffic_secrets(state.suite, &handshake_secret, &transcript_hash)
        .expect("application traffic secrets")
        .server_application_traffic_secret
}

#[test]
fn observed_position6_absent_emits_no_extra_record() {
    let mut state = state_with_flight(flight_with_encrypted_lens(200, 900, 320, 128));
    let server_hello_record =
        build_handshake_record(state.server_hello_message.as_ref().expect("sh")).expect("record");
    let encrypted = build_encrypted_records(&mut state);
    let flight = assemble_server_handshake_flight_out(&server_hello_record, &encrypted);
    let parsed = parse_tls_records(&flight).expect("parsable flight");

    assert_eq!(parsed.len(), 6);
    assert_eq!(state.server_application_write_sequence, 0);
}

#[test]
fn observed_position6_length_emits_exactly_one_extra_record() {
    let target_len = 180;
    let mut state = state_with_flight(flight_with_position6(200, 900, 320, 128, target_len));
    let server_hello_record =
        build_handshake_record(state.server_hello_message.as_ref().expect("sh")).expect("record");
    let encrypted = build_encrypted_records(&mut state);
    let flight = assemble_server_handshake_flight_out(&server_hello_record, &encrypted);
    let parsed = parse_tls_records(&flight).expect("parsable flight");

    assert_eq!(parsed.len(), 7);
    assert_eq!(parsed[6].raw.len(), target_len);
    assert_eq!(
        parsed[6].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(parsed[6].legacy_version, TLS_LEGACY_VERSION_1_2);
}

#[test]
fn position6_is_encrypted_with_server_application_traffic_secret_after_server_finished() {
    let target_len = 180;
    let mut state = state_with_flight(flight_with_position6(200, 900, 320, 128, target_len));
    let records = parse_tls_records(&build_encrypted_records(&mut state)).expect("records");
    let position6 = records.last().expect("position-6 record").clone();

    let server_secret = server_application_traffic_secret_at_server_finished(&state);
    let server_keys = derive_traffic_key(state.suite, &server_secret).expect("server keys");
    let mut server_decryptor =
        Tls13RecordDecryptor::new(state.suite, server_keys.clone()).expect("decryptor");
    let inner = server_decryptor
        .decrypt_record_payload(&position6)
        .expect("server app secret decrypt");
    let plaintext =
        parse_tls13_application_inner_plaintext(&inner).expect("application inner plaintext");
    assert!(plaintext.is_empty());

    let handshake_secret = state
        .handshake_secrets
        .as_ref()
        .expect("handshake secrets")
        .server_handshake_traffic_secret
        .clone();
    let handshake_keys = derive_traffic_key(state.suite, &handshake_secret).expect("hs keys");
    let mut handshake_decryptor =
        Tls13RecordDecryptor::new(state.suite, handshake_keys).expect("decryptor");
    assert!(handshake_decryptor
        .decrypt_record_payload(&position6)
        .is_err());
}

#[test]
fn position6_dummy_plaintext_is_empty_application_data_with_zero_padding() {
    let target_len = 180;
    let mut state = state_with_flight(flight_with_position6(200, 900, 320, 128, target_len));
    let records = parse_tls_records(&build_encrypted_records(&mut state)).expect("records");
    let position6 = records.last().expect("position-6 record").clone();

    let suite = state.suite;
    let min_wire = minimum_tls13_encrypted_application_record_wire_len(suite, 0).expect("min wire");
    assert_eq!(target_len, position6.raw.len());

    let server_secret = server_application_traffic_secret_at_server_finished(&state);
    let server_keys = derive_traffic_key(suite, &server_secret).expect("server keys");
    let mut decryptor = Tls13RecordDecryptor::new(suite, server_keys).expect("decryptor");
    let inner = decryptor
        .decrypt_record_payload(&position6)
        .expect("decrypted inner");
    let (body, content_type, padding_len) =
        tls13_inner_plaintext_metadata(&inner).expect("inner metadata");
    assert!(body.is_empty());
    assert_eq!(content_type, TLS_RECORD_APPLICATION_DATA);
    assert_eq!(padding_len, target_len - min_wire);
}

#[test]
fn position6_does_not_alter_handshake_transcript() {
    let state = state_with_handshake_secrets();
    let digest_before = state.transcript.digest();

    let server_secret = server_application_traffic_secret_at_server_finished(&state);
    let server_keys = derive_traffic_key(state.suite, &server_secret).expect("server keys");
    let mut encryptor = Tls13RecordEncryptor::new(state.suite, server_keys).expect("encryptor");
    encryptor
        .encrypt_camouflage_position6_record_with_desired_wire_len(180)
        .expect("camouflage record");

    assert_eq!(state.transcript.digest(), digest_before);
}

#[test]
fn position6_consumes_one_server_application_write_sequence_number() {
    let mut state = state_with_flight(flight_with_position6(200, 900, 320, 128, 180));
    build_encrypted_records(&mut state);
    assert_eq!(state.server_application_write_sequence, 1);
}

#[test]
fn application_data_after_position6_decrypts_at_sequence_one() {
    let mut state = state_with_flight(flight_with_position6(200, 900, 320, 128, 180));
    build_encrypted_records(&mut state);

    let server_secret = server_application_traffic_secret_at_server_finished(&state);
    let server_keys = derive_traffic_key(state.suite, &server_secret).expect("server keys");
    let mut encryptor = Tls13RecordEncryptor::new(state.suite, server_keys.clone()).expect("enc");
    encryptor.sequence = state.server_application_write_sequence;
    let payload = b"post-handshake-app";
    let record = encryptor
        .encrypt_application_data(payload)
        .expect("application record");

    let mut decryptor = Tls13RecordDecryptor::new(state.suite, server_keys).expect("dec");
    decryptor.sequence = 1;
    let parsed = parse_tls_records(&record).expect("record")[0].clone();
    let decrypted = decryptor
        .decrypt_application_data_record(&parsed)
        .expect("application decrypt");
    assert_eq!(decrypted, payload);
}

#[test]
fn position6_target_length_too_small_returns_controlled_error() {
    let mut state = state_with_flight(flight_with_position6(200, 900, 320, 128, 8));
    let err = build_encrypted_records_result(&mut state).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("smaller than minimum"));
}

#[test]
fn x25519_path_position6_record_shape_emission() {
    let mut state = state_with_flight(flight_with_position6(200, 900, 320, 128, 176));
    build_encrypted_records(&mut state);
    assert_eq!(
        state.observed_server_hello.selected_key_share_group,
        NamedGroup::X25519
    );
    assert_eq!(state.server_application_write_sequence, 1);
}

#[test]
fn hybrid_x25519mlkem768_path_position6_record_shape_emission() {
    let (client_hybrid, _, _) = build_valid_client_hybrid_share();
    let observed = valid_observed_hybrid_server_hello(TLS_AES_128_GCM_SHA256, &[0xA5; 1120]);
    let flight = flight_with_position6(200, 900, 320, 128, 176);
    let mut state =
        RealityTls13ServerState::new(sample_accepted(), observed, flight).expect("valid state");
    state
        .prepare_server_hello(&client_hello_with_hybrid_keyshare(client_hybrid))
        .expect("hybrid ServerHello");
    let transcript_hash = state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("transcript");
    state
        .derive_handshake_secrets(&transcript_hash)
        .expect("handshake secrets");
    build_encrypted_records(&mut state);
    assert_eq!(
        state.observed_server_hello.selected_key_share_group,
        NamedGroup::X25519MLKEM768
    );
    assert_eq!(state.server_application_write_sequence, 1);
}
