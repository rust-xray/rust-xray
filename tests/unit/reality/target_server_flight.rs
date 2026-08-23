use super::*;
use crate::protocol::enums::NamedGroup;
use crate::reality::handshake::{
    extract_observed_server_hello, RealityDestHandshake, TLS13_VERSION,
};
use crate::reality::key_share::{
    NAMED_GROUP_X25519, NAMED_GROUP_X25519MLKEM768, X25519_MLKEM768_SERVER_KEY_SHARE_LEN,
    X25519_PUBLIC_KEY_LEN,
};
use crate::tls::TLS_LEGACY_VERSION_1_2 as TLS_RECORD_LEGACY_VERSION;
use crate::tls::{
    build_change_cipher_spec_record, EXTENSION_KEY_SHARE, EXTENSION_SUPPORTED_VERSIONS,
    TLS_LEGACY_VERSION_1_2, TLS_MAX_RECORD_WIRE_LEN, TLS_RECORD_HEADER_LEN,
};
use std::io::ErrorKind;

const X25519_KEY_EXCHANGE_LEN: usize = X25519_PUBLIC_KEY_LEN;

fn build_server_hello_handshake_message(extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let random = [0x11; 32];
    let mut body = Vec::new();
    body.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
    body.extend_from_slice(&random);
    body.push(0);
    body.extend_from_slice(&0x1301u16.to_be_bytes());
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

fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
    raw.push(content_type);
    raw.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
    raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    raw.extend_from_slice(payload);
    raw
}

fn handshake_record(payload: &[u8]) -> Vec<u8> {
    tls_record(0x16, payload)
}

fn application_data_record(payload: &[u8]) -> Vec<u8> {
    tls_record(0x17, payload)
}

fn complete_target_server_flight_with_sh(server_hello_message: &[u8]) -> Vec<u8> {
    let mut out = handshake_record(server_hello_message);
    out.extend_from_slice(&build_change_cipher_spec_record());
    for payload_len in [80usize, 1200, 260, 64, 48] {
        out.extend_from_slice(&application_data_record(&vec![0xAA; payload_len]));
    }
    out
}

fn feed_all_chunks(chunks: &[&[u8]]) -> std::io::Result<TargetServerFlightFeedOutcome> {
    let mut observer = TargetServerFlightObserver::new();
    let mut last = observer.evaluate_buffered()?;
    for chunk in chunks {
        last = observer.feed(chunk)?;
    }
    Ok(last)
}

fn split_into_single_byte_chunks(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes.iter().map(|byte| vec![*byte]).collect()
}

#[test]
fn complete_server_flight_parses_all_wire_lengths() {
    let bytes = complete_target_server_flight_with_sh(&valid_tls13_x25519_server_hello_message());
    let outcome = feed_all_chunks(&[&bytes]).expect("complete flight");

    assert_eq!(outcome.status, TargetServerFlightFeedStatus::Complete);
    assert_eq!(outcome.complete_record_count, 7);

    let flight = outcome.flight;
    assert_eq!(
        flight.server_hello_wire_len,
        handshake_record(&valid_tls13_x25519_server_hello_message()).len()
    );
    assert_eq!(
        flight.change_cipher_spec,
        Some(ObservedChangeCipherSpec { wire_len: 6 })
    );
    assert_eq!(flight.encrypted_extensions_wire_len, Some(5 + 80));
    assert_eq!(flight.certificate_wire_len, Some(5 + 1200));
    assert_eq!(flight.certificate_verify_wire_len, Some(5 + 260));
    assert_eq!(flight.finished_wire_len, Some(5 + 64));
    assert_eq!(flight.next_encrypted_record_wire_len, Some(5 + 48));
}

#[test]
fn incremental_feed_splits_every_record_across_many_reads() {
    let bytes = complete_target_server_flight_with_sh(&valid_tls13_x25519_server_hello_message());
    let chunks = split_into_single_byte_chunks(&bytes);
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    let outcome = feed_all_chunks(&chunk_refs).expect("byte-split flight");

    assert_eq!(outcome.complete_record_count, 7);
    assert_eq!(outcome.flight.next_encrypted_record_wire_len, Some(5 + 48));
}

#[test]
fn incremental_feed_coalesced_records_in_one_read() {
    let bytes = complete_target_server_flight_with_sh(&valid_tls13_x25519_server_hello_message());
    let outcome = feed_all_chunks(&[&bytes]).expect("complete flight");

    assert_eq!(outcome.complete_record_count, 7);
    assert_eq!(outcome.flight.certificate_wire_len, Some(5 + 1200));
}

#[test]
fn incremental_feed_tls_header_split_across_reads() {
    let bytes = complete_target_server_flight_with_sh(&valid_tls13_x25519_server_hello_message());
    let outcome =
        feed_all_chunks(&[&bytes[..3], &bytes[3..5], &bytes[5..]]).expect("header-split flight");

    assert_eq!(outcome.complete_record_count, 7);
    assert_eq!(
        outcome.flight.server_hello_wire_len,
        handshake_record(&valid_tls13_x25519_server_hello_message()).len()
    );
}

#[test]
fn partial_final_encrypted_record_retained_as_need_more_data() {
    let mut bytes =
        complete_target_server_flight_with_sh(&valid_tls13_x25519_server_hello_message());
    bytes.truncate(bytes.len() - 10);

    let outcome = feed_all_chunks(&[&bytes]).expect("partial final record");
    assert_eq!(outcome.status, TargetServerFlightFeedStatus::NeedMoreData);
    assert!(outcome.has_incomplete_trailing_record);
    assert_eq!(outcome.complete_record_count, 6);
    assert_eq!(outcome.flight.finished_wire_len, Some(5 + 64));
    assert_eq!(outcome.flight.next_encrypted_record_wire_len, None);
}

#[test]
fn malformed_change_cipher_spec_payload_rejected() {
    let mut bytes = handshake_record(&valid_tls13_x25519_server_hello_message());
    bytes.extend_from_slice(&tls_record(0x14, &[0x02]));

    let err = feed_all_chunks(&[&bytes]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("14 03 03 00 01 01"));
}

#[test]
fn wrong_record_type_at_position_one_rejected() {
    let mut bytes = handshake_record(&valid_tls13_x25519_server_hello_message());
    bytes.extend_from_slice(&application_data_record(&[0x01, 0x02, 0x03]));

    let err = feed_all_chunks(&[&bytes]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("position 1"));
}

#[test]
fn wrong_record_type_at_position_two_or_later_rejected() {
    let mut bytes = handshake_record(&valid_tls13_x25519_server_hello_message());
    bytes.extend_from_slice(&build_change_cipher_spec_record());
    bytes.extend_from_slice(&handshake_record(&[0x08, 0x00, 0x00, 0x00, 0x00]));

    let err = feed_all_chunks(&[&bytes]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("position 2"));
}

#[test]
fn invalid_legacy_record_version_rejected() {
    let mut record = handshake_record(&valid_tls13_x25519_server_hello_message());
    record[1] = 0x03;
    record[2] = 0x01;

    let err = feed_all_chunks(&[&record]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("0x0303"));
}

#[test]
fn declared_length_exceeding_available_data_returns_need_more_data() {
    let mut observer = TargetServerFlightObserver::new();
    let partial = [
        0x17, 0x03, 0x03, 0x01, 0x00, // declares 256-byte payload, only 0 present
    ];
    let outcome = observer.feed(&partial).expect("feed should not panic");
    assert_eq!(outcome.status, TargetServerFlightFeedStatus::NeedMoreData);
    assert!(outcome.has_incomplete_trailing_record);
    assert_eq!(outcome.complete_record_count, 0);
}

#[test]
fn over_limit_total_observation_buffer_returns_controlled_error() {
    let mut observer = TargetServerFlightObserver::new();
    let chunk = vec![0u8; DEST_SERVER_FLIGHT_READ_CAP + 1];
    let err = observer.feed(&chunk).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("read cap exceeded"));
}

#[test]
fn tls_record_wire_len_from_header_returns_wire_length() {
    let header = [0x17, 0x03, 0x03, 0x00, 0x10];
    assert_eq!(
        tls_record_wire_len_from_header(&header).expect("valid header"),
        21
    );
}

#[test]
fn target_x25519_server_hello_semantics_still_parsed() {
    let bytes = handshake_record(&valid_tls13_x25519_server_hello_message());
    let outcome = feed_all_chunks(&[&bytes]).expect("complete flight");
    let dest = RealityDestHandshake::try_from_records(bytes.clone(), {
        let (records, _) = crate::tls::parse_complete_tls_records_prefix(&bytes).unwrap();
        records
    })
    .expect("dest handshake");

    let observed = extract_observed_server_hello(&dest).expect("observed ServerHello");
    assert_eq!(observed.selected_key_share_group, NamedGroup::X25519);
    assert_eq!(outcome.flight.server_hello_wire_len, bytes.len());
}

#[test]
fn target_x25519mlkem768_server_hello_semantics_still_parsed() {
    let message = valid_tls13_x25519mlkem768_server_hello_message();
    let bytes = handshake_record(&message);
    let outcome = feed_all_chunks(&[&bytes]).expect("complete flight");
    let dest = RealityDestHandshake::try_from_records(bytes.clone(), {
        let (records, _) = crate::tls::parse_complete_tls_records_prefix(&bytes).unwrap();
        records
    })
    .expect("dest handshake");

    let observed = extract_observed_server_hello(&dest).expect("observed hybrid ServerHello");
    assert_eq!(
        observed.selected_key_share_group,
        NamedGroup::X25519MLKEM768
    );
    assert_eq!(outcome.flight.server_hello_wire_len, bytes.len());
}

#[test]
fn partial_profile_server_hello_and_encrypted_extension_only() {
    let mut bytes = handshake_record(&valid_tls13_x25519_server_hello_message());
    bytes.extend_from_slice(&build_change_cipher_spec_record());
    bytes.extend_from_slice(&application_data_record(&[0xBB; 32]));

    let outcome = feed_all_chunks(&[&bytes]).expect("complete flight");
    assert_eq!(outcome.complete_record_count, 3);
    assert_eq!(outcome.flight.encrypted_extensions_wire_len, Some(5 + 32));
    assert_eq!(outcome.flight.certificate_wire_len, None);
}
