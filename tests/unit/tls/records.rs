use super::*;

#[test]
fn build_handshake_record_encodes_record() {
    let payload = [0x02, 0x00, 0x00, 0x01, 0x00];
    let record = build_handshake_record(&payload).unwrap();

    assert_eq!(
        record,
        vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00]
    );
}

#[test]
fn build_application_data_record_encodes_record() {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let record = build_application_data_record(&payload).unwrap();

    assert_eq!(
        record,
        vec![0x17, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn build_tls_record_rejects_payload_too_long() {
    let payload = vec![0u8; u16::MAX as usize + 1];
    let err = build_tls_record(TLS_RECORD_HANDSHAKE, TLS_LEGACY_VERSION_1_2, &payload).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("payload too long"));
}

#[test]
fn build_change_cipher_spec_record_is_exact_bytes() {
    let record = build_change_cipher_spec_record();
    assert_eq!(record, vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
}

#[test]
fn build_tls_record_roundtrips_with_parse_tls_records() {
    let payload = [0x02, 0x00, 0x00, 0x01, 0x00];
    let record = build_handshake_record(&payload).unwrap();
    let records = parse_tls_records(&record).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].content_type, TlsRecordContentType::Handshake);
    assert_eq!(records[0].legacy_version, TLS_LEGACY_VERSION_1_2);
    assert_eq!(records[0].payload, payload);
    assert_eq!(records[0].raw, record);
}

#[test]
fn parse_tls_records_one_handshake_record() {
    let input = build_handshake_record(&[0x02, 0x00, 0x00, 0x01, 0x00]).unwrap();
    let records = parse_tls_records(&input).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].content_type, TlsRecordContentType::Handshake);
    assert_eq!(records[0].legacy_version, [0x03, 0x03]);
    assert_eq!(records[0].payload, vec![0x02, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(records[0].raw, input);
}

#[test]
fn parse_tls_records_change_cipher_spec_record() {
    let input = build_change_cipher_spec_record();
    let records = parse_tls_records(&input).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].content_type,
        TlsRecordContentType::ChangeCipherSpec
    );
    assert_eq!(records[0].payload, vec![0x01]);
}

#[test]
fn parse_tls_records_application_data_record() {
    let input = build_application_data_record(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
    let records = parse_tls_records(&input).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(records[0].payload, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn parse_tls_records_multiple_records() {
    let first = build_handshake_record(&[0x02, 0x00, 0x00, 0x01, 0x00]).unwrap();
    let second = build_change_cipher_spec_record();
    let mut input = first;
    input.extend_from_slice(&second);

    let records = parse_tls_records(&input).unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].content_type, TlsRecordContentType::Handshake);
    assert_eq!(
        records[1].content_type,
        TlsRecordContentType::ChangeCipherSpec
    );
}

#[test]
fn parse_tls_records_incomplete_record_is_unexpected_eof() {
    let mut input = build_handshake_record(&[0x02, 0x00, 0x00, 0x01, 0x00]).unwrap();
    input.truncate(7);

    let err = parse_tls_records(&input).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn parse_complete_tls_records_prefix_returns_complete_records_and_consumed() {
    let first = build_handshake_record(&[0x02, 0x00, 0x00, 0x01, 0x00]).unwrap();
    let second = build_application_data_record(&[0xaa, 0xbb]).unwrap();
    let mut input = first.clone();
    input.extend_from_slice(&second);
    input.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x10]); // incomplete third header+partial payload

    let (records, consumed) = parse_complete_tls_records_prefix(&input).unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].content_type, TlsRecordContentType::Handshake);
    assert_eq!(
        records[1].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(consumed, first.len() + second.len());
    assert_eq!(&input[consumed..], &[0x16, 0x03, 0x03, 0x00, 0x10]);
}

#[test]
fn parse_complete_tls_records_prefix_first_header_incomplete_returns_empty() {
    let input = [0x16, 0x03, 0x03];
    let (records, consumed) = parse_complete_tls_records_prefix(&input).unwrap();

    assert!(records.is_empty());
    assert_eq!(consumed, 0);
}

#[test]
fn parse_tls_records_unknown_content_type() {
    let input = build_tls_record(0x99, TLS_LEGACY_VERSION_1_2, &[0x01, 0x02]).unwrap();
    let records = parse_tls_records(&input).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].content_type, TlsRecordContentType::Unknown(0x99));
}
