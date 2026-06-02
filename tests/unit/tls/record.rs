use super::*;

fn build_client_hello_record(payload: &[u8]) -> Vec<u8> {
    let handshake_len = payload.len();
    assert!(handshake_len <= 0xff_ffff);

    let body_len = HANDSHAKE_HEADER_LEN + handshake_len;
    let mut body = Vec::with_capacity(body_len);
    body.push(TLS_HANDSHAKE_CLIENT_HELLO);
    body.extend_from_slice(&(handshake_len as u32).to_be_bytes()[1..]);
    body.extend_from_slice(payload);

    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + body.len());
    record.push(TLS_CONTENT_TYPE_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

fn split_record(record: &[u8], first_body_bytes: usize) -> (Vec<u8>, Vec<u8>) {
    assert!(record.len() > RECORD_HEADER_LEN + first_body_bytes);
    let first_body_len = first_body_bytes;
    let mut first = Vec::with_capacity(RECORD_HEADER_LEN + first_body_len);
    first.push(record[0]);
    first.extend_from_slice(&record[1..3]);
    first.extend_from_slice(&(first_body_len as u16).to_be_bytes());
    first.extend_from_slice(&record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + first_body_len]);

    let mut second = Vec::new();
    second.push(record[0]);
    second.extend_from_slice(&record[1..3]);
    let remaining = record.len() - RECORD_HEADER_LEN - first_body_len;
    second.extend_from_slice(&(remaining as u16).to_be_bytes());
    second.extend_from_slice(&record[RECORD_HEADER_LEN + first_body_len..]);
    (first, second)
}

#[test]
fn parse_valid_minimal_client_hello_record() {
    let input = build_client_hello_record(&[0xaa, 0xbb, 0xcc]);
    let record = parse_client_hello_record_bytes(&input).expect("valid record");

    assert_eq!(record.initial_client_bytes(), input.as_slice());
    assert_eq!(record.raw_record, input);
    assert!(record.trailing_bytes.is_empty());
    assert_eq!(record.handshake_payload, vec![0xaa, 0xbb, 0xcc]);
}

#[test]
fn parse_rejects_non_handshake_content_type() {
    let mut input = build_client_hello_record(&[0x01]);
    input[0] = 0x17;

    let err = parse_client_hello_record_bytes(&input).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn parse_rejects_non_client_hello_handshake_type() {
    let payload = [0xde, 0xad];
    let mut input = build_client_hello_record(&payload);
    input[RECORD_HEADER_LEN] = 0x02;

    let err = parse_client_hello_record_bytes(&input).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn parse_needs_more_data_for_incomplete_client_hello_in_single_record() {
    let mut input = build_client_hello_record(&[0x01, 0x02, 0x03]);
    input[RECORD_HEADER_LEN + 1] = 0x00;
    input[RECORD_HEADER_LEN + 2] = 0x01;
    input[RECORD_HEADER_LEN + 3] = 0x00;

    let err = parse_client_hello_record_bytes(&input).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn parse_accepts_coalesced_trailing_bytes_after_client_hello_in_record_body() {
    let mut input = build_client_hello_record(&[0x01, 0x02]);
    input.push(0x02);
    input.push(0x00);
    input.push(0x00);
    input.push(0x01);
    input.push(0x00);
    let body_len = input.len() - RECORD_HEADER_LEN;
    input[3..5].copy_from_slice(&(body_len as u16).to_be_bytes());

    let record = parse_client_hello_record_bytes(&input).expect("valid record");
    assert_eq!(record.handshake_payload, vec![0x01, 0x02]);
    assert_eq!(record.trailing_bytes, vec![0x02, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(record.initial_client_bytes(), input.as_slice());
    assert_eq!(
        record.raw_record.len(),
        RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + 2
    );
}

#[test]
fn parse_accepts_trailing_bytes_after_complete_tls_record() {
    let mut input = build_client_hello_record(&[0x01, 0x02]);
    input.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x00]);

    let record = parse_client_hello_record_bytes(&input).expect("valid record");
    assert_eq!(
        record.trailing_bytes,
        vec![0x16, 0x03, 0x03, 0x00, 0x01, 0x00]
    );
    assert_eq!(record.initial_client_bytes(), input.as_slice());
}

#[test]
fn parse_client_hello_across_two_tls_records() {
    let payload = vec![0x55; 120];
    let full = build_client_hello_record(&payload);
    let (first, second) = split_record(&full, 40);
    let mut input = first;
    input.extend_from_slice(&second);

    let record = parse_client_hello_record_bytes(&input).expect("valid record");
    assert_eq!(record.handshake_payload, payload);
    assert_eq!(record.initial_client_bytes(), input.as_slice());
    assert_eq!(record.raw_record, input);
    assert!(record.trailing_bytes.is_empty());
}

#[test]
fn parse_client_hello_across_two_records_with_trailing_bytes() {
    let payload = vec![0x77; 80];
    let full = build_client_hello_record(&payload);
    let (first, second) = split_record(&full, 30);
    let mut input = first;
    input.extend_from_slice(&second);
    input.extend_from_slice(b"coalesced-tail");

    let record = parse_client_hello_record_bytes(&input).expect("valid record");
    assert_eq!(record.trailing_bytes, b"coalesced-tail");
    assert_eq!(record.initial_client_bytes(), input.as_slice());
}

#[test]
fn initial_client_bytes_matches_fallback_expectation() {
    let input = build_client_hello_record(&[0x10, 0x20]);
    let record = parse_client_hello_record_bytes(&input).expect("valid record");
    assert_eq!(record.initial_client_bytes(), input.as_slice());
}
