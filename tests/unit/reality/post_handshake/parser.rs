use crate::reality::{parse_post_handshake_application_record_lengths, PostHandshakeParseError};

const TLS13_MAX_ENCRYPTED_RECORD_PAYLOAD_LEN: usize = 16_384 + 256;

fn app_record(payload_len: usize) -> Vec<u8> {
    assert!(payload_len <= u16::MAX as usize);
    let mut record = vec![0x17, 0x03, 0x03];
    record.extend_from_slice(&(payload_len as u16).to_be_bytes());
    record.extend(vec![0xAA; payload_len]);
    record
}

#[test]
fn parses_one_application_record() {
    let bytes = app_record(16);
    let lengths = parse_post_handshake_application_record_lengths(&bytes).expect("parse");
    assert_eq!(lengths, vec![bytes.len()]);
}

#[test]
fn parses_multiple_consecutive_records() {
    let first = app_record(8);
    let second = app_record(32);
    let third = app_record(4);
    let mut bytes = first.clone();
    bytes.extend_from_slice(&second);
    bytes.extend_from_slice(&third);

    let lengths = parse_post_handshake_application_record_lengths(&bytes).expect("parse");
    assert_eq!(lengths, vec![first.len(), second.len(), third.len()]);
}

#[test]
fn returns_full_wire_lengths() {
    let bytes = app_record(100);
    let lengths = parse_post_handshake_application_record_lengths(&bytes).expect("parse");
    assert_eq!(lengths, vec![105]);
}

#[test]
fn rejects_truncated_header() {
    let err = parse_post_handshake_application_record_lengths(&[0x17, 0x03]).unwrap_err();
    assert_eq!(
        err,
        PostHandshakeParseError::TruncatedHeader {
            offset: 0,
            available: 2,
        }
    );
}

#[test]
fn rejects_truncated_payload() {
    let mut bytes = app_record(20);
    bytes.truncate(10);
    let err = parse_post_handshake_application_record_lengths(&bytes).unwrap_err();
    assert!(matches!(
        err,
        PostHandshakeParseError::TruncatedPayload {
            offset: 0,
            declared_payload_len: 20,
            available_payload_len: 5,
        }
    ));
}

#[test]
fn rejects_wrong_content_type_at_start() {
    let mut bytes = app_record(4);
    bytes[0] = 0x16;
    let err = parse_post_handshake_application_record_lengths(&bytes).unwrap_err();
    assert_eq!(
        err,
        PostHandshakeParseError::WrongContentType {
            offset: 0,
            found: 0x16,
        }
    );
}

#[test]
fn rejects_wrong_record_version_at_start() {
    let mut bytes = app_record(4);
    bytes[1] = 0x03;
    bytes[2] = 0x01;
    let err = parse_post_handshake_application_record_lengths(&bytes).unwrap_err();
    assert_eq!(
        err,
        PostHandshakeParseError::WrongLegacyVersion {
            offset: 0,
            found: [0x03, 0x01],
        }
    );
}

#[test]
fn rejects_oversized_declared_length() {
    let payload_len = TLS13_MAX_ENCRYPTED_RECORD_PAYLOAD_LEN + 1;
    let mut record = vec![0x17, 0x03, 0x03];
    record.extend_from_slice(&(payload_len as u16).to_be_bytes());
    let err = parse_post_handshake_application_record_lengths(&record).unwrap_err();
    assert!(matches!(
        err,
        PostHandshakeParseError::DeclaredLengthExceedsMaximum { offset: 0, .. }
    ));
}

#[test]
fn truncated_payload_after_complete_prefix_is_error() {
    let complete = app_record(8);
    let mut bytes = complete.clone();
    bytes.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x10, 0x01]);

    let err = parse_post_handshake_application_record_lengths(&bytes).unwrap_err();
    assert_eq!(
        err,
        PostHandshakeParseError::TruncatedPayload {
            offset: complete.len(),
            declared_payload_len: 16,
            available_payload_len: 1,
        }
    );
}

#[test]
fn trailing_incomplete_header_after_complete_prefix_is_error() {
    let complete = app_record(8);
    let mut bytes = complete.clone();
    bytes.extend_from_slice(&[0x17, 0x03, 0x03]);

    let err = parse_post_handshake_application_record_lengths(&bytes).unwrap_err();
    assert_eq!(
        err,
        PostHandshakeParseError::TrailingIncompleteRecord {
            parsed_lengths: vec![complete.len()],
            trailing_len: 3,
        }
    );
}

#[test]
fn empty_input_yields_empty_success() {
    let lengths = parse_post_handshake_application_record_lengths(&[]).expect("parse");
    assert!(lengths.is_empty());
}

#[test]
fn non_application_record_after_complete_prefix_is_trailing_error() {
    let complete = app_record(8);
    let mut bytes = complete.clone();
    bytes.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]);

    let err = parse_post_handshake_application_record_lengths(&bytes).unwrap_err();
    assert_eq!(
        err,
        PostHandshakeParseError::TrailingIncompleteRecord {
            parsed_lengths: vec![complete.len()],
            trailing_len: 9,
        }
    );
}
