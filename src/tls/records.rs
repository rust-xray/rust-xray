use std::io::{Error, ErrorKind};

const RECORD_HEADER_LEN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRecordContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    pub content_type: TlsRecordContentType,
    pub legacy_version: [u8; 2],
    pub payload: Vec<u8>,
    pub raw: Vec<u8>,
}

fn parse_content_type(byte: u8) -> TlsRecordContentType {
    match byte {
        20 => TlsRecordContentType::ChangeCipherSpec,
        21 => TlsRecordContentType::Alert,
        22 => TlsRecordContentType::Handshake,
        23 => TlsRecordContentType::ApplicationData,
        other => TlsRecordContentType::Unknown(other),
    }
}

fn unexpected_eof(message: &str) -> Error {
    Error::new(ErrorKind::UnexpectedEof, message)
}

fn parse_tls_record_at(input: &[u8], offset: usize) -> std::io::Result<(TlsRecord, usize)> {
    let header = input
        .get(offset..offset + RECORD_HEADER_LEN)
        .ok_or_else(|| unexpected_eof("TLS record header incomplete"))?;

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let record_end = offset
        .checked_add(RECORD_HEADER_LEN)
        .and_then(|start| start.checked_add(record_len))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "TLS record length overflow"))?;

    let raw = input
        .get(offset..record_end)
        .ok_or_else(|| unexpected_eof("TLS record payload incomplete"))?
        .to_vec();

    Ok((
        TlsRecord {
            content_type: parse_content_type(header[0]),
            legacy_version: [header[1], header[2]],
            payload: raw[RECORD_HEADER_LEN..].to_vec(),
            raw,
        },
        record_end - offset,
    ))
}

pub fn parse_tls_records(input: &[u8]) -> std::io::Result<Vec<TlsRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset < input.len() {
        let (record, consumed) = parse_tls_record_at(input, offset)?;
        records.push(record);
        offset += consumed;
    }

    Ok(records)
}

pub fn parse_complete_tls_records_prefix(input: &[u8]) -> std::io::Result<(Vec<TlsRecord>, usize)> {
    if input.len() < RECORD_HEADER_LEN {
        return Ok((Vec::new(), 0));
    }

    let mut records = Vec::new();
    let mut offset = 0;

    while offset + RECORD_HEADER_LEN <= input.len() {
        let header = &input[offset..offset + RECORD_HEADER_LEN];
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let record_total_len = RECORD_HEADER_LEN + record_len;

        if offset + record_total_len > input.len() {
            break;
        }

        let (record, consumed) = parse_tls_record_at(input, offset)?;
        records.push(record);
        offset += consumed;
    }

    Ok((records, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
        record.push(content_type);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn parse_tls_records_one_handshake_record() {
        let input = build_tls_record(0x16, &[0x02, 0x00, 0x00, 0x01, 0x00]);
        let records = parse_tls_records(&input).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, TlsRecordContentType::Handshake);
        assert_eq!(records[0].legacy_version, [0x03, 0x03]);
        assert_eq!(records[0].payload, vec![0x02, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(records[0].raw, input);
    }

    #[test]
    fn parse_tls_records_change_cipher_spec_record() {
        let input = build_tls_record(0x14, &[0x01]);
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
        let input = build_tls_record(0x17, &[0xde, 0xad, 0xbe, 0xef]);
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
        let first = build_tls_record(0x16, &[0x02, 0x00, 0x00, 0x01, 0x00]);
        let second = build_tls_record(0x14, &[0x01]);
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
        let mut input = build_tls_record(0x16, &[0x02, 0x00, 0x00, 0x01, 0x00]);
        input.truncate(7);

        let err = parse_tls_records(&input).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn parse_complete_tls_records_prefix_returns_complete_records_and_consumed() {
        let first = build_tls_record(0x16, &[0x02, 0x00, 0x00, 0x01, 0x00]);
        let second = build_tls_record(0x17, &[0xaa, 0xbb]);
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
        let input = build_tls_record(0x99, &[0x01, 0x02]);
        let records = parse_tls_records(&input).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, TlsRecordContentType::Unknown(0x99));
    }
}
