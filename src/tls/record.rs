use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;

pub(crate) const ERR_FRAGMENTED_CLIENT_HELLO: &str = "fragmented ClientHello is not supported yet";
pub(crate) const ERR_MULTIPLE_HANDSHAKE_MESSAGES: &str =
    "multiple handshake messages in first TLS record are not supported yet";

/// Parsed first TLS record containing a single ClientHello handshake message.
///
/// # Current limitations
///
/// - Accepts **exactly one** TLS record containing **exactly one** ClientHello.
/// - A ClientHello split across multiple TLS records is rejected (`InvalidData`).
/// - Extra handshake messages after ClientHello in the same record are rejected
///   (`InvalidData`).
/// - Trailing bytes after the first TLS record are rejected (`InvalidData`).
///
/// # Fallback relay
///
/// When inspection falls back, callers must relay `raw_record` (TLS record header +
/// body) so bytes already read from the client are preserved.
///
/// # Future work
///
/// - Buffer multiple TLS records until a complete ClientHello is available.
/// - Support fragmented ClientHello across records without changing fallback
///   byte preservation semantics.
#[derive(Debug, PartialEq, Eq)]
pub struct TlsClientHelloRecord {
    /// Full first TLS record: 5-byte record header + record body.
    pub raw_record: Vec<u8>,
    /// ClientHello handshake message: 4-byte handshake header + ClientHello payload.
    pub handshake_message: Vec<u8>,
    /// ClientHello payload only (no handshake header); used for TLS struct parsing.
    pub handshake_payload: Vec<u8>,
}

/// Parses a single in-memory TLS record buffer into a ClientHello view.
///
/// See [`TlsClientHelloRecord`] for supported input shape and rejection rules.
pub fn parse_client_hello_record_bytes(input: &[u8]) -> std::io::Result<TlsClientHelloRecord> {
    // TODO: read and buffer multiple TLS records until ClientHello is complete.
    // TODO: support ClientHello fragmented across TLS records.
    // TODO: support multiple handshake messages in one TLS record (unlikely for ClientHello path).
    if input.len() < RECORD_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "TLS record header incomplete",
        ));
    }

    let header = &input[..RECORD_HEADER_LEN];

    if header[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "expected TLS handshake record (content_type=0x16), got 0x{:02x}",
                header[0]
            ),
        ));
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let record_end = RECORD_HEADER_LEN.checked_add(record_len).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record length overflow",
        )
    })?;

    if input.len() < record_end {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "TLS record incomplete: expected {} bytes, got {}",
                record_end,
                input.len()
            ),
        ));
    }

    if input.len() > record_end {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "TLS record has trailing data: expected {} bytes, got {}",
                record_end,
                input.len()
            ),
        ));
    }

    let body = &input[RECORD_HEADER_LEN..record_end];
    parse_client_hello_body(header, body)
}

fn parse_client_hello_body(header: &[u8], body: &[u8]) -> std::io::Result<TlsClientHelloRecord> {
    if body.len() < HANDSHAKE_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "TLS record body too short for handshake header: {} bytes",
                body.len()
            ),
        ));
    }

    if body[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "expected ClientHello handshake (type=0x01), got 0x{:02x}",
                body[0]
            ),
        ));
    }

    let handshake_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    let handshake_end = HANDSHAKE_HEADER_LEN
        .checked_add(handshake_len)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ClientHello handshake length overflow",
            )
        })?;

    if handshake_end > body.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{ERR_FRAGMENTED_CLIENT_HELLO}: need {} bytes, have {}",
                handshake_end,
                body.len()
            ),
        ));
    }

    if handshake_end < body.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{ERR_MULTIPLE_HANDSHAKE_MESSAGES}: handshake is {} bytes, record body is {} bytes",
                handshake_end,
                body.len()
            ),
        ));
    }

    let mut raw_record = Vec::with_capacity(header.len() + body.len());
    raw_record.extend_from_slice(header);
    raw_record.extend_from_slice(body);

    let handshake_message = body[..handshake_end].to_vec();
    let handshake_payload = body[HANDSHAKE_HEADER_LEN..handshake_end].to_vec();

    Ok(TlsClientHelloRecord {
        raw_record,
        handshake_message,
        handshake_payload,
    })
}

pub async fn read_client_hello_record(
    stream: &mut TcpStream,
) -> std::io::Result<TlsClientHelloRecord> {
    // TODO: loop over TLS records until a complete ClientHello is buffered.
    let mut header = [0u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut header).await?;

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; record_len];
    stream.read_exact(&mut body).await?;

    let mut record_bytes = Vec::with_capacity(RECORD_HEADER_LEN + body.len());
    record_bytes.extend_from_slice(&header);
    record_bytes.extend_from_slice(&body);

    parse_client_hello_record_bytes(&record_bytes)
}

#[cfg(test)]
mod tests {
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
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version (ignored by parser)
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn parse_valid_minimal_client_hello_record() {
        let input = build_client_hello_record(&[0xaa, 0xbb, 0xcc]);
        let record = parse_client_hello_record_bytes(&input).expect("valid record");

        assert_eq!(record.raw_record, input);
        assert_eq!(
            record.raw_record.len(),
            RECORD_HEADER_LEN + record.handshake_message.len()
        );
        assert_eq!(record.raw_record[0], TLS_CONTENT_TYPE_HANDSHAKE);
        assert_eq!(record.handshake_message[0], TLS_HANDSHAKE_CLIENT_HELLO);
        assert_eq!(record.handshake_message.len(), HANDSHAKE_HEADER_LEN + 3);
        assert_eq!(
            record.handshake_message.len(),
            HANDSHAKE_HEADER_LEN + record.handshake_payload.len()
        );
        assert_eq!(record.handshake_payload, vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(
            &record.handshake_message[HANDSHAKE_HEADER_LEN..],
            record.handshake_payload.as_slice()
        );
    }

    #[test]
    fn parse_rejects_non_handshake_content_type() {
        let mut input = build_client_hello_record(&[0x01]);
        input[0] = 0x17;

        let err = parse_client_hello_record_bytes(&input).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("content_type=0x16"));
    }

    #[test]
    fn parse_rejects_body_shorter_than_handshake_header() {
        let mut input = Vec::new();
        input.push(TLS_CONTENT_TYPE_HANDSHAKE);
        input.extend_from_slice(&[0x03, 0x01]);
        input.extend_from_slice(&2u16.to_be_bytes()); // body length = 2
        input.extend_from_slice(&[0x01, 0x00]); // only 2 bytes, need 4

        let err = parse_client_hello_record_bytes(&input).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too short for handshake header"));
    }

    #[test]
    fn parse_rejects_non_client_hello_handshake_type() {
        let payload = [0xde, 0xad];
        let mut input = build_client_hello_record(&payload);
        input[RECORD_HEADER_LEN] = 0x02; // ServerHello

        let err = parse_client_hello_record_bytes(&input).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("ClientHello handshake"));
    }

    #[test]
    fn parse_rejects_handshake_len_larger_than_body() {
        let mut input = build_client_hello_record(&[0x01, 0x02]);
        // Claim handshake payload is 100 bytes while body only contains 2.
        input[RECORD_HEADER_LEN + 1] = 0x00;
        input[RECORD_HEADER_LEN + 2] = 0x00;
        input[RECORD_HEADER_LEN + 3] = 0x64;

        let err = parse_client_hello_record_bytes(&input).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(ERR_FRAGMENTED_CLIENT_HELLO));
    }

    #[test]
    fn parse_rejects_incomplete_client_hello_in_single_record_as_invalid_data() {
        let mut input = build_client_hello_record(&[0x01, 0x02, 0x03]);
        input[RECORD_HEADER_LEN + 1] = 0x00;
        input[RECORD_HEADER_LEN + 2] = 0x01;
        input[RECORD_HEADER_LEN + 3] = 0x00;

        let err = parse_client_hello_record_bytes(&input).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(ERR_FRAGMENTED_CLIENT_HELLO));
    }

    #[test]
    fn parse_rejects_extra_bytes_after_client_hello_in_record_body() {
        let mut input = build_client_hello_record(&[0x01, 0x02]);
        // Append extra handshake bytes after a valid ClientHello.
        input.push(0x02); // ServerHello type
        input.push(0x00);
        input.push(0x00);
        input.push(0x01);
        input.push(0x00);
        // Update record length in header to include trailing bytes.
        let body_len = input.len() - RECORD_HEADER_LEN;
        input[3..5].copy_from_slice(&(body_len as u16).to_be_bytes());

        let err = parse_client_hello_record_bytes(&input).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(ERR_MULTIPLE_HANDSHAKE_MESSAGES));
    }

    #[test]
    fn parse_rejects_trailing_bytes_after_complete_tls_record() {
        let mut input = build_client_hello_record(&[0x01, 0x02]);
        input.push(0x16);
        input.push(0x03);
        input.push(0x03);
        input.push(0x00);
        input.push(0x01);
        input.push(0x00);

        let err = parse_client_hello_record_bytes(&input).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("trailing data"));
    }

    #[test]
    fn parse_returns_full_raw_record() {
        let input = build_client_hello_record(&[0x10, 0x20, 0x30, 0x40]);
        let record = parse_client_hello_record_bytes(&input).expect("valid record");

        assert_eq!(record.raw_record.len(), input.len());
        assert_eq!(record.raw_record, input);
        assert_eq!(
            &record.raw_record[..RECORD_HEADER_LEN],
            &input[..RECORD_HEADER_LEN]
        );
        assert_eq!(
            &record.raw_record[RECORD_HEADER_LEN..],
            &input[RECORD_HEADER_LEN..]
        );
    }

    #[test]
    fn parse_returns_handshake_message_for_reality_aad() {
        let payload = vec![0x03, 0x03, 0x00, 0x01, 0x02];
        let input = build_client_hello_record(&payload);
        let record = parse_client_hello_record_bytes(&input).expect("valid record");

        assert_eq!(record.handshake_message[0], TLS_HANDSHAKE_CLIENT_HELLO);
        assert_eq!(
            record.handshake_message.len(),
            HANDSHAKE_HEADER_LEN + record.handshake_payload.len()
        );
        assert_eq!(record.handshake_payload, payload);
        assert_ne!(
            record.handshake_payload.first(),
            Some(&TLS_HANDSHAKE_CLIENT_HELLO)
        );
        assert_eq!(
            record.raw_record.len(),
            RECORD_HEADER_LEN + record.handshake_message.len()
        );
        assert_eq!(
            &record.raw_record[..RECORD_HEADER_LEN],
            &input[..RECORD_HEADER_LEN]
        );
        assert_eq!(
            &record.raw_record[RECORD_HEADER_LEN..],
            record.handshake_message.as_slice()
        );
        assert!(!record
            .handshake_message
            .starts_with(&[TLS_CONTENT_TYPE_HANDSHAKE]));
    }

    #[test]
    fn parse_returns_handshake_payload_without_header() {
        let payload = vec![0x00, 0x02, 0x03, 0x04, 0x05];
        let input = build_client_hello_record(&payload);
        let record = parse_client_hello_record_bytes(&input).expect("valid record");

        assert_eq!(record.handshake_payload, payload);
        assert_eq!(
            record.handshake_message.len(),
            HANDSHAKE_HEADER_LEN + payload.len()
        );
        assert_eq!(
            &record.handshake_message[HANDSHAKE_HEADER_LEN..],
            payload.as_slice()
        );
        assert!(!record.handshake_payload.is_empty());
        assert_ne!(record.handshake_payload[0], TLS_HANDSHAKE_CLIENT_HELLO);
    }
}
