use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;

pub(crate) const ERR_FRAGMENTED_CLIENT_HELLO: &str =
    "ClientHello handshake incomplete in buffered TLS records";

/// Parsed ClientHello view over bytes read from the client TCP stream.
///
/// # Fields
///
/// - [`raw_record`](Self::raw_record): TLS record bytes to forward to `dest` (valid records
///   containing the ClientHello; the last record is truncated when coalesced trailing data
///   follows the ClientHello in the same record).
/// - [`initial_client_bytes`](Self::initial_client_bytes): exact bytes read from the client
///   while assembling the ClientHello (for fallback relay without loss or duplication).
/// - [`trailing_bytes`](Self::trailing_bytes): bytes after the ClientHello handshake message
///   within `initial_client_bytes` (for accepted-path stream prefixing).
#[derive(Debug, PartialEq, Eq)]
pub struct TlsClientHelloRecord {
    pub raw_record: Vec<u8>,
    pub handshake_message: Vec<u8>,
    pub handshake_payload: Vec<u8>,
    pub trailing_bytes: Vec<u8>,
    initial_client_bytes: Vec<u8>,
}

impl TlsClientHelloRecord {
    /// Exact bytes read from the client while assembling the ClientHello.
    pub fn initial_client_bytes(&self) -> &[u8] {
        &self.initial_client_bytes
    }
}

enum ClientHelloBufferParse {
    NeedMoreData,
    Complete(TlsClientHelloRecord),
}

struct ClientHelloAssembly {
    handshake_start: usize,
    handshake_len: usize,
}

fn handshake_payload_len(bytes: &[u8]) -> std::io::Result<usize> {
    if bytes.len() < 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello handshake length incomplete",
        ));
    }
    Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize)
}

fn build_raw_record_for_dest(buffer: &[u8], message_end: usize) -> std::io::Result<Vec<u8>> {
    let mut offset = 0usize;
    let mut out = Vec::new();

    while offset < message_end {
        if offset + RECORD_HEADER_LEN > buffer.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ClientHello record header truncated",
            ));
        }

        let header = &buffer[offset..offset + RECORD_HEADER_LEN];
        if header[0] != TLS_CONTENT_TYPE_HANDSHAKE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "expected TLS handshake record (content_type=0x16), got 0x{:02x}",
                    header[0]
                ),
            ));
        }

        let record_body_start = offset + RECORD_HEADER_LEN;
        let declared_body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let declared_record_end = record_body_start + declared_body_len;

        if message_end <= declared_record_end {
            let truncated_body_len = message_end - record_body_start;
            out.extend_from_slice(&header[..3]);
            out.extend_from_slice(&(truncated_body_len as u16).to_be_bytes());
            out.extend_from_slice(&buffer[record_body_start..message_end]);
            return Ok(out);
        }

        if buffer.len() < declared_record_end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ClientHello record body truncated",
            ));
        }

        out.extend_from_slice(&buffer[offset..declared_record_end]);
        offset = declared_record_end;
    }

    Ok(out)
}

fn extract_contiguous_handshake_and_trailing(
    buffer: &[u8],
    assembly: &ClientHelloAssembly,
) -> std::io::Result<(Vec<u8>, Vec<u8>, usize)> {
    let message_len = HANDSHAKE_HEADER_LEN + assembly.handshake_len;
    let mut message = Vec::with_capacity(message_len);
    let mut collected = 0usize;
    let mut offset = 0usize;

    while offset + RECORD_HEADER_LEN <= buffer.len() {
        let header = &buffer[offset..offset + RECORD_HEADER_LEN];
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
        let record_end = offset
            .checked_add(RECORD_HEADER_LEN + record_len)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TLS record length overflow",
                )
            })?;

        if buffer.len() < record_end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                ERR_FRAGMENTED_CLIENT_HELLO,
            ));
        }

        let body_start = offset + RECORD_HEADER_LEN;
        let body = &buffer[body_start..record_end];

        if collected < message_len {
            let body_handshake_start = assembly.handshake_start.saturating_sub(body_start);
            if body_handshake_start < body.len() {
                let available_in_body = body.len() - body_handshake_start;
                let need = message_len - collected;
                let take = available_in_body.min(need);
                message.extend_from_slice(&body[body_handshake_start..body_handshake_start + take]);
                collected += take;

                if collected < message_len {
                    offset = record_end;
                    continue;
                }

                let handshake_stream_end = body_start + body_handshake_start + take;
                let trailing = buffer.get(handshake_stream_end..).unwrap_or(&[]).to_vec();
                return Ok((message, trailing, handshake_stream_end));
            }
        }

        offset = record_end;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        ERR_FRAGMENTED_CLIENT_HELLO,
    ))
}

fn parse_client_hello_buffer(buffer: &[u8]) -> std::io::Result<ClientHelloBufferParse> {
    if buffer.len() < RECORD_HEADER_LEN {
        return Ok(ClientHelloBufferParse::NeedMoreData);
    }

    let mut offset = 0usize;
    let mut assembly: Option<ClientHelloAssembly> = None;

    while offset + RECORD_HEADER_LEN <= buffer.len() {
        let header = &buffer[offset..offset + RECORD_HEADER_LEN];
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
        let record_end = offset
            .checked_add(RECORD_HEADER_LEN + record_len)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TLS record length overflow",
                )
            })?;

        if buffer.len() < record_end {
            return Ok(ClientHelloBufferParse::NeedMoreData);
        }

        if assembly.is_none() {
            let body = &buffer[offset + RECORD_HEADER_LEN..record_end];
            if body.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TLS handshake record body is empty",
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
            if body.len() < HANDSHAKE_HEADER_LEN {
                return Ok(ClientHelloBufferParse::NeedMoreData);
            }
            let handshake_len = handshake_payload_len(&body[1..HANDSHAKE_HEADER_LEN])?;
            assembly = Some(ClientHelloAssembly {
                handshake_start: offset + RECORD_HEADER_LEN,
                handshake_len,
            });
        }

        offset = record_end;

        if let Some(ref asm) = assembly {
            match extract_contiguous_handshake_and_trailing(buffer, asm) {
                Ok((handshake_message, trailing_bytes, handshake_stream_end)) => {
                    let handshake_payload = handshake_message[HANDSHAKE_HEADER_LEN..].to_vec();
                    let raw_record = build_raw_record_for_dest(buffer, handshake_stream_end)?;
                    return Ok(ClientHelloBufferParse::Complete(TlsClientHelloRecord {
                        raw_record,
                        handshake_message,
                        handshake_payload,
                        trailing_bytes,
                        initial_client_bytes: buffer.to_vec(),
                    }));
                }
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(err) => return Err(err),
            }
        }
    }

    Ok(ClientHelloBufferParse::NeedMoreData)
}

/// Parses an in-memory buffer that contains complete ClientHello TLS record(s).
pub fn parse_client_hello_record_bytes(input: &[u8]) -> std::io::Result<TlsClientHelloRecord> {
    match parse_client_hello_buffer(input)? {
        ClientHelloBufferParse::Complete(record) => Ok(record),
        ClientHelloBufferParse::NeedMoreData => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            ERR_FRAGMENTED_CLIENT_HELLO,
        )),
    }
}

async fn read_next_tls_record_into(
    buffer: &mut Vec<u8>,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let header_start = buffer.len();
    buffer.resize(header_start + RECORD_HEADER_LEN, 0);
    stream
        .read_exact(&mut buffer[header_start..header_start + RECORD_HEADER_LEN])
        .await?;

    let record_len =
        u16::from_be_bytes([buffer[header_start + 3], buffer[header_start + 4]]) as usize;
    let body_start = header_start + RECORD_HEADER_LEN;
    buffer.resize(body_start + record_len, 0);
    stream
        .read_exact(&mut buffer[body_start..body_start + record_len])
        .await?;
    Ok(())
}

/// Reads from `stream` until a complete ClientHello is available.
///
/// Supports TCP fragmentation, ClientHello split across multiple TLS records, and
/// coalesced trailing bytes after the ClientHello handshake message.
pub async fn read_client_hello_record(
    stream: &mut TcpStream,
) -> std::io::Result<TlsClientHelloRecord> {
    let mut buffer = Vec::new();
    loop {
        match parse_client_hello_buffer(&buffer)? {
            ClientHelloBufferParse::Complete(record) => return Ok(record),
            ClientHelloBufferParse::NeedMoreData => {
                read_next_tls_record_into(&mut buffer, stream).await?;
            }
        }
    }
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
}
