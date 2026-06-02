use tokio::io::{AsyncRead, AsyncReadExt};

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

async fn read_next_tls_record_into<S: AsyncRead + Unpin>(
    buffer: &mut Vec<u8>,
    stream: &mut S,
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
pub async fn read_client_hello_record<S: AsyncRead + Unpin>(
    stream: &mut S,
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
#[path = "../../tests/unit/tls/record.rs"]
mod tests;
