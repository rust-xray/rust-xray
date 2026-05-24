use std::io::{Error, ErrorKind};

const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_HEADER_LEN: usize = 4;

const LEGACY_VERSION_LEN: usize = 2;
const RANDOM_LEN: usize = 32;
const SESSION_ID_LEN_FIELD: usize = 1;
const CIPHER_SUITE_LEN: usize = 2;
const COMPRESSION_METHOD_LEN: usize = 1;
const EXTENSIONS_LEN_FIELD: usize = 2;
const EXTENSION_HEADER_LEN: usize = 4;

/// TLS extension type: supported_versions (RFC 8446).
pub const EXTENSION_SUPPORTED_VERSIONS: u16 = 43;

/// TLS extension type: key_share (RFC 8446).
pub const EXTENSION_KEY_SHARE: u16 = 51;

/// TLS named group: X25519 (RFC 8446).
pub const NAMED_GROUP_X25519: u16 = 0x001d;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloKeyShare {
    pub group: u16,
    pub key_exchange: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerHello {
    pub legacy_version: [u8; 2],
    pub random: [u8; 32],
    pub session_id_echo: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<TlsExtension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

impl TlsServerHello {
    pub fn get_extension(&self, ext_type: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|extension| extension.extension_type == ext_type)
            .map(|extension| extension.data.as_slice())
    }
}

/// Parses the `key_share` extension body from a TLS 1.3 ServerHello.
///
/// ServerHello carries a single KeyShareEntry:
/// ```text
/// group:           u16
/// key_exchange length: u16
/// key_exchange:    variable
/// ```
pub fn parse_server_hello_key_share(data: &[u8]) -> std::io::Result<ServerHelloKeyShare> {
    if data.len() < 4 {
        return Err(unexpected_eof("ServerHello key_share extension too short"));
    }

    let group = u16::from_be_bytes([data[0], data[1]]);
    let key_exchange_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let key_exchange_end = 4usize
        .checked_add(key_exchange_len)
        .ok_or_else(|| invalid_data("ServerHello key_share key_exchange length overflow"))?;

    let key_exchange = data
        .get(4..key_exchange_end)
        .ok_or_else(|| unexpected_eof("ServerHello key_share key_exchange incomplete"))?
        .to_vec();

    if data.len() > key_exchange_end {
        return Err(invalid_data(
            "ServerHello key_share extension has trailing data",
        ));
    }

    Ok(ServerHelloKeyShare {
        group,
        key_exchange,
    })
}

fn unexpected_eof(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::UnexpectedEof, message.into())
}

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}

/// Parses a **full TLS handshake message** containing exactly one ServerHello.
///
/// # Input format
///
/// ```text
/// byte 0       handshake type (must be 0x02)
/// bytes 1..4   handshake message length (3-byte big-endian, excludes the 4-byte header)
/// bytes 4..    ServerHello body
/// ```
///
/// The buffer must contain exactly one handshake message: no trailing bytes after the
/// declared body length.
pub fn parse_tls_server_hello_handshake(
    handshake_payload_or_message: &[u8],
) -> std::io::Result<TlsServerHello> {
    if handshake_payload_or_message.len() < HANDSHAKE_HEADER_LEN {
        return Err(unexpected_eof("ServerHello handshake header incomplete"));
    }

    if handshake_payload_or_message[0] != TLS_HANDSHAKE_SERVER_HELLO {
        return Err(invalid_data(format!(
            "expected ServerHello handshake (type=0x02), got 0x{:02x}",
            handshake_payload_or_message[0]
        )));
    }

    let handshake_len = u32::from_be_bytes([
        0,
        handshake_payload_or_message[1],
        handshake_payload_or_message[2],
        handshake_payload_or_message[3],
    ]) as usize;
    let message_end = HANDSHAKE_HEADER_LEN
        .checked_add(handshake_len)
        .ok_or_else(|| invalid_data("ServerHello handshake length overflow"))?;

    if handshake_payload_or_message.len() < message_end {
        return Err(unexpected_eof(format!(
            "ServerHello handshake incomplete: expected {} bytes, got {}",
            message_end,
            handshake_payload_or_message.len()
        )));
    }

    if handshake_payload_or_message.len() > message_end {
        return Err(invalid_data(format!(
            "ServerHello handshake has trailing data: expected {} bytes, got {}",
            message_end,
            handshake_payload_or_message.len()
        )));
    }

    parse_server_hello_body(&handshake_payload_or_message[HANDSHAKE_HEADER_LEN..message_end])
}

fn parse_server_hello_body(body: &[u8]) -> std::io::Result<TlsServerHello> {
    let minimum_body_len = LEGACY_VERSION_LEN
        + RANDOM_LEN
        + SESSION_ID_LEN_FIELD
        + CIPHER_SUITE_LEN
        + COMPRESSION_METHOD_LEN
        + EXTENSIONS_LEN_FIELD;
    if body.len() < minimum_body_len {
        return Err(unexpected_eof("ServerHello body too short"));
    }

    let mut offset = 0;

    let legacy_version = read_fixed::<2>(body, &mut offset, "legacy_version")?;
    let random = read_fixed::<32>(body, &mut offset, "random")?;

    let session_id_len = read_u8(body, &mut offset, "session_id length")? as usize;
    let session_id_echo = read_bytes(body, &mut offset, session_id_len, "session_id echo")?;

    let cipher_suite = read_u16(body, &mut offset, "cipher_suite")?;
    let compression_method = read_u8(body, &mut offset, "compression_method")?;

    let extensions_len = read_u16(body, &mut offset, "extensions length")? as usize;
    let extensions_end = offset
        .checked_add(extensions_len)
        .ok_or_else(|| invalid_data("ServerHello extensions length overflow"))?;
    if extensions_end > body.len() {
        return Err(unexpected_eof("ServerHello extensions exceed body"));
    }

    let mut extensions = Vec::new();
    while offset < extensions_end {
        if extensions_end - offset < EXTENSION_HEADER_LEN {
            return Err(unexpected_eof("ServerHello extension header incomplete"));
        }

        let extension_type = read_u16(body, &mut offset, "extension type")?;
        let extension_len = read_u16(body, &mut offset, "extension length")? as usize;
        let extension_data = read_bytes(body, &mut offset, extension_len, "extension data")?;

        extensions.push(TlsExtension {
            extension_type,
            data: extension_data,
        });
    }

    if offset != body.len() {
        return Err(invalid_data(format!(
            "ServerHello body has trailing bytes: parsed {} bytes, body is {} bytes",
            offset,
            body.len()
        )));
    }

    Ok(TlsServerHello {
        legacy_version,
        random,
        session_id_echo,
        cipher_suite,
        compression_method,
        extensions,
    })
}

fn read_u8(input: &[u8], offset: &mut usize, field: &str) -> std::io::Result<u8> {
    let value = input
        .get(*offset)
        .copied()
        .ok_or_else(|| unexpected_eof(format!("ServerHello {field} incomplete")))?;
    *offset += 1;
    Ok(value)
}

fn read_u16(input: &[u8], offset: &mut usize, field: &str) -> std::io::Result<u16> {
    let slice = input
        .get(*offset..*offset + 2)
        .ok_or_else(|| unexpected_eof(format!("ServerHello {field} incomplete")))?;
    *offset += 2;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_bytes(
    input: &[u8],
    offset: &mut usize,
    len: usize,
    field: &str,
) -> std::io::Result<Vec<u8>> {
    let slice = input
        .get(*offset..*offset + len)
        .ok_or_else(|| unexpected_eof(format!("ServerHello {field} incomplete")))?;
    *offset += len;
    Ok(slice.to_vec())
}

fn read_fixed<const N: usize>(
    input: &[u8],
    offset: &mut usize,
    field: &str,
) -> std::io::Result<[u8; N]> {
    let slice = input
        .get(*offset..*offset + N)
        .ok_or_else(|| unexpected_eof(format!("ServerHello {field} incomplete")))?;
    *offset += N;
    Ok(slice.try_into().expect("fixed-size slice length matches N"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_server_hello_handshake_message(
        random: [u8; 32],
        session_id_echo: &[u8],
        cipher_suite: u16,
        extensions: &[(u16, &[u8])],
    ) -> Vec<u8> {
        assert!(session_id_echo.len() <= u8::MAX as usize);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(session_id_echo.len() as u8);
        body.extend_from_slice(session_id_echo);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0x00);

        let mut extension_bytes = Vec::new();
        for (extension_type, data) in extensions {
            extension_bytes.extend_from_slice(&extension_type.to_be_bytes());
            extension_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            extension_bytes.extend_from_slice(data);
        }
        body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension_bytes);

        let mut message = Vec::with_capacity(HANDSHAKE_HEADER_LEN + body.len());
        message.push(TLS_HANDSHAKE_SERVER_HELLO);
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn parse_minimal_valid_tls13_server_hello_with_supported_versions_and_key_share() {
        let random = [0x11; 32];
        let supported_versions = [0x03, 0x04];
        let key_share = {
            let mut data = Vec::new();
            data.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
            data.extend_from_slice(&32u16.to_be_bytes());
            data.extend_from_slice(&[0x22; 32]);
            data
        };

        let input = build_server_hello_handshake_message(
            random,
            &[],
            0x1301,
            &[
                (EXTENSION_SUPPORTED_VERSIONS, &supported_versions),
                (EXTENSION_KEY_SHARE, &key_share),
            ],
        );

        let server_hello = parse_tls_server_hello_handshake(&input).expect("valid ServerHello");

        assert_eq!(server_hello.legacy_version, [0x03, 0x03]);
        assert_eq!(server_hello.random, random);
        assert!(server_hello.session_id_echo.is_empty());
        assert_eq!(server_hello.cipher_suite, 0x1301);
        assert_eq!(server_hello.compression_method, 0x00);
        assert_eq!(server_hello.extensions.len(), 2);
        assert_eq!(
            server_hello.get_extension(EXTENSION_SUPPORTED_VERSIONS),
            Some(supported_versions.as_slice())
        );
        assert_eq!(
            server_hello.get_extension(EXTENSION_KEY_SHARE),
            Some(key_share.as_slice())
        );
    }

    #[test]
    fn parse_rejects_wrong_handshake_type() {
        let mut input = build_server_hello_handshake_message([0; 32], &[], 0x1301, &[]);
        input[0] = 0x01;

        let err = parse_tls_server_hello_handshake(&input).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("ServerHello handshake"));
    }

    #[test]
    fn parse_rejects_truncated_body() {
        let input = build_server_hello_handshake_message([0; 32], &[], 0x1301, &[]);
        let truncated = &input[..input.len() - 2];

        let err = parse_tls_server_hello_handshake(truncated).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let mut input = build_server_hello_handshake_message([0; 32], &[], 0x1301, &[]);
        input.push(0xff);

        let err = parse_tls_server_hello_handshake(&input).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("trailing data"));
    }

    #[test]
    fn parse_server_hello_key_share_valid_x25519() {
        let mut data = Vec::new();
        data.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
        data.extend_from_slice(&32u16.to_be_bytes());
        data.extend_from_slice(&[0x44; 32]);

        let key_share = parse_server_hello_key_share(&data).expect("valid key_share");
        assert_eq!(key_share.group, NAMED_GROUP_X25519);
        assert_eq!(key_share.key_exchange, vec![0x44; 32]);
    }

    #[test]
    fn extension_lookup_works() {
        let custom_ext_data = [0xaa, 0xbb, 0xcc];
        let input = build_server_hello_handshake_message(
            [0x33; 32],
            &[0x01, 0x02],
            0x1302,
            &[(0x1234, &custom_ext_data)],
        );

        let server_hello = parse_tls_server_hello_handshake(&input).expect("valid ServerHello");

        assert_eq!(server_hello.session_id_echo, vec![0x01, 0x02]);
        assert_eq!(
            server_hello.get_extension(0x1234),
            Some(custom_ext_data.as_slice())
        );
        assert_eq!(
            server_hello.get_extension(EXTENSION_SUPPORTED_VERSIONS),
            None
        );
    }
}
