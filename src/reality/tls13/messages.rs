use std::io::{Error, ErrorKind, Result};

pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 0x0b;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 0x0f;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 0x14;
pub const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 0x18;

pub const KEY_UPDATE_NOT_REQUESTED: u8 = 0x00;
pub const KEY_UPDATE_REQUESTED: u8 = 0x01;

const MAX_HANDSHAKE_BODY_LEN: usize = 0x00ff_ffff;
const MAX_SESSION_ID_ECHO_LEN: usize = 32;

pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;
pub const TLS_VERSION_1_2_LEGACY: [u8; 2] = [0x03, 0x03];
pub const TLS_VERSION_1_3: [u8; 2] = [0x03, 0x04];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13ServerHelloParams {
    pub random: [u8; 32],
    pub session_id_echo: Vec<u8>,
    pub cipher_suite: u16,
    pub key_share_extension_body: Vec<u8>,
}

/// Placeholder plan for generating the server-facing ServerHello message.
///
/// Upstream equivalent: ServerHello construction inside Go `hs.handshake()`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityServerHelloPlan {
    // TODO: legacy_version
    // TODO: random
    // TODO: cipher_suite
    // TODO: key_share
}

/// Placeholder plan for EncryptedExtensions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityEncryptedExtensionsPlan {
    // TODO: ALPN
    // TODO: other extensions required by REALITY camouflage
}

/// Placeholder plan for the server Certificate message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityCertificatePlan {
    // TODO: ephemeral / camouflage certificate chain
}

/// Placeholder plan for the server Finished message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityFinishedPlan {
    // TODO: verify_data derived from transcript + key schedule
}

pub fn build_handshake_message(handshake_type: u8, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > MAX_HANDSHAKE_BODY_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "TLS 1.3 handshake body too long: {} bytes (max {MAX_HANDSHAKE_BODY_LEN})",
                body.len()
            ),
        ));
    }

    let body_len = u32::try_from(body.len()).expect("body length fits in u32 after max check");

    let mut message = Vec::with_capacity(1 + 3 + body.len());
    message.push(handshake_type);
    message.extend_from_slice(&body_len.to_be_bytes()[1..]);
    message.extend_from_slice(body);
    Ok(message)
}

pub fn build_key_update_message(request_update: u8) -> Result<Vec<u8>> {
    if request_update != KEY_UPDATE_NOT_REQUESTED && request_update != KEY_UPDATE_REQUESTED {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("TLS 1.3 KeyUpdate request_update must be 0 or 1, got {request_update}"),
        ));
    }

    build_handshake_message(HANDSHAKE_TYPE_KEY_UPDATE, &[request_update])
}

pub fn parse_key_update_handshake(message: &[u8]) -> Result<u8> {
    if message.first() != Some(&HANDSHAKE_TYPE_KEY_UPDATE) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 KeyUpdate handshake must start with type 0x18",
        ));
    }

    if message.len() != 5 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "TLS 1.3 KeyUpdate handshake must be 5 bytes, got {}",
                message.len()
            ),
        ));
    }

    let body_len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
    if body_len != 1 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS 1.3 KeyUpdate handshake body must be 1 byte, got {body_len}"),
        ));
    }

    let request_update = message[4];
    if request_update != KEY_UPDATE_NOT_REQUESTED && request_update != KEY_UPDATE_REQUESTED {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS 1.3 KeyUpdate request_update must be 0 or 1, got {request_update}"),
        ));
    }

    Ok(request_update)
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

fn encode_extension(extension_type: u16, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        return Err(invalid_input(format!(
            "TLS 1.3 extension data too long: {} bytes (max {})",
            data.len(),
            u16::MAX
        )));
    }

    let data_len =
        u16::try_from(data.len()).expect("extension data length fits in u16 after validation");

    let mut extension = Vec::with_capacity(4 + data.len());
    extension.extend_from_slice(&extension_type.to_be_bytes());
    extension.extend_from_slice(&data_len.to_be_bytes());
    extension.extend_from_slice(data);
    Ok(extension)
}

pub fn build_tls13_server_hello(params: &Tls13ServerHelloParams) -> Result<Vec<u8>> {
    if params.session_id_echo.len() > MAX_SESSION_ID_ECHO_LEN {
        return Err(invalid_input(format!(
            "TLS 1.3 ServerHello session_id_echo too long: {} bytes (max {MAX_SESSION_ID_ECHO_LEN})",
            params.session_id_echo.len()
        )));
    }

    let supported_versions = encode_extension(EXT_SUPPORTED_VERSIONS, &TLS_VERSION_1_3)?;
    let key_share = encode_extension(EXT_KEY_SHARE, &params.key_share_extension_body)?;

    let extensions_len = supported_versions
        .len()
        .checked_add(key_share.len())
        .ok_or_else(|| invalid_input("TLS 1.3 ServerHello extensions length overflow"))?;

    if extensions_len > u16::MAX as usize {
        return Err(invalid_input(format!(
            "TLS 1.3 ServerHello extensions too long: {extensions_len} bytes (max {})",
            u16::MAX
        )));
    }

    let session_id_len = u8::try_from(params.session_id_echo.len())
        .expect("session_id_echo length fits in u8 after max check");

    let mut body = Vec::with_capacity(
        TLS_VERSION_1_2_LEGACY.len()
            + params.random.len()
            + 1
            + params.session_id_echo.len()
            + 2
            + 1
            + 2
            + extensions_len,
    );
    body.extend_from_slice(&TLS_VERSION_1_2_LEGACY);
    body.extend_from_slice(&params.random);
    body.push(session_id_len);
    body.extend_from_slice(&params.session_id_echo);
    body.extend_from_slice(&params.cipher_suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    body.extend_from_slice(&supported_versions);
    body.extend_from_slice(&key_share);

    build_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, &body)
}

pub fn build_encrypted_extensions_empty() -> Result<Vec<u8>> {
    build_handshake_message(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, &[0x00, 0x00])
}

pub fn build_finished(verify_data: &[u8]) -> Result<Vec<u8>> {
    build_handshake_message(HANDSHAKE_TYPE_FINISHED, verify_data)
}

pub fn build_certificate_placeholder() -> Result<Vec<u8>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "REALITY TLS 1.3 Certificate message builder is not implemented yet",
    ))
}

pub fn build_certificate_verify_placeholder() -> Result<Vec<u8>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "REALITY TLS 1.3 CertificateVerify message builder is not implemented yet",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::tls13::key_share::{
        encode_key_share_extension_body, Tls13ServerKeyShare, NAMED_GROUP_X25519, X25519_KEY_LEN,
    };
    use crate::reality::tls13::TLS_AES_128_GCM_SHA256;
    use crate::tls::parse_tls_server_hello_handshake;

    fn sample_server_hello_params(session_id_echo: Vec<u8>) -> Tls13ServerHelloParams {
        let key_share = Tls13ServerKeyShare {
            group: NAMED_GROUP_X25519,
            public_key: [0x55; X25519_KEY_LEN],
            shared_secret: [0x66; X25519_KEY_LEN],
        };

        Tls13ServerHelloParams {
            random: [0x11; 32],
            session_id_echo,
            cipher_suite: TLS_AES_128_GCM_SHA256,
            key_share_extension_body: encode_key_share_extension_body(&key_share)
                .expect("valid key_share extension body"),
        }
    }

    #[test]
    fn build_tls13_server_hello_encodes_handshake_message() {
        let params = sample_server_hello_params(vec![0x22; 8]);
        let message = build_tls13_server_hello(&params).expect("valid ServerHello");

        assert_eq!(message[0], HANDSHAKE_TYPE_SERVER_HELLO);
        let declared_len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
        assert_eq!(declared_len, message.len() - 4);
    }

    #[test]
    fn build_tls13_server_hello_preserves_body_fields_and_extensions() {
        let params = sample_server_hello_params(vec![0x22; 8]);
        let message = build_tls13_server_hello(&params).expect("valid ServerHello");
        let body = &message[4..];
        let parsed = parse_tls_server_hello_handshake(&message).expect("parsable ServerHello");

        assert_eq!(&body[..2], &TLS_VERSION_1_2_LEGACY);
        assert_eq!(parsed.legacy_version, TLS_VERSION_1_2_LEGACY);
        assert_eq!(parsed.random, params.random);
        assert_eq!(parsed.session_id_echo, params.session_id_echo);
        assert_eq!(parsed.cipher_suite, params.cipher_suite);
        assert_eq!(parsed.compression_method, 0);
        assert_eq!(
            parsed.get_extension(EXT_SUPPORTED_VERSIONS),
            Some(TLS_VERSION_1_3.as_slice())
        );
        assert_eq!(
            parsed.get_extension(EXT_KEY_SHARE),
            Some(params.key_share_extension_body.as_slice())
        );
    }

    #[test]
    fn build_tls13_server_hello_rejects_session_id_echo_longer_than_32() {
        let params = sample_server_hello_params(vec![0x33; 33]);
        let err = build_tls13_server_hello(&params).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("session_id_echo too long"));
    }

    #[test]
    fn build_key_update_message_encodes_request_update_byte() {
        let message = build_key_update_message(KEY_UPDATE_NOT_REQUESTED).unwrap();
        assert_eq!(message, vec![0x18, 0x00, 0x00, 0x01, 0x00]);

        let requested = build_key_update_message(KEY_UPDATE_REQUESTED).unwrap();
        assert_eq!(requested, vec![0x18, 0x00, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn parse_key_update_handshake_roundtrips() {
        let message = build_key_update_message(KEY_UPDATE_REQUESTED).unwrap();
        assert_eq!(
            parse_key_update_handshake(&message).expect("valid key update"),
            KEY_UPDATE_REQUESTED
        );
    }

    #[test]
    fn build_handshake_message_encodes_length_correctly() {
        let body = [0x01, 0x02, 0x03];
        let message = build_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, &body).unwrap();

        assert_eq!(message, vec![0x02, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn build_handshake_message_rejects_body_too_long() {
        let body = vec![0u8; MAX_HANDSHAKE_BODY_LEN + 1];
        let err = build_handshake_message(HANDSHAKE_TYPE_FINISHED, &body).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("handshake body too long"));
    }

    #[test]
    fn build_encrypted_extensions_empty_is_exact_bytes() {
        let message = build_encrypted_extensions_empty().unwrap();
        assert_eq!(message, vec![0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn build_finished_wraps_verify_data() {
        let verify_data = [0xaa, 0xbb, 0xcc, 0xdd];
        let message = build_finished(&verify_data).unwrap();

        assert_eq!(
            message,
            vec![0x14, 0x00, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]
        );
    }

    #[test]
    fn build_certificate_placeholder_returns_unsupported() {
        let err = build_certificate_placeholder().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn build_certificate_verify_placeholder_returns_unsupported() {
        let err = build_certificate_verify_placeholder().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}
