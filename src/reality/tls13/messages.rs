use std::io::{Error, ErrorKind, Result};

pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 0x0b;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 0x0f;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 0x14;

const MAX_HANDSHAKE_BODY_LEN: usize = 0x00ff_ffff;

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
