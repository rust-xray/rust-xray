use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MLDSA65_SEED_LEN: usize = 32;
pub const MLDSA65_VERIFY_KEY_LEN: usize = 1952;
pub const MLDSA65_CERT_EXTENSION_VALUE_LEN: usize = 3309;
pub const MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET: usize = 126;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mldsa65Seed([u8; MLDSA65_SEED_LEN]);

impl Mldsa65Seed {
    pub fn from_bytes(bytes: [u8; MLDSA65_SEED_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; MLDSA65_SEED_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Mldsa65Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mldsa65Seed(<redacted>)")
    }
}

pub fn decode_mldsa65_seed(
    seed: Option<&str>,
    private_key: &str,
) -> std::io::Result<Option<Mldsa65Seed>> {
    let Some(seed) = seed else {
        return Ok(None);
    };

    if seed.is_empty() {
        return Ok(None);
    }

    if seed == private_key {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.mldsa65Seed must not equal privateKey",
        ));
    }

    let decoded = URL_SAFE_NO_PAD.decode(seed).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid mldsa65Seed base64: {e}"),
        )
    })?;

    decoded
        .try_into()
        .map(|bytes| Some(Mldsa65Seed(bytes)))
        .map_err(|decoded: Vec<u8>| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid mldsa65Seed length: expected {} bytes, got {}",
                    MLDSA65_SEED_LEN,
                    decoded.len()
                ),
            )
        })
}

/// Stub for future REALITY ML-DSA-65 certificate extension signing.
///
/// Upstream feeds HMAC state with `auth_key`, the Ed25519 public key, raw ClientHello, and raw
/// ServerHello, then writes the ML-DSA-65 signature at
/// [`MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET`]. This placeholder does not perform signing.
pub fn sign_reality_cert_extension_stub(
    _cert_der: &[u8],
    _ed25519_public_key: &[u8; 32],
    _auth_key: &[u8; 32],
    _client_hello_original: &[u8],
    _server_hello_original: &[u8],
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "REALITY ML-DSA-65 certificate extension signing is not implemented",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
    const VALID_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const SEED_31_BYTES_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg";
    const SEED_33_BYTES_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";

    #[test]
    fn mldsa65_constants_match_expected_lengths() {
        assert_eq!(MLDSA65_SEED_LEN, 32);
        assert_eq!(MLDSA65_VERIFY_KEY_LEN, 1952);
        assert_eq!(MLDSA65_CERT_EXTENSION_VALUE_LEN, 3309);
    }

    #[test]
    fn mldsa65_extension_constants_match_upstream_layout() {
        assert_eq!(MLDSA65_SEED_LEN, 32);
        assert_eq!(MLDSA65_VERIFY_KEY_LEN, 1952);
        assert_eq!(MLDSA65_CERT_EXTENSION_VALUE_LEN, 3309);
        assert_eq!(MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET, 126);
    }

    #[test]
    fn mldsa65_stub_does_not_mutate_cert_der() {
        let cert_before = vec![0x55; 256];
        let cert_after = cert_before.clone();
        let public_key = [0x11; 32];
        let auth_key = [0x22; 32];
        let client_hello = [0x01, 0x02, 0x03];
        let server_hello = [0x04, 0x05, 0x06];

        let err = sign_reality_cert_extension_stub(
            &cert_after,
            &public_key,
            &auth_key,
            &client_hello,
            &server_hello,
        )
        .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(cert_after, cert_before);
    }

    #[test]
    fn mldsa65_seed_debug_does_not_expose_bytes() {
        let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
            .unwrap()
            .unwrap();
        let debug = format!("{seed:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(VALID_SEED_B64));
    }

    #[test]
    fn accepts_valid_mldsa65_seed() {
        let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY).unwrap();
        assert!(seed.is_some());
        assert_eq!(seed.unwrap().as_bytes().len(), MLDSA65_SEED_LEN);
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = decode_mldsa65_seed(Some("not-valid-base64!!!"), TEST_PRIVATE_KEY).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("invalid mldsa65Seed base64"));
    }

    #[test]
    fn rejects_decoded_31_bytes() {
        let err = decode_mldsa65_seed(Some(SEED_31_BYTES_B64), TEST_PRIVATE_KEY).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("expected 32 bytes, got 31"));
    }

    #[test]
    fn rejects_decoded_33_bytes() {
        let err = decode_mldsa65_seed(Some(SEED_33_BYTES_B64), TEST_PRIVATE_KEY).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("expected 32 bytes, got 33"));
    }

    #[test]
    fn empty_seed_is_none() {
        assert!(decode_mldsa65_seed(None, TEST_PRIVATE_KEY)
            .unwrap()
            .is_none());
        assert!(decode_mldsa65_seed(Some(""), TEST_PRIVATE_KEY)
            .unwrap()
            .is_none());
    }

    #[test]
    fn seed_equal_private_key_is_rejected() {
        let err = decode_mldsa65_seed(Some(TEST_PRIVATE_KEY), TEST_PRIVATE_KEY).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("must not equal privateKey"));
    }
}
