use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MLDSA65_SEED_LEN: usize = 32;
pub const MLDSA65_VERIFY_KEY_LEN: usize = 1952;
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;
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
        f.write_str("Mldsa65Seed(redacted)")
    }
}

#[derive(Clone)]
pub struct Mldsa65VerifyKey(Vec<u8>);

impl Mldsa65VerifyKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Mldsa65VerifyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mldsa65VerifyKey(redacted)")
    }
}

#[derive(Clone)]
pub struct Mldsa65Signature(Vec<u8>);

impl Mldsa65Signature {
    pub fn from_bytes(bytes: Vec<u8>) -> std::io::Result<Self> {
        if bytes.len() != MLDSA65_SIGNATURE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid ML-DSA-65 signature length: expected {} bytes, got {}",
                    MLDSA65_SIGNATURE_LEN,
                    bytes.len()
                ),
            ));
        }

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Mldsa65Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mldsa65Signature(redacted)")
    }
}

pub fn decode_mldsa65_verify_key(value: &str) -> std::io::Result<Mldsa65VerifyKey> {
    if value.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mldsa65Verify must not be empty",
        ));
    }

    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid mldsa65Verify base64: {e}"),
        )
    })?;

    if decoded.len() != MLDSA65_VERIFY_KEY_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid mldsa65Verify length: expected {} bytes, got {}",
                MLDSA65_VERIFY_KEY_LEN,
                decoded.len()
            ),
        ));
    }

    Ok(Mldsa65VerifyKey(decoded))
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

pub fn build_reality_mldsa65_message(
    auth_key: &[u8; 32],
    ed25519_public_key: &[u8; 32],
    client_hello_original: &[u8],
    server_hello_original: &[u8],
) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(auth_key)
        .expect("HMAC-SHA512 accepts 32-byte REALITY auth keys");
    mac.update(ed25519_public_key);
    mac.update(client_hello_original);
    mac.update(server_hello_original);
    mac.finalize().into_bytes().into()
}

/// Writes an ML-DSA-65 signature into the REALITY certificate extension value at
/// [`MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET`].
pub fn write_reality_mldsa65_cert_extension_signature(
    cert_der: &mut [u8],
    signature: &Mldsa65Signature,
) -> std::io::Result<()> {
    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
    if cert_der.len() < extension_end {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "REALITY certificate DER too short for ML-DSA-65 extension patch: {} bytes (need >= {extension_end})",
                cert_der.len()
            ),
        ));
    }

    cert_der[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end]
        .copy_from_slice(signature.as_bytes());

    Ok(())
}

/// Offline REALITY ML-DSA-65 message signing from a 32-byte seed.
///
/// Requires the `reality-mldsa65-crypto` feature. Without it, returns
/// [`std::io::ErrorKind::Unsupported`].
#[cfg(not(feature = "reality-mldsa65-crypto"))]
pub fn sign_reality_mldsa65_message(
    _seed: &Mldsa65Seed,
    _message: &[u8; 64],
) -> std::io::Result<Mldsa65Signature> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "REALITY ML-DSA-65 signing requires the `reality-mldsa65-crypto` feature",
    ))
}

/// Offline REALITY ML-DSA-65 message signing from a 32-byte seed.
#[cfg(feature = "reality-mldsa65-crypto")]
pub fn sign_reality_mldsa65_message(
    seed: &Mldsa65Seed,
    message: &[u8; 64],
) -> std::io::Result<Mldsa65Signature> {
    use ml_dsa::{MlDsa65, SignatureEncoding, Signer, SigningKey};

    let seed_bytes = ml_dsa::B32::from(*seed.as_bytes());
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_bytes);
    let signature = signing_key.try_sign(message.as_slice()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "ML-DSA-65 signing failed",
        )
    })?;

    Mldsa65Signature::from_bytes(signature.to_bytes().as_slice().to_vec())
}

/// Stub for future REALITY ML-DSA-65 certificate extension signing.
///
/// Upstream feeds HMAC state with `auth_key`, the Ed25519 public key, raw ClientHello, and raw
/// ServerHello, then writes the ML-DSA-65 signature at
/// [`MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET`]. This placeholder does not perform signing.
pub fn sign_reality_cert_extension_stub(
    _cert_der: &[u8],
    _mldsa65_seed: &Mldsa65Seed,
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
        assert_eq!(MLDSA65_SIGNATURE_LEN, 3309);
        assert_eq!(MLDSA65_CERT_EXTENSION_VALUE_LEN, 3309);
    }

    #[test]
    fn mldsa65_extension_constants_match_upstream_layout() {
        assert_eq!(MLDSA65_SEED_LEN, 32);
        assert_eq!(MLDSA65_VERIFY_KEY_LEN, 1952);
        assert_eq!(MLDSA65_SIGNATURE_LEN, MLDSA65_CERT_EXTENSION_VALUE_LEN);
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
        let mldsa65_seed = Mldsa65Seed::from_bytes([0x33; 32]);

        let err = sign_reality_cert_extension_stub(
            &cert_after,
            &mldsa65_seed,
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
        assert_eq!(debug, "Mldsa65Seed(redacted)");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(VALID_SEED_B64));
        assert!(!debug.contains("0, 1, 2"));
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

    fn b64url_no_pad(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn mldsa65_verify_key_debug_does_not_expose_bytes() {
        let verify_b64 = b64url_no_pad(&vec![0x42; MLDSA65_VERIFY_KEY_LEN]);
        let verify = decode_mldsa65_verify_key(&verify_b64).unwrap();
        let debug = format!("{verify:?}");
        assert_eq!(debug, "Mldsa65VerifyKey(redacted)");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(&verify_b64));
        assert!(!debug.contains("66"));
    }

    #[test]
    fn decode_mldsa65_verify_key_rejects_empty_string() {
        let err = decode_mldsa65_verify_key("").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn decode_mldsa65_verify_key_rejects_invalid_base64() {
        let err = decode_mldsa65_verify_key("not-valid-base64!!!").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("invalid mldsa65Verify base64"));
    }

    #[test]
    fn decode_mldsa65_verify_key_rejects_wrong_lengths() {
        let verify_1951 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN - 1]);
        let err = decode_mldsa65_verify_key(&verify_1951).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("expected 1952 bytes, got 1951"));

        let verify_1953 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN + 1]);
        let err = decode_mldsa65_verify_key(&verify_1953).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("expected 1952 bytes, got 1953"));
    }

    #[test]
    fn decode_mldsa65_verify_key_accepts_1952_bytes() {
        let verify_b64 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN]);
        let verify = decode_mldsa65_verify_key(&verify_b64).unwrap();
        assert_eq!(verify.as_bytes().len(), MLDSA65_VERIFY_KEY_LEN);
    }

    #[cfg(not(feature = "reality-mldsa65-crypto"))]
    #[test]
    fn sign_reality_mldsa65_message_without_feature_returns_unsupported() {
        let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
            .unwrap()
            .unwrap();
        let message = [0x33; 64];

        let err = sign_reality_mldsa65_message(&seed, &message).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("reality-mldsa65-crypto"));
    }

    #[cfg(feature = "reality-mldsa65-crypto")]
    #[test]
    fn sign_reality_mldsa65_message_with_feature_returns_expected_length() {
        let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
            .unwrap()
            .unwrap();
        let message = build_reality_mldsa65_message(
            &[0x22; 32],
            &[0x11; 32],
            &[0x01, 0x02, 0x03],
            &[0x04, 0x05, 0x06],
        );

        let signature = sign_reality_mldsa65_message(&seed, &message).expect("valid signature");

        assert_eq!(signature.as_bytes().len(), MLDSA65_SIGNATURE_LEN);
    }

    #[test]
    fn write_reality_mldsa65_cert_extension_signature_writes_at_offset() {
        let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
        let mut cert_der = vec![0xaa; extension_end + 64];
        let signature =
            Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_SIGNATURE_LEN]).unwrap();

        write_reality_mldsa65_cert_extension_signature(&mut cert_der, &signature)
            .expect("valid extension write");

        assert_eq!(
            &cert_der[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end],
            signature.as_bytes()
        );
        assert_eq!(&cert_der[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET], &[0xaa; 126]);
        assert_eq!(&cert_der[extension_end..], &[0xaa; 64]);
    }

    #[test]
    fn write_reality_mldsa65_cert_extension_signature_rejects_too_short_cert() {
        let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
        let mut cert_der = vec![0xaa; extension_end - 1];
        let cert_before = cert_der.clone();
        let signature =
            Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_SIGNATURE_LEN]).unwrap();

        let err =
            write_reality_mldsa65_cert_extension_signature(&mut cert_der, &signature).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(cert_der, cert_before);
    }

    #[test]
    fn mldsa65_signature_debug_does_not_expose_bytes() {
        let signature =
            Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_SIGNATURE_LEN]).unwrap();
        let debug = format!("{signature:?}");
        assert_eq!(debug, "Mldsa65Signature(redacted)");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("66"));
    }

    #[test]
    fn build_reality_mldsa65_message_matches_manual_hmac() {
        let auth_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x00, 0x01,
        ];
        let ed25519_public_key = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x10, 0x11,
        ];
        let client_hello_original = [0x01, 0x02, 0x03, 0x04];
        let server_hello_original = [0x02, 0x03, 0x04, 0x05];

        let actual = build_reality_mldsa65_message(
            &auth_key,
            &ed25519_public_key,
            &client_hello_original,
            &server_hello_original,
        );

        let mut mac = Hmac::<Sha512>::new_from_slice(&auth_key).expect("valid HMAC key");
        mac.update(&ed25519_public_key);
        mac.update(&client_hello_original);
        mac.update(&server_hello_original);
        let expected: [u8; 64] = mac.finalize().into_bytes().into();

        assert_eq!(actual, expected);
    }
}
