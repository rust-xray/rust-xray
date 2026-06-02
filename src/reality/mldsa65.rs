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

#[derive(Clone, PartialEq, Eq)]
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
pub fn patch_reality_cert_der_with_mldsa65_signature(
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityMldsa65HandshakeDataAvailability {
    pub has_client_hello_original: bool,
    pub client_hello_len: usize,
    pub has_server_hello_original: bool,
    pub server_hello_len: usize,
    pub has_ed25519_public_key: bool,
    pub has_auth_key: bool,
    pub has_mldsa65_seed: bool,
    pub cert_der_len: usize,
    pub cert_der_has_mldsa65_patch_range: bool,
}

pub fn reality_mldsa65_handshake_data_shape(
    client_hello_original: Option<&[u8]>,
    server_hello_original: Option<&[u8]>,
    ed25519_public_key: Option<&[u8; 32]>,
    auth_key: Option<&[u8; 32]>,
    mldsa65_seed: Option<&Mldsa65Seed>,
    cert_der: Option<&[u8]>,
) -> RealityMldsa65HandshakeDataAvailability {
    let client_hello_len = client_hello_original.map_or(0, <[u8]>::len);
    let server_hello_len = server_hello_original.map_or(0, <[u8]>::len);
    let cert_der_len = cert_der.map_or(0, <[u8]>::len);
    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;

    RealityMldsa65HandshakeDataAvailability {
        has_client_hello_original: client_hello_len > 0,
        client_hello_len,
        has_server_hello_original: server_hello_len > 0,
        server_hello_len,
        has_ed25519_public_key: ed25519_public_key.is_some(),
        has_auth_key: auth_key.is_some(),
        has_mldsa65_seed: mldsa65_seed.is_some(),
        cert_der_len,
        cert_der_has_mldsa65_patch_range: cert_der_len >= extension_end,
    }
}

pub fn validate_reality_mldsa65_live_handshake_data_shape(
    shape: &RealityMldsa65HandshakeDataAvailability,
) -> std::io::Result<()> {
    if !shape.has_client_hello_original {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY ML-DSA-65 live handshake data requires ClientHello original bytes",
        ));
    }

    if !shape.has_server_hello_original {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY ML-DSA-65 live handshake data requires ServerHello original bytes",
        ));
    }

    if !shape.has_ed25519_public_key {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY ML-DSA-65 live handshake data requires Ed25519 public key",
        ));
    }

    if !shape.has_auth_key {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY ML-DSA-65 live handshake data requires auth_key",
        ));
    }

    if !shape.has_mldsa65_seed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY ML-DSA-65 live handshake data requires mldsa65Seed",
        ));
    }

    if !shape.cert_der_has_mldsa65_patch_range {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "REALITY ML-DSA-65 live handshake data requires certificate DER patch range",
        ));
    }

    Ok(())
}

/// Builds the REALITY ML-DSA-65 message and signs it with `seed`.
pub fn sign_reality_cert_extension(
    seed: &Mldsa65Seed,
    ed25519_public_key: &[u8; 32],
    auth_key: &[u8; 32],
    client_hello_original: &[u8],
    server_hello_original: &[u8],
) -> std::io::Result<Mldsa65Signature> {
    let message = build_reality_mldsa65_message(
        auth_key,
        ed25519_public_key,
        client_hello_original,
        server_hello_original,
    );

    sign_reality_mldsa65_message(seed, &message)
}

/// Offline REALITY ML-DSA-65 message signing from a 32-byte seed.
pub fn sign_reality_mldsa65_message(
    seed: &Mldsa65Seed,
    message: &[u8; 64],
) -> std::io::Result<Mldsa65Signature> {
    use ml_dsa::{MlDsa65, SignatureEncoding, Signer, SigningKey};

    let seed_bytes = ml_dsa::B32::from(*seed.as_bytes());
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_bytes);
    let signature = signing_key.try_sign(message.as_slice()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "ML-DSA-65 signing failed")
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
#[path = "../../tests/unit/reality/mldsa65.rs"]
mod tests;
