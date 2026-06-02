use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::debug;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::protocol::enums::{NamedGroup, ProtocolVersion};
use crate::protocol::structs::{ClientHelloPayload, KeyShareEntry};

pub struct RealityAuthResult {
    pub(crate) auth_key: [u8; 32],
    #[allow(dead_code)] // populated for future REALITY handshake path
    pub(crate) client_public_key: [u8; 32],
}

impl Drop for RealityAuthResult {
    fn drop(&mut self) {
        self.auth_key.zeroize();
    }
}

impl std::fmt::Debug for RealityAuthResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityAuthResult")
            .field("auth_key", &"<redacted>")
            .field("client_public_key", &"<redacted>")
            .finish()
    }
}

fn decode_reality_private_key(value: &str) -> std::io::Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid REALITY private key base64: {e}"),
        )
    })?;

    decoded.try_into().map_err(|decoded: Vec<u8>| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid REALITY private key length: expected 32 bytes, got {}",
                decoded.len()
            ),
        )
    })
}

fn find_x25519_public_key(keyshares: &[KeyShareEntry]) -> Option<[u8; 32]> {
    for keyshare in keyshares {
        if keyshare.group != NamedGroup::X25519 {
            continue;
        }

        if let Ok(key) = keyshare.payload.bytes().try_into() {
            return Some(key);
        }
    }

    None
}

pub(crate) fn extract_x25519_keyshare(hello: &ClientHelloPayload) -> Option<[u8; 32]> {
    let keyshares = hello.keyshare_extension()?;
    find_x25519_public_key(keyshares)
}

pub fn validate_reality_private_key_b64(value: &str) -> std::io::Result<()> {
    decode_reality_private_key(value).map(|_| ())
}

pub(crate) fn derive_reality_auth_key(
    hello: &ClientHelloPayload,
    server_private_key_b64: &str,
) -> std::io::Result<Option<RealityAuthResult>> {
    let supports_tls13 = hello
        .versions_extension()
        .is_some_and(|versions| versions.contains(&ProtocolVersion::TLSv1_3));

    if !supports_tls13 {
        return Ok(None);
    }

    let server_private_key = decode_reality_private_key(server_private_key_b64)?;
    let server_secret = StaticSecret::from(server_private_key);

    let client_public_key = match extract_x25519_keyshare(hello) {
        Some(key) => key,
        None => return Ok(None),
    };

    let client_public = PublicKey::from(client_public_key);
    let shared_secret = server_secret.diffie_hellman(&client_public);

    let hk = Hkdf::<Sha256>::new(Some(&hello.random.0[..20]), shared_secret.as_bytes());
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("HKDF expand failed: {e}"),
        )
    })?;

    debug!("HKDF derive ok");

    Ok(Some(RealityAuthResult {
        auth_key,
        client_public_key,
    }))
}

#[cfg(test)]
#[path = "../../tests/unit/reality/auth.rs"]
mod tests;
