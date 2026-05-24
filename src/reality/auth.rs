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
mod tests {
    use super::*;
    use crate::codec::Codec;
    use crate::protocol::enums::ProtocolVersion;
    use crate::protocol::structs::{ClientExtension, ClientHelloPayload, Random, SessionId};

    fn hello_with_x25519_keyshare(payload: Vec<u8>) -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random([0u8; 32]),
            session_id: SessionId::empty(),
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: vec![ClientExtension::KeyShare(vec![KeyShareEntry::new(
                NamedGroup::X25519,
                payload,
            )])],
        }
    }

    #[test]
    fn extract_x25519_keyshare_returns_raw_32_bytes() {
        let raw: [u8; 32] = core::array::from_fn(|i| i as u8);
        let hello = hello_with_x25519_keyshare(raw.to_vec());

        let extracted = extract_x25519_keyshare(&hello).expect("valid X25519 keyshare");

        assert_eq!(extracted, raw);
    }

    #[test]
    fn extract_x25519_keyshare_rejects_get_encoding_prefix_mistake() {
        let raw: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
        let hello = hello_with_x25519_keyshare(raw.to_vec());
        let keyshare = hello.keyshare_extension().unwrap().first().unwrap();

        let extracted = extract_x25519_keyshare(&hello).expect("valid X25519 keyshare");
        let wrong_via_get_encoding = &keyshare.payload.get_encoding()[..32];

        assert_eq!(extracted, raw);
        assert_ne!(extracted.as_slice(), wrong_via_get_encoding);
        assert_eq!(keyshare.payload.get_encoding().len(), 34);
    }

    #[test]
    fn extract_x25519_keyshare_rejects_non_32_byte_payload() {
        let payload = vec![0u8; 34];
        let hello = hello_with_x25519_keyshare(payload);

        assert!(extract_x25519_keyshare(&hello).is_none());
    }

    #[test]
    fn reality_auth_result_debug_redacts_sensitive_fields() {
        let auth = RealityAuthResult {
            auth_key: [7u8; 32],
            client_public_key: [9u8; 32],
        };

        let debug = format!("{auth:?}");

        assert!(debug.contains("auth_key"));
        assert!(debug.contains("client_public_key"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("[7, 7, 7"));
        assert!(!debug.contains("[9, 9, 9"));
    }
}
