use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::enums::{NamedGroup, ProtocolVersion};
use crate::structs::{ClientHelloPayload, KeyShareEntry, ServerNamePayload};

#[derive(Debug)]
pub struct RealityAuthResult {
    pub auth_key: [u8; 42],
    pub client_public_key: [u8; 32],
}

pub enum RealityDecision {
    Accepted(RealityAuthResult),
    Fallback,
}

pub struct RealityClientAuth {
    pub short_id: Vec<u8>,
    pub unix_time: u64,
}

/// Minimum TLS Session ID length used by REALITY clients (32-byte AES-GCM ciphertext).
const REALITY_SESSION_ID_LEN: usize = 32;

pub fn log_client_hello_diagnostics(hello: &ClientHelloPayload) {
    match hello.sni_extension() {
        Some(names) => {
            let hostnames = names
                .iter()
                .filter_map(|name| match &name.payload {
                    ServerNamePayload::HostName(dns) => Some(dns.as_ref().to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if hostnames.is_empty() {
                debug!(
                    count = names.len(),
                    "SNI extension found without DNS hostnames"
                );
            } else {
                debug!(?hostnames, "SNI extension found");
            }
        }
        None => debug!("SNI extension missing"),
    }

    match hello.versions_extension() {
        Some(versions) if versions.contains(&ProtocolVersion::TLSv1_3) => {
            debug!("TLS 1.3 supported in supported_versions");
        }
        Some(_) => debug!("TLS 1.3 unsupported in supported_versions"),
        None => debug!("supported_versions extension missing"),
    }

    match extract_x25519_keyshare(hello) {
        Some(_) => debug!("X25519 keyshare found"),
        None => debug!("X25519 keyshare missing or invalid length"),
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

pub fn extract_x25519_keyshare(hello: &ClientHelloPayload) -> Option<[u8; 32]> {
    let keyshares = hello.keyshare_extension()?;
    find_x25519_public_key(keyshares)
}

pub fn derive_reality_auth_key(
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
    let mut auth_key = [0u8; 42];
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

pub fn open_reality_session_id(
    hello: &ClientHelloPayload,
    raw_client_hello_payload: &[u8],
    auth_key: &[u8; 42],
) -> std::io::Result<Option<RealityClientAuth>> {
    let session_id = hello.session_id.as_bytes();

    if session_id.len() < REALITY_SESSION_ID_LEN {
        debug!(
            len = session_id.len(),
            "REALITY session_id open skipped: session_id too short"
        );
        return Ok(None);
    }

    let _ = (raw_client_hello_payload, auth_key, &hello.random.0);

    // TODO: Port AES-GCM open 1:1 from XTLS/REALITY `tls.go` (server path, ~lines 236–249):
    //
    //   block, _ := aes.NewCipher(authKey)          // AES-256 key from HKDF output
    //   aead, _ := cipher.NewGCM(block)
    //   aead.Open(plainText[:0], hello.random[20:32], sessionIdCiphertext, hello.original)
    //
    // Wire parameters (must match Go exactly before returning Some):
    //   - nonce  = ClientHello.random bytes [20..32]
    //   - aad    = raw ClientHello bytes (`hello.original` / `raw_client_hello_payload`)
    //   - input  = session_id ciphertext (32 bytes)
    //   - key    = HKDF-derived AuthKey (verify 32 vs 42 byte split against Go)
    //
    // Plaintext layout after successful open:
    //   [0..3]   client version (x.y.z)
    //   [4..7]   unix timestamp (big-endian u32)
    //   [8..15]  short_id (up to 8 bytes)
    //
    // Do not guess nonce, AAD, or key slicing here.

    warn!("REALITY session_id open not implemented yet");
    Ok(None)
}

pub fn inspect_reality_client_hello(
    hello: &ClientHelloPayload,
    raw_client_hello_payload: &[u8],
    server_private_key_b64: &str,
) -> std::io::Result<RealityDecision> {
    log_client_hello_diagnostics(hello);

    let Some(auth) = derive_reality_auth_key(hello, server_private_key_b64)? else {
        return Ok(RealityDecision::Fallback);
    };

    match open_reality_session_id(hello, raw_client_hello_payload, &auth.auth_key)? {
        Some(_client_auth) => {
            debug!("REALITY session_id open ok");
            Ok(RealityDecision::Accepted(auth))
        }
        None => {
            warn!("REALITY session_id open failed or not implemented");
            Ok(RealityDecision::Fallback)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Codec;
    use crate::enums::ProtocolVersion;
    use crate::structs::{ClientExtension, ClientHelloPayload, Random, SessionId};

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
}
