use std::fmt;
use std::io::{Error, ErrorKind};

use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::enums::NamedGroup;
use crate::protocol::structs::ClientHelloPayload;

pub const NAMED_GROUP_X25519: u16 = 0x001d;
pub const X25519_KEY_LEN: usize = 32;

/// TLS 1.3 server ephemeral X25519 key share for the accepted TLS session.
///
/// This is separate from REALITY auth X25519 used during ClientHello validation.
#[derive(Clone)]
pub struct Tls13ServerKeyShare {
    pub group: u16,
    pub public_key: [u8; 32],
    pub shared_secret: [u8; 32],
}

impl fmt::Debug for Tls13ServerKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13ServerKeyShare")
            .field("group", &format!("0x{:04x}", self.group))
            .field("public_key", &format!("<{} bytes>", self.public_key.len()))
            .field("shared_secret", &"<redacted>")
            .finish()
    }
}

pub fn generate_x25519_server_key_share(
    client_public_key: [u8; 32],
) -> std::io::Result<Tls13ServerKeyShare> {
    let server_secret = StaticSecret::random();
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(client_public_key);
    let shared_secret = server_secret.diffie_hellman(&client_public);

    Ok(Tls13ServerKeyShare {
        group: NAMED_GROUP_X25519,
        public_key: *server_public.as_bytes(),
        shared_secret: *shared_secret.as_bytes(),
    })
}

pub fn encode_key_share_extension_body(share: &Tls13ServerKeyShare) -> std::io::Result<Vec<u8>> {
    if share.group != NAMED_GROUP_X25519 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "unsupported TLS 1.3 key_share group: 0x{:04x} (expected X25519)",
                share.group
            ),
        ));
    }

    let mut body = Vec::with_capacity(4 + X25519_KEY_LEN);
    body.extend_from_slice(&share.group.to_be_bytes());
    body.extend_from_slice(&(X25519_KEY_LEN as u16).to_be_bytes());
    body.extend_from_slice(&share.public_key);
    Ok(body)
}

/// Extracts the client X25519 public key from a TLS 1.3 ClientHello `key_share`.
///
/// This is separate from REALITY auth key-share extraction in `reality/auth.rs`.
pub fn extract_client_x25519_key_share(
    hello: &ClientHelloPayload,
) -> std::io::Result<Option<[u8; 32]>> {
    let Some(keyshares) = hello.keyshare_extension() else {
        return Ok(None);
    };

    for keyshare in keyshares {
        if keyshare.group() != NamedGroup::X25519 {
            continue;
        }

        let payload = keyshare.payload.bytes();
        return match payload.try_into() {
            Ok(key) => Ok(Some(key)),
            Err(_) => Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "TLS 1.3 ClientHello X25519 key_exchange must be {} bytes, got {}",
                    X25519_KEY_LEN,
                    payload.len()
                ),
            )),
        };
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::enums::ProtocolVersion;
    use crate::protocol::structs::{
        ClientExtension, ClientHelloPayload, KeyShareEntry, Random, SessionId,
    };

    fn hello_with_keyshares(keyshares: Vec<KeyShareEntry>) -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random([0u8; 32]),
            session_id: SessionId::empty(),
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: vec![ClientExtension::KeyShare(keyshares)],
        }
    }

    fn hello_without_keyshare() -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random([0u8; 32]),
            session_id: SessionId::empty(),
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: Vec::new(),
        }
    }

    fn sample_client_public_key() -> [u8; 32] {
        let client_secret = StaticSecret::random();
        *PublicKey::from(&client_secret).as_bytes()
    }

    #[test]
    fn generate_x25519_server_key_share_lengths() {
        let share =
            generate_x25519_server_key_share(sample_client_public_key()).expect("valid key share");

        assert_eq!(share.group, NAMED_GROUP_X25519);
        assert_eq!(share.public_key.len(), X25519_KEY_LEN);
        assert_eq!(share.shared_secret.len(), X25519_KEY_LEN);
    }

    #[test]
    fn encode_key_share_extension_body_for_x25519() {
        let share = Tls13ServerKeyShare {
            group: NAMED_GROUP_X25519,
            public_key: [0x33; X25519_KEY_LEN],
            shared_secret: [0x44; X25519_KEY_LEN],
        };

        let body = encode_key_share_extension_body(&share).expect("valid extension body");

        assert_eq!(body.len(), 36);
        assert_eq!(&body[..4], &[0x00, 0x1d, 0x00, 0x20]);
        assert_eq!(&body[4..], &[0x33; X25519_KEY_LEN]);
    }

    #[test]
    fn debug_does_not_contain_shared_secret_bytes() {
        let share = Tls13ServerKeyShare {
            group: NAMED_GROUP_X25519,
            public_key: [0x11; X25519_KEY_LEN],
            shared_secret: [0xde; X25519_KEY_LEN],
        };

        let debug = format!("{share:?}");

        assert!(!debug.contains("222"));
        assert!(!debug.contains("0xde"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn extract_client_x25519_key_share_returns_none_without_extension() {
        let hello = hello_without_keyshare();
        let extracted = extract_client_x25519_key_share(&hello).expect("valid extraction");

        assert_eq!(extracted, None);
    }

    #[test]
    fn extract_client_x25519_key_share_returns_some_for_valid_x25519() {
        let raw: [u8; 32] = core::array::from_fn(|i| i as u8);
        let hello =
            hello_with_keyshares(vec![KeyShareEntry::new(NamedGroup::X25519, raw.to_vec())]);

        let extracted = extract_client_x25519_key_share(&hello)
            .expect("valid extraction")
            .expect("X25519 key share present");

        assert_eq!(extracted, raw);
    }

    #[test]
    fn extract_client_x25519_key_share_rejects_wrong_length() {
        let hello =
            hello_with_keyshares(vec![KeyShareEntry::new(NamedGroup::X25519, vec![0u8; 31])]);

        let err = extract_client_x25519_key_share(&hello).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn extract_client_x25519_key_share_ignores_non_x25519_groups() {
        let hello = hello_with_keyshares(vec![KeyShareEntry::new(
            NamedGroup::secp256r1,
            vec![0u8; 65],
        )]);

        let extracted = extract_client_x25519_key_share(&hello).expect("valid extraction");

        assert_eq!(extracted, None);
    }

    #[test]
    fn extract_client_x25519_key_share_prefers_x25519_among_multiple_groups() {
        let raw: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
        let hello = hello_with_keyshares(vec![
            KeyShareEntry::new(NamedGroup::secp256r1, vec![0u8; 65]),
            KeyShareEntry::new(NamedGroup::X25519, raw.to_vec()),
        ]);

        let extracted = extract_client_x25519_key_share(&hello)
            .expect("valid extraction")
            .expect("X25519 key share present");

        assert_eq!(extracted, raw);
    }
}
