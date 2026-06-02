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
#[path = "../../../tests/unit/reality/tls13/key_share.rs"]
mod tests;
