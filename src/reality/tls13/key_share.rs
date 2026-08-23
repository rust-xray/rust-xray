use std::fmt;
use std::io::{Error, ErrorKind};

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::protocol::enums::NamedGroup;
use crate::protocol::structs::ClientHelloPayload;
use crate::reality::key_share::{
    MLKEM768_ENCAPSULATION_KEY_LEN, MLKEM768_SHARED_SECRET_LEN, NAMED_GROUP_X25519MLKEM768,
    X25519_MLKEM768_CLIENT_KEY_SHARE_LEN, X25519_MLKEM768_SERVER_KEY_SHARE_LEN,
    X25519_MLKEM768_SHARED_SECRET_LEN, X25519_PUBLIC_KEY_LEN,
};
use crate::reality::mlkem768::encapsulate_mlkem768;

pub const NAMED_GROUP_X25519: u16 = 0x001d;
pub const X25519_KEY_LEN: usize = X25519_PUBLIC_KEY_LEN;

/// TLS 1.3 server key share for the accepted REALITY path.
///
/// `key_exchange` is the TLS wire payload (32-byte X25519 or 1120-byte hybrid).
/// `shared_secret` is the ECDHE input to the TLS 1.3 key schedule (32 or 64 bytes).
pub struct Tls13ServerKeyShare {
    pub group: u16,
    pub key_exchange: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
}

impl Tls13ServerKeyShare {
    pub fn key_exchange(&self) -> &[u8] {
        &self.key_exchange
    }

    pub fn shared_secret(&self) -> &[u8] {
        self.shared_secret.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        group: u16,
        key_exchange: Vec<u8>,
        shared_secret: Vec<u8>,
    ) -> Self {
        Self {
            group,
            key_exchange,
            shared_secret: Zeroizing::new(shared_secret),
        }
    }
}

impl fmt::Debug for Tls13ServerKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13ServerKeyShare")
            .field("group", &format!("0x{:04x}", self.group))
            .field(
                "key_exchange",
                &format!("<{} bytes>", self.key_exchange.len()),
            )
            .field("shared_secret", &"<redacted>")
            .finish()
    }
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}

pub fn generate_x25519_server_key_share(
    client_public_key: [u8; X25519_KEY_LEN],
) -> std::io::Result<Tls13ServerKeyShare> {
    let server_secret = StaticSecret::random();
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(client_public_key);
    let shared_secret = server_secret.diffie_hellman(&client_public);

    Ok(Tls13ServerKeyShare {
        group: NAMED_GROUP_X25519,
        key_exchange: server_public.as_bytes().to_vec(),
        shared_secret: Zeroizing::new(shared_secret.as_bytes().to_vec()),
    })
}

/// Generates an X25519MLKEM768 server key share from a 1216-byte client hybrid share.
pub fn generate_x25519mlkem768_server_key_share(
    client_hybrid_share: &[u8],
) -> std::io::Result<Tls13ServerKeyShare> {
    if client_hybrid_share.len() != X25519_MLKEM768_CLIENT_KEY_SHARE_LEN {
        return Err(invalid_input(format!(
            "TLS 1.3 X25519MLKEM768 client key_share must be {} bytes, got {}",
            X25519_MLKEM768_CLIENT_KEY_SHARE_LEN,
            client_hybrid_share.len()
        )));
    }

    let mlkem_ek = &client_hybrid_share[..MLKEM768_ENCAPSULATION_KEY_LEN];
    let client_x25519_bytes: [u8; X25519_KEY_LEN] = client_hybrid_share
        [MLKEM768_ENCAPSULATION_KEY_LEN..]
        .try_into()
        .map_err(|_| {
            invalid_data(format!(
                "TLS 1.3 X25519MLKEM768 client X25519 component must be {} bytes",
                X25519_KEY_LEN
            ))
        })?;

    let encapsulation = encapsulate_mlkem768(mlkem_ek)?;

    let server_secret = StaticSecret::random();
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(client_x25519_bytes);
    let x25519_shared = server_secret.diffie_hellman(&client_public);

    let mut tls_shared = Zeroizing::new(vec![0u8; X25519_MLKEM768_SHARED_SECRET_LEN]);
    tls_shared[..MLKEM768_SHARED_SECRET_LEN].copy_from_slice(encapsulation.shared_secret());
    tls_shared[MLKEM768_SHARED_SECRET_LEN..].copy_from_slice(x25519_shared.as_bytes());

    let mut key_exchange = Vec::with_capacity(X25519_MLKEM768_SERVER_KEY_SHARE_LEN);
    key_exchange.extend_from_slice(&encapsulation.ciphertext);
    key_exchange.extend_from_slice(server_public.as_bytes());
    debug_assert_eq!(key_exchange.len(), X25519_MLKEM768_SERVER_KEY_SHARE_LEN);

    Ok(Tls13ServerKeyShare {
        group: NAMED_GROUP_X25519MLKEM768,
        key_exchange,
        shared_secret: tls_shared,
    })
}

pub fn encode_key_share_extension_body(share: &Tls13ServerKeyShare) -> std::io::Result<Vec<u8>> {
    let expected_len = match share.group {
        NAMED_GROUP_X25519 => X25519_KEY_LEN,
        NAMED_GROUP_X25519MLKEM768 => X25519_MLKEM768_SERVER_KEY_SHARE_LEN,
        other => {
            return Err(invalid_input(format!(
                "unsupported TLS 1.3 key_share group: 0x{other:04x}"
            )));
        }
    };

    if share.key_exchange.len() != expected_len {
        return Err(invalid_data(format!(
            "TLS 1.3 key_share group 0x{:04x} key_exchange must be {expected_len} bytes, got {}",
            share.group,
            share.key_exchange.len()
        )));
    }

    let mut body = Vec::with_capacity(4 + share.key_exchange.len());
    body.extend_from_slice(&share.group.to_be_bytes());
    body.extend_from_slice(&(share.key_exchange.len() as u16).to_be_bytes());
    body.extend_from_slice(&share.key_exchange);
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

/// Extracts the client X25519MLKEM768 hybrid key_share payload when present.
pub fn extract_client_x25519mlkem768_hybrid_key_share(
    hello: &ClientHelloPayload,
) -> std::io::Result<Option<Vec<u8>>> {
    let Some(keyshares) = hello.keyshare_extension() else {
        return Ok(None);
    };

    for keyshare in keyshares {
        if u16::from(keyshare.group()) != NAMED_GROUP_X25519MLKEM768 {
            continue;
        }

        let payload = keyshare.payload.bytes();
        if payload.len() != X25519_MLKEM768_CLIENT_KEY_SHARE_LEN {
            return Err(invalid_data(format!(
                "TLS 1.3 ClientHello X25519MLKEM768 key_exchange must be {} bytes, got {}",
                X25519_MLKEM768_CLIENT_KEY_SHARE_LEN,
                payload.len()
            )));
        }
        return Ok(Some(payload.to_vec()));
    }

    Ok(None)
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/key_share.rs"]
mod tests;
