use std::io::{Error, ErrorKind};

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::reality::key_share::X25519_PUBLIC_KEY_LEN;

/// X25519 secret key wrapper.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct X25519SecretKey([u8; 32]);

impl X25519SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<x25519 secret>")
    }
}

/// X25519 public key wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        validate_x25519_public_key(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive X25519 public key from a 32-byte private key.
pub fn x25519_public_key(secret: &X25519SecretKey) -> X25519PublicKey {
    let static_secret = StaticSecret::from(*secret.as_bytes());
    let public = PublicKey::from(&static_secret);
    X25519PublicKey(*public.as_bytes())
}

/// ECDH shared secret for local private key and peer public key.
pub fn x25519_ecdh(secret: &X25519SecretKey, peer: &X25519PublicKey) -> Result<[u8; 32], Error> {
    validate_x25519_public_key(peer.as_bytes())?;
    let static_secret = StaticSecret::from(*secret.as_bytes());
    let public = PublicKey::from(*peer.as_bytes());
    Ok(*static_secret.diffie_hellman(&public).as_bytes())
}

/// Upstream rejects peer X25519 public keys whose last byte has bit 7 set.
pub fn validate_x25519_public_key(public: &[u8; 32]) -> Result<(), Error> {
    if public[31] > 127 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "the highest bit of the last byte of the peer-sent X25519 public key is not 0",
        ));
    }
    Ok(())
}

pub fn validate_x25519_public_key_slice(public: &[u8]) -> Result<[u8; 32], Error> {
    if public.len() != X25519_PUBLIC_KEY_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "X25519 public key must be {X25519_PUBLIC_KEY_LEN} bytes, got {}",
                public.len()
            ),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(public);
    validate_x25519_public_key(&arr)?;
    Ok(arr)
}
