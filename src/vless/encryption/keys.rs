use std::fmt;

use std::hash::{Hash, Hasher};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size secret material with redacted `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretBytes<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Hash for SecretBytes<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("<secret {N} bytes>"))
    }
}

/// Parsed NFS static key material for VLESS Encryption relay chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NfsStaticKey {
    /// 32-byte X25519 private key.
    X25519(SecretBytes<32>),
    /// ML-KEM-768 decapsulation key bytes (64-byte seed form accepted by upstream config).
    MlKem768Decapsulation(SecretBytes<64>),
}

impl NfsStaticKey {
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::X25519(_) => "x25519",
            Self::MlKem768Decapsulation(_) => "mlkem768",
        }
    }

    /// Upstream NFS public key bytes (`NfsPKeysBytes`) used for xorpub/random CTR.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, KeyMaterialError> {
        match self {
            Self::X25519(secret) => {
                let public = super::x25519::x25519_public_key(
                    &super::x25519::X25519SecretKey::from_bytes(*secret.as_bytes()),
                );
                Ok(public.as_bytes().to_vec())
            }
            Self::MlKem768Decapsulation(seed) => {
                use ml_kem::ml_kem_768::MlKem768;
                use ml_kem::{FromSeed, KeyExport, Seed};
                let seed = Seed::from(*seed.as_bytes());
                let (_, ek) = MlKem768::from_seed(&seed);
                Ok(ek.to_bytes().to_vec())
            }
        }
    }
}

/// Blake3-256 hash of NFS public key material (upstream `Hash32s`).
pub fn nfs_public_key_hash(public_key_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(public_key_bytes).as_bytes()
}

/// Inbound decryption accepts 32- or 64-byte decoded NFS keys.
pub(crate) fn nfs_inbound_key_from_bytes(bytes: Vec<u8>) -> Result<NfsStaticKey, KeyMaterialError> {
    match bytes.len() {
        32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(NfsStaticKey::X25519(SecretBytes::new(arr)))
        }
        64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(NfsStaticKey::MlKem768Decapsulation(SecretBytes::new(arr)))
        }
        other => Err(KeyMaterialError::InvalidLength {
            expected: "32 or 64",
            actual: other,
        }),
    }
}

/// Outbound encryption accepts 32-byte X25519 public keys or 1184-byte ML-KEM encapsulation keys.
pub(crate) fn nfs_outbound_key_from_bytes(
    bytes: Vec<u8>,
) -> Result<OutboundNfsKey, KeyMaterialError> {
    match bytes.len() {
        32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(OutboundNfsKey::X25519Public(arr))
        }
        1184 => {
            let mut arr = [0u8; 1184];
            arr.copy_from_slice(&bytes);
            Ok(OutboundNfsKey::MlKem768Encapsulation(arr))
        }
        other => Err(KeyMaterialError::InvalidLength {
            expected: "32 or 1184",
            actual: other,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundNfsKey {
    X25519Public([u8; 32]),
    MlKem768Encapsulation([u8; 1184]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterialError {
    InvalidBase64,
    InvalidLength {
        expected: &'static str,
        actual: usize,
    },
    EmptyKeyChain,
}

impl fmt::Display for KeyMaterialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBase64 => f.write_str("invalid base64url NFS key material"),
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid NFS key length: expected {expected}, got {actual}"
                )
            }
            Self::EmptyKeyChain => f.write_str("VLESS encryption key chain must not be empty"),
        }
    }
}

impl std::error::Error for KeyMaterialError {}

pub(crate) fn decode_base64url_key(token: &str) -> Result<Vec<u8>, KeyMaterialError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| KeyMaterialError::InvalidBase64)
}
