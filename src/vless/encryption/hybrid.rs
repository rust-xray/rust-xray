use std::io::{Error, ErrorKind};

use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;

pub const PFS_KEY_LEN: usize = MLKEM768_SHARED_SECRET_LEN + 32;
pub const UNITED_KEY_LEN: usize = PFS_KEY_LEN + 32;

/// 64-byte PFS key: ML-KEM-768 shared secret || X25519 shared secret.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PfsKey([u8; PFS_KEY_LEN]);

impl PfsKey {
    pub fn from_parts(
        mlkem_shared: &[u8; MLKEM768_SHARED_SECRET_LEN],
        x25519_shared: &[u8; 32],
    ) -> Self {
        let mut out = [0u8; PFS_KEY_LEN];
        out[..MLKEM768_SHARED_SECRET_LEN].copy_from_slice(mlkem_shared);
        out[MLKEM768_SHARED_SECRET_LEN..].copy_from_slice(x25519_shared);
        Self(out)
    }

    pub fn as_bytes(&self) -> &[u8; PFS_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for PfsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<pfs key>")
    }
}

/// 96-byte united key: PFS key || NFS relay key.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct UnitedKey([u8; UNITED_KEY_LEN]);

impl UnitedKey {
    pub fn from_parts(pfs: &PfsKey, nfs_shared: &[u8; 32]) -> Self {
        let mut out = [0u8; UNITED_KEY_LEN];
        out[..PFS_KEY_LEN].copy_from_slice(pfs.as_bytes());
        out[PFS_KEY_LEN..].copy_from_slice(nfs_shared);
        Self(out)
    }

    pub fn as_bytes(&self) -> &[u8; UNITED_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for UnitedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<united key>")
    }
}

pub fn compose_pfs_key(
    mlkem_shared: &[u8; MLKEM768_SHARED_SECRET_LEN],
    x25519_shared: &[u8; 32],
) -> PfsKey {
    PfsKey::from_parts(mlkem_shared, x25519_shared)
}

pub fn compose_united_key(pfs: &PfsKey, nfs_shared: &[u8; 32]) -> UnitedKey {
    UnitedKey::from_parts(pfs, nfs_shared)
}

/// Encode 16-bit length prefix used throughout VLESS Encryption handshake records.
pub fn encode_length(value: u16) -> [u8; 2] {
    [(value >> 8) as u8, value as u8]
}

/// Decode 16-bit length prefix.
pub fn decode_length(bytes: &[u8; 2]) -> u16 {
    u16::from_be_bytes(*bytes)
}

/// Validate ticket lifetime seconds encoded in ticket prefix (upstream `EncodeLength`).
pub fn encode_ticket_lifetime_seconds(seconds: u64) -> Result<[u8; 2], Error> {
    let value = u16::try_from(seconds).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("ticket lifetime seconds out of range: {seconds}"),
        )
    })?;
    Ok(encode_length(value))
}
