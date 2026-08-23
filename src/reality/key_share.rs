//! REALITY pre-auth key_share constants and peer X25519 extraction.
//!
//! Hybrid ML-KEM layout is parsed for auth only; no ML-KEM cryptography is performed.
//! TLS 1.3 accepted-path key exchange remains in `reality/tls13/key_share.rs`.

use crate::protocol::enums::NamedGroup;
use crate::protocol::structs::KeyShareEntry;

/// TLS NamedGroup: X25519 (RFC 8446).
pub const NAMED_GROUP_X25519: u16 = 0x001d;

/// TLS NamedGroup: X25519MLKEM768 (hybrid KEX, draft/RFC).
pub const NAMED_GROUP_X25519MLKEM768: u16 = 0x11ec;

/// X25519 public key length in bytes.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// ML-KEM-768 encapsulation key length in client hybrid key_share (opaque to REALITY auth).
pub const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;

/// ClientHello X25519MLKEM768 key_exchange length: encapsulation key + X25519 public key.
pub const X25519_MLKEM768_CLIENT_KEY_SHARE_LEN: usize =
    MLKEM768_ENCAPSULATION_KEY_LEN + X25519_PUBLIC_KEY_LEN;

const fn invalid_public_key_len(len: usize) -> bool {
    len != X25519_PUBLIC_KEY_LEN
}

/// Returns true when `group` is X25519MLKEM768 (`0x11ec`), including `Unknown(4588)`.
pub fn is_x25519mlkem768_group(group: NamedGroup) -> bool {
    u16::from(group) == NAMED_GROUP_X25519MLKEM768
}

fn standalone_x25519_public_key(payload: &[u8]) -> Option<[u8; X25519_PUBLIC_KEY_LEN]> {
    if invalid_public_key_len(payload.len()) {
        return None;
    }
    payload.try_into().ok()
}

fn hybrid_x25519_public_key(payload: &[u8]) -> Option<[u8; X25519_PUBLIC_KEY_LEN]> {
    if payload.len() != X25519_MLKEM768_CLIENT_KEY_SHARE_LEN {
        return None;
    }
    payload[MLKEM768_ENCAPSULATION_KEY_LEN..].try_into().ok()
}

/// Upstream REALITY pre-auth peer X25519 selection (two-pass).
///
/// Pass 1: standalone `X25519` entry with exactly 32-byte key_exchange.
/// Pass 2: `X25519MLKEM768` entry with exactly 1216-byte key_exchange; returns trailing 32 bytes.
pub fn find_reality_auth_x25519_public_key(
    keyshares: &[KeyShareEntry],
) -> Option<[u8; X25519_PUBLIC_KEY_LEN]> {
    for keyshare in keyshares {
        if u16::from(keyshare.group) != NAMED_GROUP_X25519 {
            continue;
        }
        if let Some(key) = standalone_x25519_public_key(keyshare.payload.bytes()) {
            return Some(key);
        }
    }

    for keyshare in keyshares {
        if !is_x25519mlkem768_group(keyshare.group) {
            continue;
        }
        if let Some(key) = hybrid_x25519_public_key(keyshare.payload.bytes()) {
            return Some(key);
        }
    }

    None
}

/// Builds a client hybrid key_share payload: opaque ML-KEM prefix + trailing X25519 public key.
pub fn build_x25519mlkem768_client_key_share(
    x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
) -> Vec<u8> {
    let mut payload = vec![0u8; MLKEM768_ENCAPSULATION_KEY_LEN];
    payload.extend_from_slice(&x25519_public_key);
    debug_assert_eq!(payload.len(), X25519_MLKEM768_CLIENT_KEY_SHARE_LEN);
    payload
}

#[cfg(test)]
#[path = "../../tests/unit/reality/key_share.rs"]
mod tests;
