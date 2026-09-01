//! Secret lifetime and zeroization regression tests.

use zeroize::Zeroize;

use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
use crate::vless::encryption::hybrid::{compose_pfs_key, compose_united_key, PfsKey, UnitedKey};
use crate::vless::encryption::keys::SecretBytes;

#[test]
fn pfs_key_zeroizes_on_drop() {
    let mut mlkem = [0x11u8; MLKEM768_SHARED_SECRET_LEN];
    let mut x25519 = [0x22u8; 32];
    let key = compose_pfs_key(&mlkem, &x25519);
    let mut material = *key.as_bytes();
    drop(key);
    material.zeroize();
    assert!(material.iter().all(|b| *b == 0));
}

#[test]
fn united_key_zeroizes_explicitly() {
    let pfs = compose_pfs_key(&[0x33u8; MLKEM768_SHARED_SECRET_LEN], &[0x44u8; 32]);
    let united = compose_united_key(&pfs, &[0x55u8; 32]);
    let mut copy = *united.as_bytes();
    copy.zeroize();
    assert!(copy.iter().all(|b| *b == 0));
}

#[test]
fn secret_bytes_zeroizes_on_drop() {
    let secret = SecretBytes::new([0x66u8; 32]);
    let leaked = *secret.as_bytes();
    drop(secret);
    let mut scrub = leaked;
    scrub.zeroize();
    assert!(scrub.iter().all(|b| *b == 0));
}

#[test]
fn pfs_key_debug_redacted() {
    let key = PfsKey::from_parts(&[0u8; MLKEM768_SHARED_SECRET_LEN], &[0u8; 32]);
    assert_eq!(format!("{key:?}"), "<pfs key>");
}

#[test]
fn united_key_debug_redacted() {
    let pfs = PfsKey::from_parts(&[0u8; MLKEM768_SHARED_SECRET_LEN], &[0u8; 32]);
    let united = UnitedKey::from_parts(&pfs, &[0u8; 32]);
    assert_eq!(format!("{united:?}"), "<united key>");
}
