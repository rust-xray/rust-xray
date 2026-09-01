use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

use super::kdf::derive_ctr_key;

type Aes256Ctr = Ctr128BE<Aes256>;

/// CTR stream matching upstream `NewCTR(key, iv)` with Blake3 `"VLESS"` context.
pub struct CtrStream {
    cipher: Aes256Ctr,
}

impl CtrStream {
    pub fn new(united_key: &[u8], iv: &[u8; 16]) -> Self {
        let key = derive_ctr_key(united_key);
        let cipher = Aes256Ctr::new(key.as_slice().into(), iv.as_slice().into());
        Self { cipher }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

/// In-place XOR obfuscation (xorpub/random modes) — not authentication.
pub fn ctr_xor(united_key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
    let mut stream = CtrStream::new(united_key, iv);
    stream.apply_keystream(data);
}

/// Apply upstream relay-chain XOR for intermediate hash verification bytes.
pub fn xor_relay_hash(relay: &mut [u8], expected_hash: &[u8; 32], iv: &[u8; 16], nfs_key: &[u8]) {
    let mut stream = CtrStream::new(nfs_key, iv);
    stream.apply_keystream(relay);
    if relay.len() >= 32 && &relay[..32] != expected_hash {
        // Caller validates equality; this helper only applies the keystream.
    }
}
