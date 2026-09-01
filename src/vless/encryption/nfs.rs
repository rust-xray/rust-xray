use super::config::{Mlkem768X25519PlusConfig, XorMode};
use super::handshake::HandshakeError;
use super::keys::{nfs_public_key_hash, NfsStaticKey};
use super::x25519::{validate_x25519_public_key, x25519_ecdh, X25519PublicKey, X25519SecretKey};
use super::xor::CtrStream;
use super::{decapsulate_mlkem768, SecretBytes};
use crate::reality::key_share::MLKEM768_CIPHERTEXT_LEN;

/// Prepared inbound NFS relay chain (upstream `ServerInstance` static fields).
#[derive(Debug, Clone)]
pub struct NfsServerChain {
    keys: Vec<NfsStaticKey>,
    public_keys: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    xor_mode: XorMode,
}

impl NfsServerChain {
    pub fn from_config(config: &Mlkem768X25519PlusConfig) -> Result<Self, HandshakeError> {
        if config.nfs_keys.is_empty() {
            return Err(HandshakeError::Malformed("empty NFS key chain"));
        }
        let mut public_keys = Vec::with_capacity(config.nfs_keys.len());
        let mut hash32s = Vec::with_capacity(config.nfs_keys.len());
        let mut relays_length = 0usize;
        for key in &config.nfs_keys {
            let public = key
                .public_key_bytes()
                .map_err(|_| HandshakeError::Malformed("invalid NFS public key material"))?;
            hash32s.push(nfs_public_key_hash(&public));
            relays_length = relays_length
                .saturating_add(relay_material_len(key))
                .saturating_add(32);
            public_keys.push(public);
        }
        relays_length = relays_length.saturating_sub(32);
        Ok(Self {
            keys: config.nfs_keys.clone(),
            public_keys,
            hash32s,
            relays_length,
            xor_mode: config.xor_mode,
        })
    }

    pub fn xor_mode(&self) -> XorMode {
        self.xor_mode
    }

    pub fn relays_length(&self) -> usize {
        self.relays_length
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Process client relay material and derive the final 32-byte NFS shared secret.
    pub fn derive_nfs_key(
        &self,
        iv: &[u8; super::handshake::IV_LEN],
        relays: &mut [u8],
    ) -> Result<SecretBytes<32>, HandshakeError> {
        if relays.len() != self.relays_length {
            return Err(HandshakeError::Malformed("unexpected NFS relay length"));
        }

        let mut nfs_key = [0u8; 32];
        let mut last_ctr_key: Option<[u8; 32]> = None;
        let mut offset = 0usize;

        for (index, key) in self.keys.iter().enumerate() {
            if let Some(prev_key) = last_ctr_key {
                let mut stream = CtrStream::new(&prev_key, iv);
                stream.apply_keystream(&mut relays[offset..offset + 32]);
            }

            let material_len = relay_material_len(key);
            if offset + material_len > relays.len() {
                return Err(HandshakeError::Truncated);
            }

            if self.xor_mode != XorMode::Native {
                let mut stream = CtrStream::new(&self.public_keys[index], iv);
                stream.apply_keystream(&mut relays[offset..offset + material_len]);
            }

            nfs_key = match key {
                NfsStaticKey::X25519(secret) => {
                    let peer = X25519PublicKey::from_bytes({
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&relays[offset..offset + 32]);
                        arr
                    })
                    .map_err(|_| HandshakeError::AuthenticationFailed)?;
                    validate_x25519_public_key(peer.as_bytes())
                        .map_err(|_| HandshakeError::AuthenticationFailed)?;
                    x25519_ecdh(&X25519SecretKey::from_bytes(*secret.as_bytes()), &peer)
                        .map_err(|_| HandshakeError::CryptoFailure("X25519 ECDH failed"))?
                }
                NfsStaticKey::MlKem768Decapsulation(seed) => {
                    let mut ct = [0u8; MLKEM768_CIPHERTEXT_LEN];
                    ct.copy_from_slice(&relays[offset..offset + MLKEM768_CIPHERTEXT_LEN]);
                    *decapsulate_mlkem768(seed.as_bytes(), &ct)
                        .map_err(|_| HandshakeError::AuthenticationFailed)?
                        .as_bytes()
                }
            };

            if index == self.keys.len() - 1 {
                break;
            }

            offset += material_len;
            last_ctr_key = Some(nfs_key);

            let mut stream = CtrStream::new(&nfs_key, iv);
            stream.apply_keystream(&mut relays[offset..offset + 32]);
            if relays[offset..offset + 32] != self.hash32s[index + 1] {
                return Err(HandshakeError::AuthenticationFailed);
            }
            offset += 32;
        }

        Ok(SecretBytes::new(nfs_key))
    }
}

fn relay_material_len(key: &NfsStaticKey) -> usize {
    match key {
        NfsStaticKey::X25519(_) => 32,
        NfsStaticKey::MlKem768Decapsulation(_) => MLKEM768_CIPHERTEXT_LEN,
    }
}
