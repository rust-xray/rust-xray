use std::io::{Error, ErrorKind};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use chacha20poly1305::ChaCha20Poly1305;

use super::kdf::derive_blake3_key;
use super::nonce::{increase_nonce, is_max_nonce, NonceCounter, MAX_NONCE};

const AEAD_KEY_LEN: usize = 32;
const AEAD_NONCE_LEN: usize = 12;
const AEAD_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficAeadKind {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Stateful traffic AEAD matching upstream `encryption.AEAD`.
pub struct TrafficAead {
    kind: TrafficAeadKind,
    key: [u8; AEAD_KEY_LEN],
    united_key: [u8; super::hybrid::UNITED_KEY_LEN],
    nonce: NonceCounter,
}

impl TrafficAead {
    /// Create AEAD from context label and united key (upstream `NewAEAD`).
    pub fn new(context: &[u8], united_key: &[u8], prefer_aes: bool) -> Self {
        let mut key = [0u8; AEAD_KEY_LEN];
        derive_blake3_key(&mut key, context, united_key);
        let mut united = [0u8; super::hybrid::UNITED_KEY_LEN];
        let copy_len = united_key.len().min(united.len());
        united[..copy_len].copy_from_slice(&united_key[..copy_len]);
        Self {
            kind: if prefer_aes {
                TrafficAeadKind::Aes256Gcm
            } else {
                TrafficAeadKind::ChaCha20Poly1305
            },
            key,
            united_key: united,
            nonce: NonceCounter::new(),
        }
    }

    pub fn kind(&self) -> TrafficAeadKind {
        self.kind
    }

    pub fn set_kind(&mut self, kind: TrafficAeadKind) {
        self.kind = kind;
    }

    pub fn nonce(&self) -> &NonceCounter {
        &self.nonce
    }

    /// Test-only: set stored nonce counter (stream MaxNonce matrix).
    #[cfg(test)]
    pub fn set_nonce_for_test(&mut self, nonce: [u8; 12]) {
        *self.nonce.as_mut_bytes() = nonce;
    }

    /// Encrypt plaintext with AAD; returns ciphertext including tag.
    pub fn seal(&mut self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buffer = plaintext.to_vec();
        let total = self.seal_in_place(&mut buffer, additional_data)?;
        buffer.truncate(total);
        Ok(buffer)
    }

    pub fn seal_in_place(
        &mut self,
        buffer: &mut Vec<u8>,
        additional_data: &[u8],
    ) -> Result<usize, Error> {
        let plaintext_len = buffer.len();
        buffer.resize(plaintext_len + AEAD_TAG_LEN, 0);
        let rotate = is_max_nonce(self.nonce.as_bytes());
        increase_nonce(self.nonce.as_mut_bytes());
        let nonce_bytes = *self.nonce.as_bytes();
        let total = match self.kind {
            TrafficAeadKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid AES-GCM key"))?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                let tag = cipher
                    .encrypt_in_place_detached(nonce, additional_data, &mut buffer[..plaintext_len])
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AES-GCM seal failed"))?;
                buffer[plaintext_len..plaintext_len + AEAD_TAG_LEN].copy_from_slice(&tag);
                plaintext_len + AEAD_TAG_LEN
            }
            TrafficAeadKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "invalid ChaCha20-Poly1305 key")
                })?;
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                let tag = cipher
                    .encrypt_in_place_detached(nonce, additional_data, &mut buffer[..plaintext_len])
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidData, "ChaCha20-Poly1305 seal failed")
                    })?;
                buffer[plaintext_len..plaintext_len + AEAD_TAG_LEN].copy_from_slice(&tag);
                plaintext_len + AEAD_TAG_LEN
            }
        };
        if rotate {
            self.rotate_from_context(&buffer[..total]);
        }
        Ok(total)
    }

    pub fn open(
        &mut self,
        ciphertext_with_tag: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if ciphertext_with_tag.len() < AEAD_TAG_LEN {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "ciphertext shorter than AEAD tag",
            ));
        }
        let ciphertext_len = ciphertext_with_tag.len() - AEAD_TAG_LEN;
        let mut buffer = ciphertext_with_tag.to_vec();
        let plaintext_len = self.open_in_place(&mut buffer, ciphertext_len, additional_data)?;
        buffer.truncate(plaintext_len);
        Ok(buffer)
    }

    pub fn open_in_place(
        &mut self,
        buffer: &mut [u8],
        ciphertext_len: usize,
        additional_data: &[u8],
    ) -> Result<usize, Error> {
        if ciphertext_len + AEAD_TAG_LEN > buffer.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "ciphertext length exceeds buffer",
            ));
        }
        let rotate = is_max_nonce(self.nonce.as_bytes());
        increase_nonce(self.nonce.as_mut_bytes());
        let nonce_bytes = *self.nonce.as_bytes();
        match self.kind {
            TrafficAeadKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid AES-GCM key"))?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                let (ciphertext, tag_slice) = buffer.split_at_mut(ciphertext_len);
                let tag = Tag::from_slice(&tag_slice[..AEAD_TAG_LEN]);
                cipher
                    .decrypt_in_place_detached(nonce, additional_data, ciphertext, tag)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AES-GCM open failed"))?;
            }
            TrafficAeadKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "invalid ChaCha20-Poly1305 key")
                })?;
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                let (ciphertext, tag_slice) = buffer.split_at_mut(ciphertext_len);
                let tag = chacha20poly1305::Tag::from_slice(&tag_slice[..AEAD_TAG_LEN]);
                cipher
                    .decrypt_in_place_detached(nonce, additional_data, ciphertext, tag)
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidData, "ChaCha20-Poly1305 open failed")
                    })?;
            }
        }
        if rotate {
            self.rotate_from_context(&buffer[..ciphertext_len + AEAD_TAG_LEN]);
        }
        Ok(ciphertext_len)
    }

    /// Rotate AEAD using post-max-nonce context (upstream `NewAEAD` after MaxNonce).
    pub fn rotate_from_context(&mut self, rotation_context: &[u8]) {
        derive_blake3_key(&mut self.key, rotation_context, &self.united_key);
        *self.nonce.as_mut_bytes() = [0u8; AEAD_NONCE_LEN];
    }

    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut buffer = plaintext.to_vec();
        buffer.resize(plaintext.len() + AEAD_TAG_LEN, 0);
        self.seal_in_place_with_nonce(nonce, &mut buffer, additional_data)?;
        Ok(buffer)
    }

    pub fn seal_in_place_with_nonce(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        buffer: &mut [u8],
        additional_data: &[u8],
    ) -> Result<usize, Error> {
        let plaintext_len = buffer
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "buffer shorter than AEAD tag"))?;
        let nonce_bytes = *nonce;
        match self.kind {
            TrafficAeadKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid AES-GCM key"))?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                let tag = cipher
                    .encrypt_in_place_detached(nonce, additional_data, &mut buffer[..plaintext_len])
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AES-GCM seal failed"))?;
                buffer[plaintext_len..plaintext_len + AEAD_TAG_LEN].copy_from_slice(&tag);
            }
            TrafficAeadKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "invalid ChaCha20-Poly1305 key")
                })?;
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                let tag = cipher
                    .encrypt_in_place_detached(nonce, additional_data, &mut buffer[..plaintext_len])
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidData, "ChaCha20-Poly1305 seal failed")
                    })?;
                buffer[plaintext_len..plaintext_len + AEAD_TAG_LEN].copy_from_slice(&tag);
            }
        }
        Ok(plaintext_len + AEAD_TAG_LEN)
    }

    pub fn open_with_nonce(
        &mut self,
        nonce: &[u8; AEAD_NONCE_LEN],
        ciphertext_with_tag: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if ciphertext_with_tag.len() < AEAD_TAG_LEN {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "ciphertext shorter than AEAD tag",
            ));
        }
        let ciphertext_len = ciphertext_with_tag.len() - AEAD_TAG_LEN;
        let mut buffer = ciphertext_with_tag.to_vec();
        self.open_in_place_with_nonce(nonce, &mut buffer, ciphertext_len, additional_data)?;
        buffer.truncate(ciphertext_len);
        Ok(buffer)
    }

    pub fn open_in_place_with_nonce(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        buffer: &mut [u8],
        ciphertext_len: usize,
        additional_data: &[u8],
    ) -> Result<usize, Error> {
        if ciphertext_len + AEAD_TAG_LEN > buffer.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "ciphertext length exceeds buffer",
            ));
        }
        let nonce_bytes = *nonce;
        match self.kind {
            TrafficAeadKind::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid AES-GCM key"))?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                let (ciphertext, tag_slice) = buffer.split_at_mut(ciphertext_len);
                let tag = Tag::from_slice(&tag_slice[..AEAD_TAG_LEN]);
                cipher
                    .decrypt_in_place_detached(nonce, additional_data, ciphertext, tag)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AES-GCM open failed"))?;
            }
            TrafficAeadKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "invalid ChaCha20-Poly1305 key")
                })?;
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                let (ciphertext, tag_slice) = buffer.split_at_mut(ciphertext_len);
                let tag = chacha20poly1305::Tag::from_slice(&tag_slice[..AEAD_TAG_LEN]);
                cipher
                    .decrypt_in_place_detached(nonce, additional_data, ciphertext, tag)
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidData, "ChaCha20-Poly1305 open failed")
                    })?;
            }
        }
        Ok(ciphertext_len)
    }

    /// Attempt decrypt preferring AES, falling back to ChaCha; returns AEAD with winning kind.
    pub fn open_auto_kind_with_state(
        context: &[u8],
        united_key: &[u8],
        prefer_aes: bool,
        ciphertext_with_tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, Self), Error> {
        let mut aes = Self::new(context, united_key, prefer_aes);
        aes.kind = TrafficAeadKind::Aes256Gcm;
        if let Ok(plaintext) = aes.open(ciphertext_with_tag, additional_data) {
            return Ok((plaintext, aes));
        }
        let mut chacha = Self::new(context, united_key, prefer_aes);
        chacha.kind = TrafficAeadKind::ChaCha20Poly1305;
        Ok((chacha.open(ciphertext_with_tag, additional_data)?, chacha))
    }

    /// Attempt decrypt preferring AES, falling back to ChaCha (upstream first-record behavior).
    pub fn open_auto_kind(
        context: &[u8],
        united_key: &[u8],
        prefer_aes: bool,
        ciphertext_with_tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(Vec<u8>, TrafficAeadKind), Error> {
        let mut aes = Self::new(context, united_key, prefer_aes);
        aes.kind = TrafficAeadKind::Aes256Gcm;
        if let Ok(plaintext) = aes.open(ciphertext_with_tag, additional_data) {
            return Ok((plaintext, TrafficAeadKind::Aes256Gcm));
        }
        let mut chacha = Self::new(context, united_key, prefer_aes);
        chacha.kind = TrafficAeadKind::ChaCha20Poly1305;
        Ok((
            chacha.open(ciphertext_with_tag, additional_data)?,
            TrafficAeadKind::ChaCha20Poly1305,
        ))
    }
}

pub fn max_nonce_bytes() -> [u8; AEAD_NONCE_LEN] {
    MAX_NONCE
}
