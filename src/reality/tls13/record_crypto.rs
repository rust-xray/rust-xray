use std::io::{Error, ErrorKind};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};

use crate::tls::records::{
    build_tls_record, TlsRecordContentType, TLS_LEGACY_VERSION_1_2, TLS_RECORD_APPLICATION_DATA,
    TLS_RECORD_HANDSHAKE,
};

use super::cipher_suite::{Tls13AeadAlgorithm, Tls13CipherSuite};
use super::key_schedule::{derive_traffic_key, update_traffic_secret, Tls13TrafficKeys};
use super::messages::{build_key_update_message, KEY_UPDATE_NOT_REQUESTED};

const TLS13_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// TLS 1.3 AEAD record encryptor for post-ServerHello handshake messages.
#[derive(Debug)]
pub struct Tls13RecordEncryptor {
    pub suite: Tls13CipherSuite,
    pub keys: Tls13TrafficKeys,
    pub sequence: u64,
    traffic_secret: Option<Vec<u8>>,
}

/// TLS 1.3 AEAD record decryptor for application data records.
#[derive(Debug)]
pub struct Tls13RecordDecryptor {
    pub suite: Tls13CipherSuite,
    pub keys: Tls13TrafficKeys,
    pub sequence: u64,
    traffic_secret: Option<Vec<u8>>,
}

/// TLS 1.3 per-record nonce: `static_iv XOR padded_sequence_number`.
pub fn tls13_record_nonce(iv: &[u8], sequence: u64) -> std::io::Result<[u8; 12]> {
    if iv.len() != TLS13_IV_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "TLS 1.3 record IV must be {TLS13_IV_LEN} bytes, got {}",
                iv.len()
            ),
        ));
    }

    let mut padded = [0u8; TLS13_IV_LEN];
    padded[4..].copy_from_slice(&sequence.to_be_bytes());

    let mut nonce = [0u8; TLS13_IV_LEN];
    for (out, (iv_byte, pad_byte)) in nonce.iter_mut().zip(iv.iter().zip(padded.iter())) {
        *out = iv_byte ^ pad_byte;
    }
    Ok(nonce)
}

fn build_record_aad(legacy_version: [u8; 2], ciphertext_len: u16) -> [u8; 5] {
    let mut aad = [0u8; 5];
    aad[0] = TLS_RECORD_APPLICATION_DATA;
    aad[1..3].copy_from_slice(&legacy_version);
    aad[3..5].copy_from_slice(&ciphertext_len.to_be_bytes());
    aad
}

fn validate_traffic_keys(suite: Tls13CipherSuite, keys: &Tls13TrafficKeys) -> std::io::Result<()> {
    if keys.iv.len() != TLS13_IV_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "TLS 1.3 traffic IV must be {TLS13_IV_LEN} bytes, got {}",
                keys.iv.len()
            ),
        ));
    }

    match suite.aead {
        Tls13AeadAlgorithm::Aes128Gcm
        | Tls13AeadAlgorithm::Aes256Gcm
        | Tls13AeadAlgorithm::ChaCha20Poly1305 => {
            if keys.key.len() != suite.key_len {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "TLS 1.3 {} key must be {} bytes, got {}",
                        match suite.aead {
                            Tls13AeadAlgorithm::Aes128Gcm => "AES-128-GCM",
                            Tls13AeadAlgorithm::Aes256Gcm => "AES-256-GCM",
                            Tls13AeadAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
                        },
                        suite.key_len,
                        keys.key.len()
                    ),
                ));
            }
            Ok(())
        }
    }
}

fn increment_sequence(sequence: u64) -> std::io::Result<u64> {
    sequence.checked_add(1).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "TLS 1.3 record sequence number overflow",
        )
    })
}

fn parse_tls13_inner_plaintext(
    inner: &[u8],
    expected_content_type: u8,
    wrong_content_type_error: &str,
) -> std::io::Result<Vec<u8>> {
    let (content, content_type) = tls13_inner_plaintext_parts(inner)?;

    match content_type {
        content_type if content_type == expected_content_type => Ok(content),
        TLS_RECORD_HANDSHAKE | TLS_RECORD_APPLICATION_DATA
            if content_type != expected_content_type =>
        {
            Err(Error::new(ErrorKind::Unsupported, wrong_content_type_error))
        }
        other => Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS 1.3 unexpected inner content type: {other}"),
        )),
    }
}

/// Returns TLS 1.3 inner plaintext body and trailing content-type byte.
pub(crate) fn tls13_inner_plaintext_parts(inner: &[u8]) -> std::io::Result<(Vec<u8>, u8)> {
    if inner.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 inner plaintext is empty",
        ));
    }

    let mut end = inner.len();
    while end > 0 && inner[end - 1] == 0 {
        end -= 1;
    }

    if end == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 inner plaintext has no content type",
        ));
    }

    let content_type = inner[end - 1];
    Ok((inner[..end - 1].to_vec(), content_type))
}

pub(crate) fn tls13_inner_plaintext_content_type(inner: &[u8]) -> Option<u8> {
    tls13_inner_plaintext_parts(inner)
        .ok()
        .map(|(_, content_type)| content_type)
}

pub(crate) fn tls13_inner_plaintext_body(inner: &[u8]) -> Option<Vec<u8>> {
    tls13_inner_plaintext_parts(inner)
        .ok()
        .map(|(content, _)| content)
}

/// Returns TLS 1.3 inner plaintext body, trailing content type, and zero padding length.
pub(crate) fn tls13_inner_plaintext_metadata(
    inner: &[u8],
) -> std::io::Result<(Vec<u8>, u8, usize)> {
    let (body, content_type) = tls13_inner_plaintext_parts(inner)?;
    let padding_len = inner.len().saturating_sub(body.len() + 1);
    Ok((body, content_type, padding_len))
}

pub(crate) fn tls13_record_aad_bytes(legacy_version: [u8; 2], payload_len: u16) -> [u8; 5] {
    build_record_aad(legacy_version, payload_len)
}

pub(crate) fn tls13_record_nonce_hex(iv: &[u8], sequence: u64) -> std::io::Result<String> {
    let nonce = tls13_record_nonce(iv, sequence)?;
    Ok(nonce.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn parse_tls13_handshake_inner_plaintext(inner: &[u8]) -> std::io::Result<Vec<u8>> {
    parse_tls13_inner_plaintext(
        inner,
        TLS_RECORD_HANDSHAKE,
        "TLS 1.3 handshake decrypt does not accept application data inner content type",
    )
}

pub(crate) fn parse_tls13_application_inner_plaintext(inner: &[u8]) -> std::io::Result<Vec<u8>> {
    parse_tls13_inner_plaintext(
        inner,
        TLS_RECORD_APPLICATION_DATA,
        "TLS 1.3 application data decrypt does not accept handshake inner content type",
    )
}

fn encrypt_aes128_gcm(
    key: &[u8],
    nonce: &[u8; TLS13_IV_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("TLS 1.3 AES-128-GCM key invalid: {e}"),
        )
    })?;
    cipher
        .encrypt(
            AesNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("TLS 1.3 AES-128-GCM encrypt failed: {e}"),
            )
        })
}

fn encrypt_aes256_gcm(
    key: &[u8],
    nonce: &[u8; TLS13_IV_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("TLS 1.3 AES-256-GCM key invalid: {e}"),
        )
    })?;
    cipher
        .encrypt(
            AesNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("TLS 1.3 AES-256-GCM encrypt failed: {e}"),
            )
        })
}

fn decrypt_aes128_gcm(
    key: &[u8],
    nonce: &[u8; TLS13_IV_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("TLS 1.3 AES-128-GCM key invalid: {e}"),
        )
    })?;
    cipher
        .decrypt(
            AesNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("TLS 1.3 AES-128-GCM decrypt failed: {e}"),
            )
        })
}

fn decrypt_aes256_gcm(
    key: &[u8],
    nonce: &[u8; TLS13_IV_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("TLS 1.3 AES-256-GCM key invalid: {e}"),
        )
    })?;
    cipher
        .decrypt(
            AesNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("TLS 1.3 AES-256-GCM decrypt failed: {e}"),
            )
        })
}

fn encrypt_chacha20_poly1305(
    key: &[u8],
    nonce: &[u8; TLS13_IV_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("TLS 1.3 ChaCha20-Poly1305 key invalid: {e}"),
        )
    })?;
    cipher
        .encrypt(
            ChaChaNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("TLS 1.3 ChaCha20-Poly1305 encrypt failed: {e}"),
            )
        })
}

fn decrypt_chacha20_poly1305(
    key: &[u8],
    nonce: &[u8; TLS13_IV_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("TLS 1.3 ChaCha20-Poly1305 key invalid: {e}"),
        )
    })?;
    cipher
        .decrypt(
            ChaChaNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("TLS 1.3 ChaCha20-Poly1305 decrypt failed: {e}"),
            )
        })
}

impl Tls13RecordEncryptor {
    pub fn new(suite: Tls13CipherSuite, keys: Tls13TrafficKeys) -> std::io::Result<Self> {
        validate_traffic_keys(suite, &keys)?;

        Ok(Self {
            suite,
            keys,
            sequence: 0,
            traffic_secret: None,
        })
    }

    pub fn with_traffic_secret(
        suite: Tls13CipherSuite,
        keys: Tls13TrafficKeys,
        traffic_secret: Vec<u8>,
    ) -> std::io::Result<Self> {
        validate_traffic_keys(suite, &keys)?;

        Ok(Self {
            suite,
            keys,
            sequence: 0,
            traffic_secret: Some(traffic_secret),
        })
    }

    /// Updates the sending application traffic secret and derived key/iv after KeyUpdate send.
    pub fn apply_sending_traffic_key_update(&mut self) -> std::io::Result<()> {
        let traffic_secret = self.traffic_secret.as_mut().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "TLS 1.3 sending traffic key update requires application traffic secret",
            )
        })?;
        *traffic_secret = update_traffic_secret(self.suite, traffic_secret).map_err(|err| {
            Error::new(
                err.kind(),
                format!("TLS 1.3 sending traffic key update failed: {err}"),
            )
        })?;
        self.keys = derive_traffic_key(self.suite, traffic_secret).map_err(|err| {
            Error::new(
                err.kind(),
                format!("TLS 1.3 sending traffic key derivation failed: {err}"),
            )
        })?;
        self.sequence = 0;
        Ok(())
    }

    /// Encrypts a TLS 1.3 KeyUpdate post-handshake message into an ApplicationData record.
    pub fn encrypt_key_update(&mut self, request_update: u8) -> std::io::Result<Vec<u8>> {
        let message = build_key_update_message(request_update).map_err(|err| {
            Error::new(
                err.kind(),
                format!("TLS 1.3 KeyUpdate message build failed: {err}"),
            )
        })?;
        self.encrypt_handshake_message(&message)
    }

    /// Sends KeyUpdate with `update_not_requested` and updates sending traffic keys.
    pub fn encrypt_server_key_update_response(&mut self) -> std::io::Result<Vec<u8>> {
        let record = self.encrypt_key_update(KEY_UPDATE_NOT_REQUESTED)?;
        self.apply_sending_traffic_key_update()?;
        Ok(record)
    }

    /// Encrypts a handshake message into a TLS ApplicationData record.
    pub fn encrypt_handshake_message(
        &mut self,
        handshake_message: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let nonce_bytes = tls13_record_nonce(&self.keys.iv, self.sequence)?;

        let mut inner_plaintext = Vec::with_capacity(handshake_message.len() + 1 + GCM_TAG_LEN);
        inner_plaintext.extend_from_slice(handshake_message);
        inner_plaintext.push(TLS_RECORD_HANDSHAKE);

        let ciphertext_len = u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 encrypted handshake record exceeds u16 payload limit",
            )
        })?;
        let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);

        let ciphertext = match self.suite.aead {
            Tls13AeadAlgorithm::Aes128Gcm => {
                encrypt_aes128_gcm(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
            Tls13AeadAlgorithm::Aes256Gcm => {
                encrypt_aes256_gcm(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
            Tls13AeadAlgorithm::ChaCha20Poly1305 => {
                encrypt_chacha20_poly1305(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
        };

        if ciphertext.len() != ciphertext_len as usize {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "TLS 1.3 encrypted payload length mismatch: expected {}, got {}",
                    ciphertext_len,
                    ciphertext.len()
                ),
            ));
        }

        let record = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            &ciphertext,
        )?;

        self.sequence = increment_sequence(self.sequence)?;

        Ok(record)
    }

    /// Encrypts application data into a TLS ApplicationData record.
    pub fn encrypt_application_data(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let nonce_bytes = tls13_record_nonce(&self.keys.iv, self.sequence)?;

        let mut inner_plaintext = Vec::with_capacity(plaintext.len() + 1);
        inner_plaintext.extend_from_slice(plaintext);
        inner_plaintext.push(TLS_RECORD_APPLICATION_DATA);

        let ciphertext_len = u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 encrypted application data record exceeds u16 payload limit",
            )
        })?;
        let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);

        let ciphertext = match self.suite.aead {
            Tls13AeadAlgorithm::Aes128Gcm => {
                encrypt_aes128_gcm(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
            Tls13AeadAlgorithm::Aes256Gcm => {
                encrypt_aes256_gcm(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
            Tls13AeadAlgorithm::ChaCha20Poly1305 => {
                encrypt_chacha20_poly1305(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
        };

        if ciphertext.len() != ciphertext_len as usize {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "TLS 1.3 encrypted payload length mismatch: expected {}, got {}",
                    ciphertext_len,
                    ciphertext.len()
                ),
            ));
        }

        let record = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            &ciphertext,
        )?;

        self.sequence = increment_sequence(self.sequence)?;

        Ok(record)
    }

    #[cfg(test)]
    pub(crate) fn encrypt_application_record_with_inner_content_type(
        &mut self,
        body: &[u8],
        inner_content_type: u8,
    ) -> std::io::Result<Vec<u8>> {
        let nonce_bytes = tls13_record_nonce(&self.keys.iv, self.sequence)?;

        let mut inner_plaintext = Vec::with_capacity(body.len() + 1);
        inner_plaintext.extend_from_slice(body);
        inner_plaintext.push(inner_content_type);

        let ciphertext_len = u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 encrypted application data record exceeds u16 payload limit",
            )
        })?;
        let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);

        let ciphertext = match self.suite.aead {
            Tls13AeadAlgorithm::Aes128Gcm => {
                encrypt_aes128_gcm(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
            Tls13AeadAlgorithm::Aes256Gcm => {
                encrypt_aes256_gcm(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
            Tls13AeadAlgorithm::ChaCha20Poly1305 => {
                encrypt_chacha20_poly1305(&self.keys.key, &nonce_bytes, &inner_plaintext, &aad)?
            }
        };

        if ciphertext.len() != ciphertext_len as usize {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "TLS 1.3 encrypted payload length mismatch: expected {}, got {}",
                    ciphertext_len,
                    ciphertext.len()
                ),
            ));
        }

        let record = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            &ciphertext,
        )?;

        self.sequence = increment_sequence(self.sequence)?;

        Ok(record)
    }
}

impl Tls13RecordDecryptor {
    pub fn new(suite: Tls13CipherSuite, keys: Tls13TrafficKeys) -> std::io::Result<Self> {
        validate_traffic_keys(suite, &keys)?;

        Ok(Self {
            suite,
            keys,
            sequence: 0,
            traffic_secret: None,
        })
    }

    pub fn with_traffic_secret(
        suite: Tls13CipherSuite,
        keys: Tls13TrafficKeys,
        traffic_secret: Vec<u8>,
    ) -> std::io::Result<Self> {
        validate_traffic_keys(suite, &keys)?;

        Ok(Self {
            suite,
            keys,
            sequence: 0,
            traffic_secret: Some(traffic_secret),
        })
    }

    /// Updates the receiving application traffic secret and derived key/iv after KeyUpdate receive.
    pub fn apply_receiving_traffic_key_update(&mut self) -> std::io::Result<()> {
        let traffic_secret = self.traffic_secret.as_mut().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "TLS 1.3 receiving traffic key update requires application traffic secret",
            )
        })?;
        *traffic_secret = update_traffic_secret(self.suite, traffic_secret).map_err(|err| {
            Error::new(
                err.kind(),
                format!("TLS 1.3 receiving traffic key update failed: {err}"),
            )
        })?;
        self.keys = derive_traffic_key(self.suite, traffic_secret).map_err(|err| {
            Error::new(
                err.kind(),
                format!("TLS 1.3 receiving traffic key derivation failed: {err}"),
            )
        })?;
        self.sequence = 0;
        Ok(())
    }

    pub fn decrypt_application_data_record(
        &mut self,
        record: &crate::tls::TlsRecord,
    ) -> std::io::Result<Vec<u8>> {
        let inner_plaintext = self.decrypt_record_payload(record)?;
        parse_tls13_application_inner_plaintext(&inner_plaintext)
    }

    pub fn decrypt_handshake_record(
        &mut self,
        record: &crate::tls::TlsRecord,
    ) -> std::io::Result<Vec<u8>> {
        let inner_plaintext = self.decrypt_record_payload(record)?;
        parse_tls13_handshake_inner_plaintext(&inner_plaintext)
    }

    pub(crate) fn decrypt_record_payload(
        &mut self,
        record: &crate::tls::TlsRecord,
    ) -> std::io::Result<Vec<u8>> {
        if record.content_type != TlsRecordContentType::ApplicationData {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 record decrypt requires ApplicationData record",
            ));
        }

        let payload_len = u16::try_from(record.payload.len()).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 encrypted record exceeds u16 payload limit",
            )
        })?;
        let aad = build_record_aad(record.legacy_version, payload_len);
        let decrypt_sequence = self.sequence;
        let encrypted_record_len = record.raw.len();
        let cipher_suite = self.suite.name;
        let nonce_bytes = tls13_record_nonce(&self.keys.iv, self.sequence)?;

        let inner_plaintext =
            match self.suite.aead {
                Tls13AeadAlgorithm::Aes128Gcm => {
                    decrypt_aes128_gcm(&self.keys.key, &nonce_bytes, &record.payload, &aad)
                        .map_err(|err| {
                            application_record_decrypt_error(
                                err,
                                cipher_suite,
                                decrypt_sequence,
                                encrypted_record_len,
                            )
                        })?
                }
                Tls13AeadAlgorithm::Aes256Gcm => {
                    decrypt_aes256_gcm(&self.keys.key, &nonce_bytes, &record.payload, &aad)
                        .map_err(|err| {
                            application_record_decrypt_error(
                                err,
                                cipher_suite,
                                decrypt_sequence,
                                encrypted_record_len,
                            )
                        })?
                }
                Tls13AeadAlgorithm::ChaCha20Poly1305 => {
                    decrypt_chacha20_poly1305(&self.keys.key, &nonce_bytes, &record.payload, &aad)
                        .map_err(|err| {
                        application_record_decrypt_error(
                            err,
                            cipher_suite,
                            decrypt_sequence,
                            encrypted_record_len,
                        )
                    })?
                }
            };

        self.sequence = increment_sequence(self.sequence)?;

        Ok(inner_plaintext)
    }
}

fn application_record_decrypt_error(
    err: Error,
    cipher_suite: &str,
    decrypt_sequence: u64,
    encrypted_record_len: usize,
) -> Error {
    Error::new(
        err.kind(),
        format!(
            "{} (decrypt_sequence={decrypt_sequence}, encrypted_record_len={encrypted_record_len}, cipher_suite={cipher_suite})",
            err
        ),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/record_crypto.rs"]
mod tests;
