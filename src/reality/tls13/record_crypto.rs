use std::io::{Error, ErrorKind};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce,
};

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
        Tls13AeadAlgorithm::ChaCha20Poly1305 => Err(Error::new(
            ErrorKind::Unsupported,
            "TLS 1.3 ChaCha20-Poly1305 record encryption is not implemented yet",
        )),
        Tls13AeadAlgorithm::Aes128Gcm | Tls13AeadAlgorithm::Aes256Gcm => {
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
            Nonce::from_slice(nonce),
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
            Nonce::from_slice(nonce),
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
            Nonce::from_slice(nonce),
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
            Nonce::from_slice(nonce),
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
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "TLS 1.3 ChaCha20-Poly1305 record encryption is not implemented yet",
                ));
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
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "TLS 1.3 ChaCha20-Poly1305 record encryption is not implemented yet",
                ));
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
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "TLS 1.3 ChaCha20-Poly1305 record encryption is not implemented yet",
                ));
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
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "TLS 1.3 ChaCha20-Poly1305 record decryption is not implemented yet",
                    ));
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
mod tests {
    use super::*;
    use crate::reality::tls13::{
        key_schedule::derive_traffic_key,
        messages::{parse_key_update_handshake, KEY_UPDATE_NOT_REQUESTED},
        tls13_cipher_suite, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    };
    use crate::tls::records::{parse_tls_records, TlsRecordContentType, TLS_RECORD_ALERT};

    fn sample_handshake_message() -> Vec<u8> {
        vec![0x08, 0x00, 0x00, 0x00, 0x00]
    }

    fn aes128_keys() -> Tls13TrafficKeys {
        Tls13TrafficKeys {
            key: (0x10..0x20).collect(),
            iv: (0x01..0x0d).collect(),
        }
    }

    fn aes256_keys() -> Tls13TrafficKeys {
        Tls13TrafficKeys {
            key: (0x20..0x40).collect(),
            iv: (0x01..0x0d).collect(),
        }
    }

    fn sample_traffic_secret(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn encryptor_with_traffic_secret(seed: u8) -> Tls13RecordEncryptor {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let traffic_secret = sample_traffic_secret(seed);
        let keys = derive_traffic_key(suite, &traffic_secret).expect("traffic keys");
        Tls13RecordEncryptor::with_traffic_secret(suite, keys, traffic_secret).expect("encryptor")
    }

    fn decryptor_with_traffic_secret(seed: u8) -> Tls13RecordDecryptor {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let traffic_secret = sample_traffic_secret(seed);
        let keys = derive_traffic_key(suite, &traffic_secret).expect("traffic keys");
        Tls13RecordDecryptor::with_traffic_secret(suite, keys, traffic_secret).expect("decryptor")
    }

    fn client_app_traffic_pair(seed: u8) -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let traffic_secret = sample_traffic_secret(seed);
        let keys = derive_traffic_key(suite, &traffic_secret).expect("traffic keys");
        let encryptor =
            Tls13RecordEncryptor::with_traffic_secret(suite, keys.clone(), traffic_secret.clone())
                .expect("encryptor");
        let decryptor = Tls13RecordDecryptor::with_traffic_secret(suite, keys, traffic_secret)
            .expect("decryptor");
        (encryptor, decryptor)
    }

    #[test]
    fn tls13_record_nonce_sequence_zero_equals_iv() {
        let iv = [0x11; TLS13_IV_LEN];
        let nonce = tls13_record_nonce(&iv, 0).expect("valid nonce");
        assert_eq!(nonce, iv);
    }

    #[test]
    fn tls13_record_nonce_known_xor_case() {
        let iv = [0xff; TLS13_IV_LEN];
        let nonce = tls13_record_nonce(&iv, 1).expect("valid nonce");

        let mut expected = [0xff; TLS13_IV_LEN];
        expected[11] = 0xfe;
        assert_eq!(nonce, expected);
    }

    #[test]
    fn tls13_record_nonce_rejects_wrong_iv_length() {
        let err = tls13_record_nonce(&[0u8; 8], 0).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn encrypt_handshake_message_sequence_increments() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let mut encryptor =
            Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
        let message = sample_handshake_message();

        assert_eq!(encryptor.sequence, 0);
        let first = encryptor
            .encrypt_handshake_message(&message)
            .expect("valid encrypted record");
        assert_eq!(encryptor.sequence, 1);
        let second = encryptor
            .encrypt_handshake_message(&message)
            .expect("valid encrypted record");
        assert_eq!(encryptor.sequence, 2);

        assert_ne!(first, second);
    }

    #[test]
    fn encrypt_handshake_message_record_header_is_application_data() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let mut encryptor =
            Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
        let record = encryptor
            .encrypt_handshake_message(&sample_handshake_message())
            .expect("valid encrypted record");

        assert_eq!(record[0], TLS_RECORD_APPLICATION_DATA);
        assert_eq!(record[1..3], TLS_LEGACY_VERSION_1_2);
    }

    #[test]
    fn encrypt_handshake_message_record_length_matches_ciphertext() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let mut encryptor =
            Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
        let record = encryptor
            .encrypt_handshake_message(&sample_handshake_message())
            .expect("valid encrypted record");

        let payload_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(payload_len, record.len() - 5);
        assert_eq!(
            payload_len,
            sample_handshake_message().len() + 1 + GCM_TAG_LEN
        );
    }

    #[test]
    fn encrypt_handshake_message_aes128_works() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let mut encryptor =
            Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
        let record = encryptor
            .encrypt_handshake_message(&sample_handshake_message())
            .expect("valid encrypted record");

        let records = parse_tls_records(&record).expect("parsable record");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].content_type,
            TlsRecordContentType::ApplicationData
        );
        assert!(records[0].payload.len() > GCM_TAG_LEN);
    }

    #[test]
    fn encrypt_handshake_message_aes256_works() {
        let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
        let mut encryptor =
            Tls13RecordEncryptor::new(suite, aes256_keys()).expect("valid encryptor");
        let record = encryptor
            .encrypt_handshake_message(&sample_handshake_message())
            .expect("valid encrypted record");

        let records = parse_tls_records(&record).expect("parsable record");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].content_type,
            TlsRecordContentType::ApplicationData
        );
        assert!(records[0].payload.len() > GCM_TAG_LEN);
    }

    #[test]
    fn new_chacha20_returns_unsupported() {
        let suite = tls13_cipher_suite(TLS_CHACHA20_POLY1305_SHA256).expect("known suite");
        let keys = Tls13TrafficKeys {
            key: vec![0x55; 32],
            iv: vec![0x66; 12],
        };

        let err = Tls13RecordEncryptor::new(suite, keys).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("ChaCha20"));
    }

    #[test]
    fn encrypt_handshake_message_is_deterministic() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys();
        let message = sample_handshake_message();

        let mut first = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
        let first_record = first
            .encrypt_handshake_message(&message)
            .expect("valid encrypted record");

        let mut second = Tls13RecordEncryptor::new(suite, keys).expect("valid encryptor");
        let second_record = second
            .encrypt_handshake_message(&message)
            .expect("valid encrypted record");

        assert_eq!(first_record, second_record);
    }

    fn parse_encrypted_application_record(record_bytes: &[u8]) -> crate::tls::TlsRecord {
        let records = parse_tls_records(record_bytes).expect("parsable record");
        assert_eq!(records.len(), 1);
        records.into_iter().next().expect("single record")
    }

    #[test]
    fn encrypt_application_data_roundtrip_aes128() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys();
        let plaintext = b"hello application data";

        let mut encryptor =
            Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
        let record_bytes = encryptor
            .encrypt_application_data(plaintext)
            .expect("valid encrypted record");

        let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
        let record = parse_encrypted_application_record(&record_bytes);
        let decrypted = decryptor
            .decrypt_application_data_record(&record)
            .expect("valid decrypted application data");

        assert_eq!(decrypted, plaintext);
        assert_eq!(encryptor.sequence, 1);
        assert_eq!(decryptor.sequence, 1);
    }

    #[test]
    fn encrypt_application_data_roundtrip_aes256() {
        let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
        let keys = aes256_keys();
        let plaintext = b"aes256 application payload";

        let mut encryptor =
            Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
        let record_bytes = encryptor
            .encrypt_application_data(plaintext)
            .expect("valid encrypted record");

        let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
        let record = parse_encrypted_application_record(&record_bytes);
        let decrypted = decryptor
            .decrypt_application_data_record(&record)
            .expect("valid decrypted application data");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_application_data_wrong_key_fails() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let mut encryptor =
            Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
        let record_bytes = encryptor
            .encrypt_application_data(b"secret")
            .expect("valid encrypted record");

        let mut wrong_keys = aes128_keys();
        wrong_keys.key[0] ^= 0x01;
        let mut decryptor = Tls13RecordDecryptor::new(suite, wrong_keys).expect("valid decryptor");
        let record = parse_encrypted_application_record(&record_bytes);

        let err = decryptor
            .decrypt_application_data_record(&record)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn decrypt_application_data_sequence_mismatch_fails() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys();
        let mut encryptor =
            Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
        let record_bytes = encryptor
            .encrypt_application_data(b"sequence test")
            .expect("valid encrypted record");

        let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
        decryptor.sequence = 1;
        let record = parse_encrypted_application_record(&record_bytes);

        let err = decryptor
            .decrypt_application_data_record(&record)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn decrypt_application_data_rejects_non_application_record() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let mut decryptor =
            Tls13RecordDecryptor::new(suite, aes128_keys()).expect("valid decryptor");
        let record = crate::tls::TlsRecord {
            content_type: TlsRecordContentType::Handshake,
            legacy_version: TLS_LEGACY_VERSION_1_2,
            payload: vec![0x01, 0x02, 0x03],
            raw: vec![
                TLS_RECORD_HANDSHAKE,
                0x03,
                0x03,
                0x00,
                0x03,
                0x01,
                0x02,
                0x03,
            ],
        };

        let err = decryptor
            .decrypt_application_data_record(&record)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("ApplicationData"));
    }

    #[test]
    fn decrypt_application_data_strips_zero_padding() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys();
        let plaintext = b"padded payload";

        let mut inner_plaintext = Vec::with_capacity(plaintext.len() + 1 + 4);
        inner_plaintext.extend_from_slice(plaintext);
        inner_plaintext.push(TLS_RECORD_APPLICATION_DATA);
        inner_plaintext.extend_from_slice(&[0, 0, 0, 0]);

        let nonce_bytes = tls13_record_nonce(&keys.iv, 0).expect("valid nonce");
        let ciphertext_len =
            u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).expect("valid ciphertext length");
        let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);
        let ciphertext =
            encrypt_aes128_gcm(&keys.key, &nonce_bytes, &inner_plaintext, &aad).expect("encrypt");
        let record_bytes = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            &ciphertext,
        )
        .expect("valid record");

        let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
        let record = parse_encrypted_application_record(&record_bytes);
        let decrypted = decryptor
            .decrypt_application_data_record(&record)
            .expect("valid decrypted application data");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_application_data_rejects_handshake_inner_content_type() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys();
        let handshake_message = sample_handshake_message();

        let mut inner_plaintext = handshake_message.clone();
        inner_plaintext.push(TLS_RECORD_HANDSHAKE);

        let nonce_bytes = tls13_record_nonce(&keys.iv, 0).expect("valid nonce");
        let ciphertext_len =
            u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).expect("valid ciphertext length");
        let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);
        let ciphertext =
            encrypt_aes128_gcm(&keys.key, &nonce_bytes, &inner_plaintext, &aad).expect("encrypt");
        let record_bytes = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            &ciphertext,
        )
        .expect("valid record");

        let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
        let record = parse_encrypted_application_record(&record_bytes);
        let err = decryptor
            .decrypt_application_data_record(&record)
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn decrypt_handshake_record_roundtrip_with_encrypt_handshake_message() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys();
        let handshake_message = sample_handshake_message();

        let mut encryptor =
            Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
        let record_bytes = encryptor
            .encrypt_handshake_message(&handshake_message)
            .expect("valid encrypted record");

        let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
        let record = parse_encrypted_application_record(&record_bytes);
        let decrypted = decryptor
            .decrypt_handshake_record(&record)
            .expect("valid decrypted handshake message");

        assert_eq!(decrypted, handshake_message);
    }

    #[test]
    fn tls13_inner_plaintext_content_type_reads_trailing_content_type() {
        let inner = vec![0x02, 0x28, TLS_RECORD_ALERT];
        assert_eq!(
            tls13_inner_plaintext_content_type(&inner),
            Some(TLS_RECORD_ALERT)
        );
        assert_eq!(tls13_inner_plaintext_body(&inner), Some(vec![0x02, 0x28]));
    }

    #[test]
    fn decrypt_handshake_record_rejects_encrypted_alert_inner_content() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys();

        let mut inner_plaintext = vec![0x02, 0x28];
        inner_plaintext.push(TLS_RECORD_ALERT);

        let nonce_bytes = tls13_record_nonce(&keys.iv, 0).expect("valid nonce");
        let ciphertext_len =
            u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).expect("valid ciphertext length");
        let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);
        let ciphertext =
            encrypt_aes128_gcm(&keys.key, &nonce_bytes, &inner_plaintext, &aad).expect("encrypt");
        let record_bytes = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            &ciphertext,
        )
        .expect("valid record");

        let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
        let record = parse_encrypted_application_record(&record_bytes);
        let err = decryptor.decrypt_handshake_record(&record).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("unexpected inner content type: 21"));
    }

    #[test]
    fn new_chacha20_decryptor_returns_unsupported() {
        let suite = tls13_cipher_suite(TLS_CHACHA20_POLY1305_SHA256).expect("known suite");
        let keys = Tls13TrafficKeys {
            key: vec![0x55; 32],
            iv: vec![0x66; 12],
        };

        let err = Tls13RecordDecryptor::new(suite, keys).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("ChaCha20"));
    }

    #[test]
    fn receiving_key_update_resets_sequence() {
        let mut decryptor = decryptor_with_traffic_secret(0xAA);
        let old_keys = decryptor.keys.clone();
        decryptor.sequence = 4;

        decryptor
            .apply_receiving_traffic_key_update()
            .expect("receiving key update");

        assert_eq!(decryptor.sequence, 0);
        assert_ne!(decryptor.keys.key, old_keys.key);
        assert_ne!(decryptor.keys.iv, old_keys.iv);
    }

    #[test]
    fn sending_key_update_resets_sequence() {
        let mut encryptor = encryptor_with_traffic_secret(0xBB);
        let old_keys = encryptor.keys.clone();
        encryptor.sequence = 7;

        encryptor
            .apply_sending_traffic_key_update()
            .expect("sending key update");

        assert_eq!(encryptor.sequence, 0);
        assert_ne!(encryptor.keys.key, old_keys.key);
        assert_ne!(encryptor.keys.iv, old_keys.iv);
    }

    #[test]
    fn key_update_roundtrip_resets_sequence_for_next_appdata() {
        let (mut encryptor, mut decryptor) = client_app_traffic_pair(0xCC);
        let first_plaintext = b"before key update";
        let second_plaintext = b"after key update";

        let first_record = encryptor
            .encrypt_application_data(first_plaintext)
            .expect("first appdata");
        assert_eq!(encryptor.sequence, 1);

        let key_update_record = encryptor
            .encrypt_key_update(KEY_UPDATE_NOT_REQUESTED)
            .expect("key update");
        assert_eq!(encryptor.sequence, 2);
        encryptor
            .apply_sending_traffic_key_update()
            .expect("sending key update");
        assert_eq!(encryptor.sequence, 0);

        let second_record = encryptor
            .encrypt_application_data(second_plaintext)
            .expect("second appdata");
        assert_eq!(encryptor.sequence, 1);

        let first_parsed = parse_encrypted_application_record(&first_record);
        let decrypted_first = decryptor
            .decrypt_application_data_record(&first_parsed)
            .expect("decrypt first appdata");
        assert_eq!(decrypted_first, first_plaintext);
        assert_eq!(decryptor.sequence, 1);

        let key_update_parsed = parse_encrypted_application_record(&key_update_record);
        let key_update_message = decryptor
            .decrypt_handshake_record(&key_update_parsed)
            .expect("decrypt key update");
        assert_eq!(
            parse_key_update_handshake(&key_update_message).expect("parse key update"),
            KEY_UPDATE_NOT_REQUESTED
        );
        assert_eq!(decryptor.sequence, 2);
        decryptor
            .apply_receiving_traffic_key_update()
            .expect("receiving key update");
        assert_eq!(decryptor.sequence, 0);

        let second_parsed = parse_encrypted_application_record(&second_record);
        let decrypted_second = decryptor
            .decrypt_application_data_record(&second_parsed)
            .expect("decrypt second appdata");
        assert_eq!(decrypted_second, second_plaintext);
        assert_eq!(decryptor.sequence, 1);
    }

    #[test]
    fn encrypt_server_key_update_response_uses_old_key_then_resets_sequence() {
        let (mut server_encryptor, mut client_decryptor) = client_app_traffic_pair(0xDD);
        let old_keys = server_encryptor.keys.clone();
        server_encryptor.sequence = 3;

        let key_update_response = server_encryptor
            .encrypt_server_key_update_response()
            .expect("server key update response");
        assert_eq!(server_encryptor.sequence, 0);
        assert_ne!(server_encryptor.keys.key, old_keys.key);
        assert_ne!(server_encryptor.keys.iv, old_keys.iv);

        let follow_up = server_encryptor
            .encrypt_application_data(b"server appdata after key update")
            .expect("server appdata after key update");
        assert_eq!(server_encryptor.sequence, 1);

        client_decryptor.sequence = 3;
        let key_update_parsed = parse_encrypted_application_record(&key_update_response);
        let key_update_message = client_decryptor
            .decrypt_handshake_record(&key_update_parsed)
            .expect("decrypt server key update");
        assert_eq!(
            parse_key_update_handshake(&key_update_message).expect("parse key update"),
            KEY_UPDATE_NOT_REQUESTED
        );
        assert_eq!(client_decryptor.sequence, 4);
        client_decryptor
            .apply_receiving_traffic_key_update()
            .expect("receiving key update");
        assert_eq!(client_decryptor.sequence, 0);

        let follow_up_parsed = parse_encrypted_application_record(&follow_up);
        let decrypted = client_decryptor
            .decrypt_application_data_record(&follow_up_parsed)
            .expect("decrypt server appdata after key update");
        assert_eq!(decrypted, b"server appdata after key update");
        assert_eq!(client_decryptor.sequence, 1);
    }
}
