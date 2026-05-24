use std::io::{Error, ErrorKind};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce,
};

use crate::tls::records::{
    build_tls_record, TLS_LEGACY_VERSION_1_2, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_HANDSHAKE,
};

use super::cipher_suite::{Tls13AeadAlgorithm, Tls13CipherSuite};
use super::key_schedule::Tls13TrafficKeys;

const TLS13_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// TLS 1.3 AEAD record encryptor for post-ServerHello handshake messages.
#[derive(Debug)]
pub struct Tls13RecordEncryptor {
    pub suite: Tls13CipherSuite,
    pub keys: Tls13TrafficKeys,
    pub sequence: u64,
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

fn build_record_aad(ciphertext_len: u16) -> [u8; 5] {
    let mut aad = [0u8; 5];
    aad[0] = TLS_RECORD_APPLICATION_DATA;
    aad[1..3].copy_from_slice(&TLS_LEGACY_VERSION_1_2);
    aad[3..5].copy_from_slice(&ciphertext_len.to_be_bytes());
    aad
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

impl Tls13RecordEncryptor {
    pub fn new(suite: Tls13CipherSuite, keys: Tls13TrafficKeys) -> std::io::Result<Self> {
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
            Tls13AeadAlgorithm::ChaCha20Poly1305 => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "TLS 1.3 ChaCha20-Poly1305 record encryption is not implemented yet",
                ));
            }
            Tls13AeadAlgorithm::Aes128Gcm => {
                if keys.key.len() != suite.key_len {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "TLS 1.3 AES-128-GCM key must be {} bytes, got {}",
                            suite.key_len,
                            keys.key.len()
                        ),
                    ));
                }
            }
            Tls13AeadAlgorithm::Aes256Gcm => {
                if keys.key.len() != suite.key_len {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "TLS 1.3 AES-256-GCM key must be {} bytes, got {}",
                            suite.key_len,
                            keys.key.len()
                        ),
                    ));
                }
            }
        }

        Ok(Self {
            suite,
            keys,
            sequence: 0,
        })
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
        let aad = build_record_aad(ciphertext_len);

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

        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 record sequence number overflow",
            )
        })?;

        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::tls13::{
        tls13_cipher_suite, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    };
    use crate::tls::records::{parse_tls_records, TlsRecordContentType};

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
}
