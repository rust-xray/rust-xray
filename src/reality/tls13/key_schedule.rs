use std::io::{Error, ErrorKind};

use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

use super::cipher_suite::Tls13CipherSuite;
use super::transcript::Tls13HashAlgorithm;

const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";
const SHA256_OUTPUT_LEN: usize = 32;
const SHA384_OUTPUT_LEN: usize = 48;

/// Derived TLS 1.3 traffic encryption material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13TrafficKeys {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

/// Placeholder for TLS 1.3 key schedule state.
///
/// Upstream equivalent: early/handshake/application secret derivation in Go
/// `serverHandshakeStateTLS13`.
pub struct Tls13KeySchedule {
    // TODO: early secret
    // TODO: handshake traffic secrets
    // TODO: application traffic secrets
}

impl Tls13KeySchedule {
    pub fn new() -> Self {
        Self {}
    }

    /// TODO: derive handshake traffic secrets from shared secret + transcript.
    pub fn derive_handshake_secrets(&mut self, _shared_secret: &[u8]) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "REALITY TLS 1.3 key schedule is not implemented yet",
        ))
    }

    /// TODO: derive application traffic secrets after server Finished.
    pub fn derive_application_secrets(&mut self) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "REALITY TLS 1.3 key schedule is not implemented yet",
        ))
    }
}

impl Default for Tls13KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}

/// Builds the TLS 1.3 `HkdfLabel` structure used as HKDF-Expand `info`.
fn build_hkdf_label(label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    let mut tls_label = Vec::with_capacity(TLS13_LABEL_PREFIX.len() + label.len());
    tls_label.extend_from_slice(TLS13_LABEL_PREFIX);
    tls_label.extend_from_slice(label);

    if tls_label.len() > 255 {
        return Err(invalid_input(format!(
            "TLS 1.3 HKDF label too long: {} bytes (max 255 including tls13 prefix)",
            tls_label.len()
        )));
    }
    if tls_label.len() < 7 {
        return Err(invalid_input(format!(
            "TLS 1.3 HKDF label too short: {} bytes (min 7 including tls13 prefix)",
            tls_label.len()
        )));
    }
    if context.len() > 255 {
        return Err(invalid_input(format!(
            "TLS 1.3 HKDF context too long: {} bytes (max 255)",
            context.len()
        )));
    }
    if length > u16::MAX as usize {
        return Err(invalid_input(format!(
            "TLS 1.3 HKDF output length too long: {} (max {})",
            length,
            u16::MAX
        )));
    }

    let mut info = Vec::with_capacity(2 + 1 + tls_label.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(
        tls_label
            .len()
            .try_into()
            .expect("tls_label length fits in u8 after validation"),
    );
    info.extend_from_slice(&tls_label);
    info.push(
        context
            .len()
            .try_into()
            .expect("context length fits in u8 after validation"),
    );
    info.extend_from_slice(context);
    Ok(info)
}

pub fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    let info = build_hkdf_label(label, context, len)?;
    let hk = Hkdf::<Sha256>::from_prk(secret)
        .map_err(|e| invalid_data(format!("TLS 1.3 HKDF invalid PRK length: {e}")))?;
    let mut okm = vec![0u8; len];
    hk.expand(&info, &mut okm)
        .map_err(|e| invalid_data(format!("TLS 1.3 HKDF expand failed: {e}")))?;
    Ok(okm)
}

pub fn hkdf_expand_label_sha384(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    let info = build_hkdf_label(label, context, len)?;
    let hk = Hkdf::<Sha384>::from_prk(secret)
        .map_err(|e| invalid_data(format!("TLS 1.3 HKDF invalid PRK length: {e}")))?;
    let mut okm = vec![0u8; len];
    hk.expand(&info, &mut okm)
        .map_err(|e| invalid_data(format!("TLS 1.3 HKDF expand failed: {e}")))?;
    Ok(okm)
}

pub fn derive_secret_sha256(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, Error> {
    hkdf_expand_label_sha256(secret, label, transcript_hash, SHA256_OUTPUT_LEN)
}

pub fn derive_secret_sha384(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, Error> {
    hkdf_expand_label_sha384(secret, label, transcript_hash, SHA384_OUTPUT_LEN)
}

pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
    prk.as_slice().to_vec()
}

pub fn hash_len(algorithm: Tls13HashAlgorithm) -> usize {
    match algorithm {
        Tls13HashAlgorithm::Sha256 => SHA256_OUTPUT_LEN,
        Tls13HashAlgorithm::Sha384 => SHA384_OUTPUT_LEN,
    }
}

fn hkdf_expand_label_for_hash(
    hash: Tls13HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    match hash {
        Tls13HashAlgorithm::Sha256 => hkdf_expand_label_sha256(secret, label, context, len),
        Tls13HashAlgorithm::Sha384 => hkdf_expand_label_sha384(secret, label, context, len),
    }
}

pub fn derive_traffic_key(
    suite: Tls13CipherSuite,
    traffic_secret: &[u8],
) -> Result<Tls13TrafficKeys, Error> {
    let key = hkdf_expand_label_for_hash(suite.hash, traffic_secret, b"key", b"", suite.key_len)?;
    let iv = hkdf_expand_label_for_hash(suite.hash, traffic_secret, b"iv", b"", suite.iv_len)?;
    Ok(Tls13TrafficKeys { key, iv })
}

pub fn derive_finished_key(suite: Tls13CipherSuite, base_key: &[u8]) -> Result<Vec<u8>, Error> {
    let output_len = hash_len(suite.hash);
    hkdf_expand_label_for_hash(suite.hash, base_key, b"finished", b"", output_len)
}

pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha384>::extract(salt, ikm);
    prk.as_slice().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::tls13::cipher_suite::{
        tls13_cipher_suite, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    };

    const RFC5869_SHA256_PRK: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
        0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    ];

    const DERIVED_SECRET_EMPTY_SHA256: [u8; 32] = [
        0x38, 0x3b, 0x35, 0xaa, 0xbd, 0x60, 0xa0, 0x96, 0x40, 0x00, 0x34, 0x9d, 0x9e, 0x7b, 0x52,
        0x43, 0x4d, 0x9a, 0x3e, 0xbb, 0x55, 0x1c, 0xf6, 0x4a, 0xcb, 0x75, 0x46, 0xf3, 0xe9, 0x43,
        0x18, 0xd3,
    ];

    #[test]
    fn hkdf_expand_label_output_length_is_correct() {
        let secret = [0u8; SHA256_OUTPUT_LEN];
        let output = hkdf_expand_label_sha256(&secret, b"test", b"context", 17).unwrap();
        assert_eq!(output.len(), 17);
    }

    #[test]
    fn hkdf_expand_label_uses_tls13_prefix() {
        let secret = [0u8; SHA256_OUTPUT_LEN];
        let output = hkdf_expand_label_sha256(&secret, b"derived", b"", SHA256_OUTPUT_LEN)
            .expect("valid expand");
        assert_eq!(output.as_slice(), DERIVED_SECRET_EMPTY_SHA256);
    }

    #[test]
    fn hkdf_expand_label_rejects_context_too_long() {
        let secret = [0u8; SHA256_OUTPUT_LEN];
        let context = vec![0u8; 256];
        let err = hkdf_expand_label_sha256(&secret, b"test", &context, 32).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("context too long"));
    }

    #[test]
    fn hkdf_expand_label_rejects_label_too_long() {
        let secret = [0u8; SHA256_OUTPUT_LEN];
        let label = vec![0u8; 250];
        let err = hkdf_expand_label_sha256(&secret, &label, b"", 32).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("label too long"));
    }

    #[test]
    fn derive_secret_sha256_output_length_matches_hash() {
        let secret = [1u8; SHA256_OUTPUT_LEN];
        let transcript = [2u8; SHA256_OUTPUT_LEN];
        let output = derive_secret_sha256(&secret, b"derived", &transcript).unwrap();
        assert_eq!(output.len(), SHA256_OUTPUT_LEN);
    }

    #[test]
    fn derive_secret_sha384_output_length_matches_hash() {
        let secret = [1u8; SHA384_OUTPUT_LEN];
        let transcript = [2u8; SHA384_OUTPUT_LEN];
        let output = derive_secret_sha384(&secret, b"derived", &transcript).unwrap();
        assert_eq!(output.len(), SHA384_OUTPUT_LEN);
    }

    #[test]
    fn hkdf_extract_sha256_output_length_matches_hash() {
        let ikm = vec![0x0b; 22];
        let salt: Vec<u8> = (0..13).collect();
        let prk = hkdf_extract_sha256(&salt, &ikm);
        assert_eq!(prk.len(), SHA256_OUTPUT_LEN);
        assert_eq!(prk.as_slice(), RFC5869_SHA256_PRK);
    }

    #[test]
    fn hkdf_extract_sha384_output_length_matches_hash() {
        let prk = hkdf_extract_sha384(b"salt", b"ikm");
        assert_eq!(prk.len(), SHA384_OUTPUT_LEN);
    }

    #[test]
    fn derive_traffic_key_returns_expected_lengths_for_aes128() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let traffic_secret = [0x11u8; SHA256_OUTPUT_LEN];
        let keys = derive_traffic_key(suite, &traffic_secret).expect("valid traffic key");

        assert_eq!(keys.key.len(), 16);
        assert_eq!(keys.iv.len(), 12);
    }

    #[test]
    fn derive_traffic_key_returns_expected_lengths_for_aes256() {
        let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
        let traffic_secret = [0x22u8; SHA384_OUTPUT_LEN];
        let keys = derive_traffic_key(suite, &traffic_secret).expect("valid traffic key");

        assert_eq!(keys.key.len(), 32);
        assert_eq!(keys.iv.len(), 12);
    }

    #[test]
    fn derive_finished_key_returns_hash_length() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let base_key = [0x33u8; SHA256_OUTPUT_LEN];
        let finished_key = derive_finished_key(suite, &base_key).expect("valid finished key");

        assert_eq!(finished_key.len(), hash_len(suite.hash));
        assert_eq!(finished_key.len(), SHA256_OUTPUT_LEN);
    }

    #[test]
    fn derive_traffic_key_is_deterministic() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let traffic_secret = [0x44u8; SHA256_OUTPUT_LEN];

        let first = derive_traffic_key(suite, &traffic_secret).expect("valid traffic key");
        let second = derive_traffic_key(suite, &traffic_secret).expect("valid traffic key");

        assert_eq!(first, second);
    }

    #[test]
    fn derive_traffic_key_different_labels_produce_different_outputs() {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let traffic_secret = [0x55u8; SHA256_OUTPUT_LEN];
        let keys = derive_traffic_key(suite, &traffic_secret).expect("valid traffic key");

        assert_ne!(keys.key, keys.iv);
    }
}
