use std::io::{Error, ErrorKind};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

use super::cipher_suite::Tls13CipherSuite;
use super::transcript::Tls13HashAlgorithm;

const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";
const SHA256_OUTPUT_LEN: usize = 32;
const SHA384_OUTPUT_LEN: usize = 48;

/// Derived TLS 1.3 handshake traffic secrets after ClientHello + ServerHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13HandshakeSecrets {
    pub handshake_secret: Vec<u8>,
    pub client_handshake_traffic_secret: Vec<u8>,
    pub server_handshake_traffic_secret: Vec<u8>,
}

/// Derived TLS 1.3 application traffic secrets after the handshake completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13ApplicationSecrets {
    pub master_secret: Vec<u8>,
    pub client_application_traffic_secret: Vec<u8>,
    pub server_application_traffic_secret: Vec<u8>,
}

/// Derived TLS 1.3 traffic encryption material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13TrafficKeys {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
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

/// TLS 1.3 `Hash("")` for the selected hash algorithm.
pub fn empty_hash(algorithm: Tls13HashAlgorithm) -> Vec<u8> {
    match algorithm {
        Tls13HashAlgorithm::Sha256 => Sha256::digest([]).to_vec(),
        Tls13HashAlgorithm::Sha384 => Sha384::digest([]).to_vec(),
    }
}

fn hkdf_extract_for_hash(algorithm: Tls13HashAlgorithm, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match algorithm {
        Tls13HashAlgorithm::Sha256 => hkdf_extract_sha256(salt, ikm),
        Tls13HashAlgorithm::Sha384 => hkdf_extract_sha384(salt, ikm),
    }
}

fn derive_secret_for_hash(
    algorithm: Tls13HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, Error> {
    match algorithm {
        Tls13HashAlgorithm::Sha256 => derive_secret_sha256(secret, label, transcript_hash),
        Tls13HashAlgorithm::Sha384 => derive_secret_sha384(secret, label, transcript_hash),
    }
}

/// Derives TLS 1.3 handshake traffic secrets from ECDHE shared secret and transcript hash.
pub fn derive_handshake_traffic_secrets(
    suite: Tls13CipherSuite,
    ecdhe_shared_secret: &[u8],
    transcript_hash: &[u8],
) -> std::io::Result<Tls13HandshakeSecrets> {
    let output_len = hash_len(suite.hash);
    let zero = vec![0u8; output_len];

    let early_secret = hkdf_extract_for_hash(suite.hash, &zero, &zero);
    let derived_secret = derive_secret_for_hash(
        suite.hash,
        &early_secret,
        b"derived",
        &empty_hash(suite.hash),
    )?;
    let handshake_secret = hkdf_extract_for_hash(suite.hash, &derived_secret, ecdhe_shared_secret);
    let client_handshake_traffic_secret = derive_secret_for_hash(
        suite.hash,
        &handshake_secret,
        b"c hs traffic",
        transcript_hash,
    )?;
    let server_handshake_traffic_secret = derive_secret_for_hash(
        suite.hash,
        &handshake_secret,
        b"s hs traffic",
        transcript_hash,
    )?;

    Ok(Tls13HandshakeSecrets {
        handshake_secret,
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
    })
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

/// Derives the next TLS 1.3 application traffic secret after KeyUpdate.
pub fn update_traffic_secret(
    suite: Tls13CipherSuite,
    traffic_secret: &[u8],
) -> Result<Vec<u8>, Error> {
    let output_len = hash_len(suite.hash);
    hkdf_expand_label_for_hash(suite.hash, traffic_secret, b"traffic upd", b"", output_len)
}

pub fn derive_finished_key(suite: Tls13CipherSuite, base_key: &[u8]) -> Result<Vec<u8>, Error> {
    let output_len = hash_len(suite.hash);
    hkdf_expand_label_for_hash(suite.hash, base_key, b"finished", b"", output_len)
}

/// TLS 1.3 Finished verify_data: `HMAC(finished_key, transcript_hash)`.
pub fn compute_finished_verify_data(
    suite: Tls13CipherSuite,
    finished_key: &[u8],
    transcript_hash: &[u8],
) -> std::io::Result<Vec<u8>> {
    match suite.hash {
        Tls13HashAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(finished_key).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("TLS 1.3 Finished HMAC-SHA256 key invalid: {e}"),
                )
            })?;
            mac.update(transcript_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Tls13HashAlgorithm::Sha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(finished_key).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("TLS 1.3 Finished HMAC-SHA384 key invalid: {e}"),
                )
            })?;
            mac.update(transcript_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Constant-time verification of TLS 1.3 Finished verify_data.
pub fn verify_finished_data(
    suite: Tls13CipherSuite,
    finished_key: &[u8],
    transcript_hash: &[u8],
    received_verify_data: &[u8],
) -> std::io::Result<bool> {
    let expected = compute_finished_verify_data(suite, finished_key, transcript_hash)?;
    if expected.len() != received_verify_data.len() {
        return Ok(false);
    }
    Ok(expected.ct_eq(received_verify_data).into())
}

/// Derives the TLS 1.3 master secret from the handshake secret.
pub fn derive_master_secret(
    suite: Tls13CipherSuite,
    handshake_secret: &[u8],
) -> std::io::Result<Vec<u8>> {
    let output_len = hash_len(suite.hash);
    let zero_ikm = vec![0u8; output_len];
    let derived_secret = derive_secret_for_hash(
        suite.hash,
        handshake_secret,
        b"derived",
        &empty_hash(suite.hash),
    )?;
    Ok(hkdf_extract_for_hash(
        suite.hash,
        &derived_secret,
        &zero_ikm,
    ))
}

/// Derives TLS 1.3 application traffic secrets after server and client Finished.
pub fn derive_application_traffic_secrets(
    suite: Tls13CipherSuite,
    handshake_secret: &[u8],
    transcript_hash: &[u8],
) -> std::io::Result<Tls13ApplicationSecrets> {
    let master_secret = derive_master_secret(suite, handshake_secret)?;
    let client_application_traffic_secret =
        derive_secret_for_hash(suite.hash, &master_secret, b"c ap traffic", transcript_hash)?;
    let server_application_traffic_secret =
        derive_secret_for_hash(suite.hash, &master_secret, b"s ap traffic", transcript_hash)?;

    Ok(Tls13ApplicationSecrets {
        master_secret,
        client_application_traffic_secret,
        server_application_traffic_secret,
    })
}

pub fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha384>::extract(salt, ikm);
    prk.as_slice().to_vec()
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/key_schedule.rs"]
mod tests;
