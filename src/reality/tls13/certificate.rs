use std::fmt;
use std::io::{Error, ErrorKind};

use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519};

use crate::reality::{MLDSA65_CERT_EXTENSION_VALUE_LEN, MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET};

use super::messages::{
    build_handshake_message, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
};

pub const SIGNATURE_SCHEME_ED25519: u16 = 0x0807;

const DEFAULT_REALITY_CERT_NAME: &str = "reality.invalid";
const MAX_U24: usize = 0x00ff_ffff;
const TLS13_CERTIFICATE_VERIFY_PAD_LEN: usize = 64;
const TLS13_CERTIFICATE_VERIFY_PAD_BYTE: u8 = 0x20;
const TLS13_CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// Ephemeral Ed25519 certificate material for the REALITY accepted TLS 1.3 path.
///
/// REALITY-specific DER patching lives in [`crate::reality::certificate`] and is not applied
/// here until the exact signature offset is ported from upstream XTLS/REALITY.
/// TODO: mldsa65 extra signature is not implemented yet.
/// TODO: This certificate builder is a protocol scaffold, not final REALITY-compatible
/// certificate behavior.
pub struct RealityEphemeralCertificate {
    pub der: Vec<u8>,
    pub public_key_der: Vec<u8>,
    pub public_key_raw: [u8; 32],
    pub signing_key: SigningKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityEphemeralCertificateLayout {
    LegacyHmacOnly,
    Mldsa65ExtensionPlaceholder,
}

impl fmt::Debug for RealityEphemeralCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityEphemeralCertificate")
            .field("der", &format!("<{} bytes>", self.der.len()))
            .field(
                "public_key_der",
                &format!("<{} bytes>", self.public_key_der.len()),
            )
            .field(
                "public_key_raw",
                &format!("<{} bytes>", self.public_key_raw.len()),
            )
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

fn rcgen_error(context: &str, err: rcgen::Error) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("REALITY ephemeral certificate {context}: {err}"),
    )
}

fn encode_u24(value: usize) -> Result<[u8; 3], Error> {
    if value > MAX_U24 {
        return Err(invalid_input(format!(
            "TLS 1.3 u24 length too large: {value} bytes (max {MAX_U24})"
        )));
    }
    let value = value as u32;
    Ok([
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ])
}

fn append_u24(bytes: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    bytes.extend_from_slice(&encode_u24(value)?);
    Ok(())
}

fn append_der_len(bytes: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        bytes.push(len as u8);
    } else if len <= 0xff {
        bytes.extend_from_slice(&[0x81, len as u8]);
    } else if len <= 0xffff {
        bytes.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        bytes.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + content.len());
    out.push(tag);
    append_der_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_wrap(0x30, content)
}

fn der_explicit_context_3(content: &[u8]) -> Vec<u8> {
    der_wrap(0xa3, content)
}

fn generate_reality_mldsa65_placeholder_certificate_der(
    signing_key: &SigningKey,
) -> std::io::Result<Vec<u8>> {
    const ED25519_ALGORITHM_IDENTIFIER: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    const VERSION_V3: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
    const SERIAL_ONE: &[u8] = &[0x02, 0x01, 0x01];
    const EMPTY_NAME: &[u8] = &[0x30, 0x00];
    const VALIDITY_UTC_1970_2099: &[u8] = b"\x30\x1e\x17\x0d700101000000Z\x17\x0d991231235959Z";
    const REALITY_MLDSA65_EXTENSION_OID: &[u8] = &[0x06, 0x05, 0x2b, 0x06, 0x01, 0x04, 0x01];

    let public_key_raw = signing_key.verifying_key().to_bytes();

    let mut subject_public_key = Vec::with_capacity(44);
    subject_public_key.extend_from_slice(ED25519_ALGORITHM_IDENTIFIER);
    subject_public_key.push(0x03);
    subject_public_key.push(0x21);
    subject_public_key.push(0x00);
    subject_public_key.extend_from_slice(&public_key_raw);
    let subject_public_key_info = der_sequence(&subject_public_key);

    let mut extension = Vec::with_capacity(
        REALITY_MLDSA65_EXTENSION_OID.len() + 4 + MLDSA65_CERT_EXTENSION_VALUE_LEN,
    );
    extension.extend_from_slice(REALITY_MLDSA65_EXTENSION_OID);
    extension.push(0x04);
    append_der_len(&mut extension, MLDSA65_CERT_EXTENSION_VALUE_LEN);
    extension.extend(std::iter::repeat_n(0u8, MLDSA65_CERT_EXTENSION_VALUE_LEN));
    let extensions = der_explicit_context_3(&der_sequence(&der_sequence(&extension)));

    let mut tbs_content = Vec::new();
    tbs_content.extend_from_slice(VERSION_V3);
    tbs_content.extend_from_slice(SERIAL_ONE);
    tbs_content.extend_from_slice(ED25519_ALGORITHM_IDENTIFIER);
    tbs_content.extend_from_slice(EMPTY_NAME);
    tbs_content.extend_from_slice(VALIDITY_UTC_1970_2099);
    tbs_content.extend_from_slice(EMPTY_NAME);
    tbs_content.extend_from_slice(&subject_public_key_info);
    tbs_content.extend_from_slice(&extensions);

    let tbs_certificate = der_sequence(&tbs_content);
    let signature = signing_key.sign(&tbs_certificate).to_bytes();
    let mut signature_value = Vec::with_capacity(1 + signature.len());
    signature_value.push(0);
    signature_value.extend_from_slice(&signature);

    let mut certificate_content =
        Vec::with_capacity(tbs_certificate.len() + ED25519_ALGORITHM_IDENTIFIER.len() + 67);
    certificate_content.extend_from_slice(&tbs_certificate);
    certificate_content.extend_from_slice(ED25519_ALGORITHM_IDENTIFIER);
    certificate_content.extend_from_slice(&der_wrap(0x03, &signature_value));

    let certificate = der_sequence(&certificate_content);
    let extension_end =
        MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_CERT_EXTENSION_VALUE_LEN;
    if certificate[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "REALITY ML-DSA-65 certificate placeholder is not at DER offset 126",
        ));
    }

    Ok(certificate)
}

/// Generates a self-signed ephemeral Ed25519 certificate for REALITY scaffold use.
pub fn generate_reality_ephemeral_ed25519_certificate(
    server_name: Option<&str>,
) -> std::io::Result<RealityEphemeralCertificate> {
    generate_reality_ephemeral_ed25519_certificate_with_layout(
        server_name,
        RealityEphemeralCertificateLayout::LegacyHmacOnly,
    )
}

pub fn generate_reality_ephemeral_ed25519_certificate_with_layout(
    server_name: Option<&str>,
    layout: RealityEphemeralCertificateLayout,
) -> std::io::Result<RealityEphemeralCertificate> {
    let name = server_name.unwrap_or(DEFAULT_REALITY_CERT_NAME);

    let mut params = CertificateParams::new(vec![name.to_string()])
        .map_err(|e| rcgen_error("parameter construction failed", e))?;
    params.distinguished_name.push(DnType::CommonName, name);

    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|e| rcgen_error("Ed25519 key generation failed", e))?;
    let public_key_der = key_pair.public_key_der();
    let signing_key = SigningKey::from_pkcs8_der(&key_pair.serialize_der()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("REALITY ephemeral certificate Ed25519 signing key decode failed: {e}"),
        )
    })?;

    let der = match layout {
        RealityEphemeralCertificateLayout::LegacyHmacOnly => params
            .self_signed(&key_pair)
            .map_err(|e| rcgen_error("self-signed certificate generation failed", e))?
            .der()
            .to_vec(),
        RealityEphemeralCertificateLayout::Mldsa65ExtensionPlaceholder => {
            generate_reality_mldsa65_placeholder_certificate_der(&signing_key)?
        }
    };
    let public_key_raw = signing_key.verifying_key().to_bytes();

    Ok(RealityEphemeralCertificate {
        der,
        public_key_der,
        public_key_raw,
        signing_key,
    })
}

/// Builds a TLS 1.3 Certificate handshake message from a DER certificate chain.
pub fn build_tls13_certificate_message(
    certificate_der_chain: &[Vec<u8>],
) -> std::io::Result<Vec<u8>> {
    if certificate_der_chain.is_empty() {
        return Err(invalid_input(
            "TLS 1.3 Certificate message requires at least one certificate",
        ));
    }

    let mut certificate_list = Vec::new();
    for certificate_der in certificate_der_chain {
        append_u24(certificate_list.as_mut(), certificate_der.len())?;
        certificate_list.extend_from_slice(certificate_der);
        certificate_list.extend_from_slice(&0u16.to_be_bytes());
    }

    let mut body = Vec::with_capacity(1 + 3 + certificate_list.len());
    body.push(0);
    append_u24(&mut body, certificate_list.len())?;
    body.extend_from_slice(&certificate_list);

    build_handshake_message(HANDSHAKE_TYPE_CERTIFICATE, &body)
}

/// Builds the TLS 1.3 CertificateVerify signed message for a server.
pub fn tls13_certificate_verify_message_to_sign(transcript_hash: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        TLS13_CERTIFICATE_VERIFY_PAD_LEN
            + TLS13_CERTIFICATE_VERIFY_CONTEXT.len()
            + 1
            + transcript_hash.len(),
    );
    message.extend(std::iter::repeat_n(
        TLS13_CERTIFICATE_VERIFY_PAD_BYTE,
        TLS13_CERTIFICATE_VERIFY_PAD_LEN,
    ));
    message.extend_from_slice(TLS13_CERTIFICATE_VERIFY_CONTEXT);
    message.push(0);
    message.extend_from_slice(transcript_hash);
    message
}

/// Builds a TLS 1.3 CertificateVerify handshake message signed with Ed25519.
pub fn build_tls13_certificate_verify_ed25519(
    signing_key: &SigningKey,
    transcript_hash: &[u8],
) -> std::io::Result<Vec<u8>> {
    let message = tls13_certificate_verify_message_to_sign(transcript_hash);
    let signature = signing_key.sign(&message);
    let signature_bytes = signature.to_bytes();

    if signature_bytes.len() > u16::MAX as usize {
        return Err(invalid_input(format!(
            "TLS 1.3 Ed25519 CertificateVerify signature too long: {} bytes (max {})",
            signature_bytes.len(),
            u16::MAX
        )));
    }

    let signature_len = u16::try_from(signature_bytes.len())
        .expect("signature length fits in u16 after validation");

    let mut body = Vec::with_capacity(2 + 2 + signature_bytes.len());
    body.extend_from_slice(&SIGNATURE_SCHEME_ED25519.to_be_bytes());
    body.extend_from_slice(&signature_len.to_be_bytes());
    body.extend_from_slice(&signature_bytes);

    build_handshake_message(HANDSHAKE_TYPE_CERTIFICATE_VERIFY, &body)
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/certificate.rs"]
mod tests;
