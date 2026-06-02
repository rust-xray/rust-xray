//! REALITY-specific certificate patching, isolated from generic TLS certificate builders.
//!
//! Upstream REALITY (XTLS) generates an ephemeral Ed25519 self-signed certificate, then
//! replaces the trailing signature bytes with HMAC-SHA512(AuthKey, Ed25519 public key).

use std::fmt;
use std::io::{Error, ErrorKind};

use hmac::{Hmac, Mac};
use sha2::Sha512;

const ED25519_SIGNATURE_LEN: usize = 64;

type HmacSha512 = Hmac<Sha512>;

pub enum RealityCertificatePatchMode<'a> {
    HmacOnly,
    HmacPlusMldsa65 {
        mldsa65_seed: &'a crate::reality::mldsa65::Mldsa65Seed,
        client_hello_original: &'a [u8],
        server_hello_original: &'a [u8],
    },
}

pub struct RealityCertificatePatchInput<'a> {
    pub cert_der: &'a mut [u8],
    pub ed25519_public_key: &'a [u8; 32],
    pub auth_key: &'a [u8; 32],
    pub mode: RealityCertificatePatchMode<'a>,
}

pub fn select_reality_certificate_patch_mode<'a>(
    mldsa65_seed: Option<&'a crate::reality::mldsa65::Mldsa65Seed>,
    client_hello_original: &'a [u8],
    server_hello_original: &'a [u8],
) -> std::io::Result<RealityCertificatePatchMode<'a>> {
    match mldsa65_seed {
        Some(seed) => {
            if client_hello_original.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "REALITY ML-DSA-65 certificate patch requires non-empty ClientHello original bytes",
                ));
            }

            if server_hello_original.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "REALITY ML-DSA-65 certificate patch requires non-empty ServerHello original bytes",
                ));
            }

            Ok(RealityCertificatePatchMode::HmacPlusMldsa65 {
                mldsa65_seed: seed,
                client_hello_original,
                server_hello_original,
            })
        }
        None => Ok(RealityCertificatePatchMode::HmacOnly),
    }
}

/// Future live REALITY ML-DSA-65 certificate patch inputs.
///
/// Holds borrowed transcript and key material for a later integration block.
/// Not used by the accepted TLS handshake path today.
pub struct RealityMldsa65LivePatchContext<'a> {
    pub mldsa65_seed: &'a crate::reality::mldsa65::Mldsa65Seed,
    pub client_hello_original: &'a [u8],
    pub server_hello_original: &'a [u8],
    pub ed25519_public_key: &'a [u8; 32],
    pub auth_key: &'a [u8; 32],
}

impl fmt::Debug for RealityMldsa65LivePatchContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityMldsa65LivePatchContext")
            .field("mldsa65_seed", &"<redacted>")
            .field(
                "client_hello_original_len",
                &self.client_hello_original.len(),
            )
            .field(
                "server_hello_original_len",
                &self.server_hello_original.len(),
            )
            .field("ed25519_public_key", &"<redacted>")
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

/// Validates shape of a future live ML-DSA certificate patch context.
///
/// Does not sign, mutate DER, or touch runtime state.
pub fn validate_reality_mldsa65_live_patch_context(
    context: &RealityMldsa65LivePatchContext<'_>,
) -> std::io::Result<()> {
    if context.client_hello_original.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "REALITY ML-DSA-65 live patch context requires non-empty ClientHello bytes",
        ));
    }

    if context.server_hello_original.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "REALITY ML-DSA-65 live patch context requires non-empty ServerHello bytes",
        ));
    }

    Ok(())
}

/// Returns true when `cert_der` is long enough for the REALITY Ed25519 tail signature patch.
pub fn certificate_der_has_ed25519_signature_tail(cert_der: &[u8]) -> bool {
    cert_der.len() >= ED25519_SIGNATURE_LEN
}

/// Patches a REALITY ephemeral certificate DER in place by replacing the last 64 bytes with
/// HMAC-SHA512(auth_key, ed25519_public_key).
pub fn patch_reality_certificate_der(
    cert_der: &mut [u8],
    ed25519_public_key: &[u8; 32],
    auth_key: &[u8; 32],
) -> std::io::Result<()> {
    if cert_der.len() < ED25519_SIGNATURE_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "REALITY certificate DER too short for Ed25519 signature patch: {} bytes (need >= {ED25519_SIGNATURE_LEN})",
                cert_der.len()
            ),
        ));
    }

    if !certificate_der_has_ed25519_signature_tail(cert_der) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "REALITY certificate DER does not have Ed25519 signature tail layout",
        ));
    }

    let mut mac = HmacSha512::new_from_slice(auth_key).map_err(|err| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("REALITY certificate HMAC key rejected: {err}"),
        )
    })?;
    mac.update(ed25519_public_key);
    let digest = mac.finalize().into_bytes();

    let tail_start = cert_der.len() - ED25519_SIGNATURE_LEN;
    cert_der[tail_start..].copy_from_slice(&digest);

    Ok(())
}

pub fn patch_reality_certificate_der_with_mode(
    input: RealityCertificatePatchInput<'_>,
) -> std::io::Result<()> {
    match input.mode {
        RealityCertificatePatchMode::HmacOnly => {
            patch_reality_certificate_der(input.cert_der, input.ed25519_public_key, input.auth_key)
        }
        RealityCertificatePatchMode::HmacPlusMldsa65 {
            mldsa65_seed,
            client_hello_original,
            server_hello_original,
        } => {
            let extension_end = crate::reality::MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET
                + crate::reality::MLDSA65_SIGNATURE_LEN;
            if input.cert_der.len() < extension_end {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "REALITY certificate DER too short for ML-DSA-65 extension patch: {} bytes (need >= {extension_end})",
                        input.cert_der.len()
                    ),
                ));
            }

            if input.cert_der.len() - ED25519_SIGNATURE_LEN < extension_end {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "REALITY certificate ML-DSA-65 extension patch range overlaps Ed25519 signature tail",
                ));
            }

            let signature = crate::reality::mldsa65::sign_reality_cert_extension(
                mldsa65_seed,
                input.ed25519_public_key,
                input.auth_key,
                client_hello_original,
                server_hello_original,
            )?;

            crate::reality::mldsa65::patch_reality_cert_der_with_mldsa65_signature(
                input.cert_der,
                &signature,
            )?;
            patch_reality_certificate_der(input.cert_der, input.ed25519_public_key, input.auth_key)
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/reality/certificate.rs"]
mod tests;
