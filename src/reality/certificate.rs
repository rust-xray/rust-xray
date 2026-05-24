//! REALITY-specific certificate patching, isolated from generic TLS certificate builders.
//!
//! Upstream REALITY (XTLS) generates an ephemeral Ed25519 self-signed certificate, then
//! replaces the trailing signature bytes with HMAC-SHA512(AuthKey, Ed25519 public key).

use std::io::{Error, ErrorKind};

use hmac::{Hmac, Mac};
use sha2::Sha512;

const ED25519_SIGNATURE_LEN: usize = 64;

type HmacSha512 = Hmac<Sha512>;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::tls13::generate_reality_ephemeral_ed25519_certificate;

    fn expected_reality_cert_hmac(auth_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 64] {
        let mut mac = HmacSha512::new_from_slice(auth_key).expect("valid HMAC key");
        mac.update(public_key);
        mac.finalize().into_bytes().into()
    }

    #[test]
    fn patch_reality_certificate_der_replaces_last_64_bytes() {
        let mut cert = vec![0xaa; 128];
        let public_key = [0x11; 32];
        let auth_key = [0x22; 32];
        let expected = expected_reality_cert_hmac(&auth_key, &public_key);

        patch_reality_certificate_der(&mut cert, &public_key, &auth_key).expect("valid patch");

        assert_eq!(&cert[..64], &[0xaa; 64]);
        assert_eq!(&cert[64..], expected);
    }

    #[test]
    fn patch_reality_certificate_der_rejects_too_short_cert() {
        let mut cert = vec![0xaa; 63];
        let public_key = [0x11; 32];
        let auth_key = [0x22; 32];

        let err = patch_reality_certificate_der(&mut cert, &public_key, &auth_key).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("too short"));
        assert_eq!(cert, vec![0xaa; 63]);
    }

    #[test]
    fn rcgen_certificate_der_has_ed25519_signature_tail() {
        let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
            .expect("valid ephemeral certificate");

        assert!(certificate_der_has_ed25519_signature_tail(&cert.der));
        assert_eq!(cert.der[cert.der.len() - 65], 0x00);
    }

    #[test]
    fn patch_reality_certificate_der_works_for_rcgen_certificate() {
        let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
            .expect("valid ephemeral certificate");
        let mut cert_der = cert.der.clone();
        let auth_key = [0x33; 32];
        let expected = expected_reality_cert_hmac(&auth_key, &cert.public_key_raw);

        patch_reality_certificate_der(&mut cert_der, &cert.public_key_raw, &auth_key)
            .expect("rcgen certificate supports tail signature patch");

        assert_eq!(&cert_der[cert_der.len() - 64..], expected);
        assert_ne!(cert_der, cert.der);
    }
}
