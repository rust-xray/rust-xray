//! REALITY-specific certificate patching, isolated from generic TLS certificate builders.
//!
//! Upstream REALITY (XTLS) generates an ephemeral Ed25519 self-signed certificate, then
//! replaces the trailing signature bytes with HMAC-SHA512(AuthKey, Ed25519 public key).

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
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::mldsa65::{decode_mldsa65_seed, Mldsa65Seed};
    use crate::reality::tls13::generate_reality_ephemeral_ed25519_certificate;

    const TEST_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
    const VALID_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

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

    #[test]
    fn patch_reality_certificate_der_with_mode_hmac_only_matches_legacy_patch() {
        let mut legacy_cert = vec![0xaa; 128];
        let mut mode_cert = legacy_cert.clone();
        let public_key = [0x11; 32];
        let auth_key = [0x22; 32];

        patch_reality_certificate_der(&mut legacy_cert, &public_key, &auth_key)
            .expect("legacy patch");
        patch_reality_certificate_der_with_mode(RealityCertificatePatchInput {
            cert_der: &mut mode_cert,
            ed25519_public_key: &public_key,
            auth_key: &auth_key,
            mode: RealityCertificatePatchMode::HmacOnly,
        })
        .expect("mode patch");

        assert_eq!(mode_cert, legacy_cert);
    }

    #[cfg(not(feature = "reality-mldsa65-crypto"))]
    #[test]
    fn hmac_plus_mldsa65_without_feature_returns_unsupported_and_does_not_mutate() {
        let original = vec![0xaa; 128];
        let mut cert = original.clone();
        let public_key = [0x11; 32];
        let auth_key = [0x22; 32];
        let client_hello = [0x01, 0x02, 0x03];
        let server_hello = [0x04, 0x05, 0x06];
        let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
            .expect("valid seed")
            .expect("non-empty seed");

        let err = patch_reality_certificate_der_with_mode(RealityCertificatePatchInput {
            cert_der: &mut cert,
            ed25519_public_key: &public_key,
            auth_key: &auth_key,
            mode: RealityCertificatePatchMode::HmacPlusMldsa65 {
                mldsa65_seed: &seed,
                client_hello_original: &client_hello,
                server_hello_original: &server_hello,
            },
        })
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(cert, original);
        let err_text = err.to_string();
        assert!(
            err_text.contains("reality-mldsa65-crypto") || err_text.contains("ML-DSA-65"),
            "unexpected error text: {err_text}"
        );
        assert!(!err_text.contains(VALID_SEED_B64));
    }

    #[cfg(not(feature = "reality-mldsa65-crypto"))]
    #[test]
    fn hmac_plus_mldsa65_mode_requires_seed_reference() {
        let mut cert = vec![0x5a; 512];
        let cert_before = cert.clone();
        let public_key = [0x31; 32];
        let auth_key = [0x42; 32];
        let client_hello = [0x01, 0x02, 0x03, 0x04];
        let server_hello = [0x05, 0x06, 0x07, 0x08];
        let seed = Mldsa65Seed::from_bytes([0x44; 32]);

        let err = patch_reality_certificate_der_with_mode(RealityCertificatePatchInput {
            cert_der: &mut cert,
            ed25519_public_key: &public_key,
            auth_key: &auth_key,
            mode: RealityCertificatePatchMode::HmacPlusMldsa65 {
                mldsa65_seed: &seed,
                client_hello_original: &client_hello,
                server_hello_original: &server_hello,
            },
        })
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(cert, cert_before);
    }

    #[cfg(feature = "reality-mldsa65-crypto")]
    #[test]
    fn hmac_plus_mldsa65_with_feature_patches_der_at_fixed_offset() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        use crate::reality::mldsa65_crypto::{
            derive_mldsa65_key_from_seed_for_test, verify_reality_mldsa65_signature_for_test,
        };
        use crate::reality::{
            build_reality_mldsa65_message, decode_mldsa65_verify_key,
            MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET, MLDSA65_SIGNATURE_LEN,
        };

        let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
        let original = vec![0xaa; extension_end + 16];
        let mut cert = original.clone();
        let public_key = [0x11; 32];
        let auth_key = [0x22; 32];
        let client_hello = [0x01, 0x02, 0x03];
        let server_hello = [0x04, 0x05, 0x06];
        let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
            .expect("valid seed")
            .expect("non-empty seed");

        patch_reality_certificate_der_with_mode(RealityCertificatePatchInput {
            cert_der: &mut cert,
            ed25519_public_key: &public_key,
            auth_key: &auth_key,
            mode: RealityCertificatePatchMode::HmacPlusMldsa65 {
                mldsa65_seed: &seed,
                client_hello_original: &client_hello,
                server_hello_original: &server_hello,
            },
        })
        .expect("offline ML-DSA patch");

        assert_eq!(
            &cert[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET],
            &original[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET]
        );
        assert_ne!(
            &cert[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end],
            &original[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end]
        );
        assert_eq!(&cert[extension_end..], &original[extension_end..]);

        let message =
            build_reality_mldsa65_message(&auth_key, &public_key, &client_hello, &server_hello);
        let derived = derive_mldsa65_key_from_seed_for_test(&seed).expect("derived key");
        let verify_b64 = URL_SAFE_NO_PAD.encode(&derived.verify_key_bytes);
        let verify_key = decode_mldsa65_verify_key(&verify_b64).expect("verify key");
        let signature = crate::reality::Mldsa65Signature::from_bytes(
            cert[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end].to_vec(),
        )
        .expect("patched signature bytes");
        verify_reality_mldsa65_signature_for_test(&verify_key, &message, &signature)
            .expect("signature verifies");
    }
}
