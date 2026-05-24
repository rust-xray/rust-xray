//! REALITY-specific certificate patching, isolated from generic TLS certificate builders.
//!
//! Upstream REALITY (XTLS) does not send a plain rcgen/self-signed certificate as-is.
//! It generates an ephemeral Ed25519 certificate, then patches the DER signature area using
//! HMAC-SHA512 over the REALITY auth key, Ed25519 public key, and handshake context.
//! An optional `mldsa65` extra signature extension may also be embedded.
//!
//! # TODO (upstream port)
//!
//! - Port exact `signedCert` / TBSCertificate layout handling from upstream XTLS/REALITY.
//! - Verify the fixed signature offset for the generated certificate DER used on the accepted path.
//! - Implement non-`mldsa65` HMAC-SHA512 patch once the offset is validated (do not guess).
//! - Locate and implement the `mldsa65` extra extension insertion point (not in this step).

use std::io::{Error, ErrorKind};

const UNSUPPORTED_PATCH_OFFSET_MSG: &str =
    "REALITY certificate DER patch offset is not implemented yet";

/// Inputs required to compute and apply the REALITY certificate DER patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityCertificatePatchInput<'a> {
    pub auth_key: &'a [u8; 32],
    pub client_hello_message: &'a [u8],
    pub server_hello_message: &'a [u8],
    pub mldsa65_seed: Option<&'a [u8]>,
}

/// Patches a REALITY ephemeral certificate DER in place.
///
/// This function must not write into the DER until the exact signature offset for the
/// accepted-path certificate layout is verified against upstream REALITY behavior.
///
/// rcgen-generated certificates do not have a stable, verified patch offset in this
/// project yet, so this currently returns [`ErrorKind::Unsupported`] without mutating
/// `cert_der`.
pub fn patch_reality_certificate_der(
    cert_der: &mut [u8],
    ed25519_public_key: &[u8],
    input: RealityCertificatePatchInput<'_>,
) -> std::io::Result<()> {
    validate_patch_inputs(ed25519_public_key, &input)?;

    if input.mldsa65_seed.is_some() {
        // TODO: implement mldsa65 extra signature extension location and payload layout.
        return Err(Error::new(
            ErrorKind::Unsupported,
            "REALITY mldsa65 certificate extension is not implemented yet",
        ));
    }

    // TODO: compute HMAC-SHA512(auth_key, ed25519_public_key, client_hello, server_hello)
    // using the upstream REALITY algorithm once the signature offset is known.
    //
    // TODO: write the digest into cert_der[signature_offset..signature_offset + patch_len]
    // only after signature_offset is validated for the generated DER layout.
    let _ = cert_der;

    Err(Error::new(
        ErrorKind::Unsupported,
        UNSUPPORTED_PATCH_OFFSET_MSG,
    ))
}

fn validate_patch_inputs(
    ed25519_public_key: &[u8],
    input: &RealityCertificatePatchInput<'_>,
) -> std::io::Result<()> {
    if ed25519_public_key.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "REALITY certificate patch requires non-empty Ed25519 public key",
        ));
    }

    if input.client_hello_message.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "REALITY certificate patch requires ClientHello handshake message",
        ));
    }

    if input.server_hello_message.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "REALITY certificate patch requires ServerHello handshake message",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::tls13::generate_reality_ephemeral_ed25519_certificate;

    fn sample_patch_input<'a>(
        auth_key: &'a [u8; 32],
        client_hello: &'a [u8],
        server_hello: &'a [u8],
    ) -> RealityCertificatePatchInput<'a> {
        RealityCertificatePatchInput {
            auth_key,
            client_hello_message: client_hello,
            server_hello_message: server_hello,
            mldsa65_seed: None,
        }
    }

    #[test]
    fn patch_reality_certificate_der_returns_unsupported_for_rcgen_cert() {
        let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
            .expect("valid ephemeral certificate");
        let mut cert_der = cert.der.clone();
        let original = cert_der.clone();
        let auth_key = [0xAA; 32];
        let client_hello = [0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00];
        let server_hello = [0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00];
        let input = sample_patch_input(&auth_key, &client_hello, &server_hello);

        let err =
            patch_reality_certificate_der(&mut cert_der, &cert.public_key_der, input).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.to_string(), UNSUPPORTED_PATCH_OFFSET_MSG);
        assert_eq!(cert_der, original);
    }

    #[test]
    fn patch_reality_certificate_der_does_not_mutate_cert_on_unsupported() {
        let cert = generate_reality_ephemeral_ed25519_certificate(None).expect("valid cert");
        let mut cert_der = cert.der.clone();
        let digest_before = cert_der.clone();
        let auth_key = [0xBB; 32];

        let err = patch_reality_certificate_der(
            &mut cert_der,
            cert.public_key_der.as_slice(),
            sample_patch_input(
                &auth_key,
                &[0x01, 0x00, 0x00, 0x01, 0x00],
                &[0x02, 0x00, 0x00, 0x01, 0x00],
            ),
        )
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(cert_der, digest_before);
    }

    #[test]
    fn patch_reality_certificate_der_mldsa65_seed_returns_unsupported_without_mutation() {
        let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
            .expect("valid ephemeral certificate");
        let mut cert_der = cert.der.clone();
        let original = cert_der.clone();
        let auth_key = [0xCC; 32];
        let mldsa65_seed = [0xDD; 32];
        let input = RealityCertificatePatchInput {
            auth_key: &auth_key,
            client_hello_message: &[0x01, 0x00, 0x00, 0x01, 0x00],
            server_hello_message: &[0x02, 0x00, 0x00, 0x01, 0x00],
            mldsa65_seed: Some(&mldsa65_seed),
        };

        let err =
            patch_reality_certificate_der(&mut cert_der, &cert.public_key_der, input).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("mldsa65"));
        assert_eq!(cert_der, original);
    }
}
