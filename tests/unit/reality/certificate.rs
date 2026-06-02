
use super::*;
use crate::reality::mldsa65::{decode_mldsa65_seed, Mldsa65Seed};
use crate::reality::tls13::{
    generate_reality_ephemeral_ed25519_certificate,
    generate_reality_ephemeral_ed25519_certificate_with_layout, RealityEphemeralCertificateLayout,
};

const TEST_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
const VALID_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn sample_live_patch_context<'a>(
    seed: &'a Mldsa65Seed,
    client_hello: &'a [u8],
    server_hello: &'a [u8],
    public_key: &'a [u8; 32],
    auth_key: &'a [u8; 32],
) -> RealityMldsa65LivePatchContext<'a> {
    RealityMldsa65LivePatchContext {
        mldsa65_seed: seed,
        client_hello_original: client_hello,
        server_hello_original: server_hello,
        ed25519_public_key: public_key,
        auth_key,
    }
}

#[test]
fn future_mldsa65_live_patch_context_can_be_constructed_without_exposing_seed() {
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .expect("valid seed")
        .expect("non-empty seed");
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let context =
        sample_live_patch_context(&seed, &client_hello, &server_hello, &public_key, &auth_key);

    let debug = format!("{context:?}");
    assert!(debug.contains("redacted"));
    assert!(debug.contains("client_hello_original_len"));
    assert!(debug.contains("server_hello_original_len"));
    assert!(!debug.contains(VALID_SEED_B64));
    assert!(!debug.contains("0, 1, 2"));
}

#[test]
fn empty_client_hello_is_rejected_by_context_validation() {
    let seed = Mldsa65Seed::from_bytes([0x33; 32]);
    let server_hello = [0x04, 0x05, 0x06];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let context = sample_live_patch_context(&seed, &[], &server_hello, &public_key, &auth_key);

    let err = validate_reality_mldsa65_live_patch_context(&context).unwrap_err();
    let err_text = err.to_string();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err_text.contains("ClientHello"));
    assert!(!err_text.contains(VALID_SEED_B64));
}

#[test]
fn empty_server_hello_is_rejected_by_context_validation() {
    let seed = Mldsa65Seed::from_bytes([0x33; 32]);
    let client_hello = [0x01, 0x02, 0x03];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let context = sample_live_patch_context(&seed, &client_hello, &[], &public_key, &auth_key);

    let err = validate_reality_mldsa65_live_patch_context(&context).unwrap_err();
    let err_text = err.to_string();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err_text.contains("ServerHello"));
    assert!(!err_text.contains(VALID_SEED_B64));
}

#[test]
fn valid_live_patch_context_passes_validation() {
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .expect("valid seed")
        .expect("non-empty seed");
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let context =
        sample_live_patch_context(&seed, &client_hello, &server_hello, &public_key, &auth_key);

    validate_reality_mldsa65_live_patch_context(&context).expect("valid context");
}

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

    patch_reality_certificate_der(&mut legacy_cert, &public_key, &auth_key).expect("legacy patch");
    patch_reality_certificate_der_with_mode(RealityCertificatePatchInput {
        cert_der: &mut mode_cert,
        ed25519_public_key: &public_key,
        auth_key: &auth_key,
        mode: RealityCertificatePatchMode::HmacOnly,
    })
    .expect("mode patch");

    assert_eq!(mode_cert, legacy_cert);
}

#[test]
fn hmac_only_patch_selection_without_seed_is_unchanged() {
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];

    let mode = select_reality_certificate_patch_mode(None, &client_hello, &server_hello)
        .expect("HMAC-only mode");

    assert!(matches!(mode, RealityCertificatePatchMode::HmacOnly));
}

#[test]
fn no_seed_selects_hmac_only() {
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];

    let mode = select_reality_certificate_patch_mode(None, &client_hello, &server_hello)
        .expect("HMAC-only mode");

    assert!(matches!(mode, RealityCertificatePatchMode::HmacOnly));
}

#[test]
fn live_patch_context_with_seed_selects_hmac_plus_mldsa65() {
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .expect("valid seed")
        .expect("non-empty seed");
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];

    let mode = select_reality_certificate_patch_mode(Some(&seed), &client_hello, &server_hello)
        .expect("ML-DSA mode");

    assert!(matches!(
        mode,
        RealityCertificatePatchMode::HmacPlusMldsa65 { .. }
    ));
}

#[test]
fn seed_selects_hmac_plus_mldsa65() {
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .expect("valid seed")
        .expect("non-empty seed");
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];

    let mode = select_reality_certificate_patch_mode(Some(&seed), &client_hello, &server_hello)
        .expect("ML-DSA mode");

    assert!(matches!(
        mode,
        RealityCertificatePatchMode::HmacPlusMldsa65 { .. }
    ));
}

#[test]
fn hmac_plus_mldsa65_patch_mode_patches_der() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    use crate::reality::mldsa65_crypto::{
        derive_mldsa65_key_from_seed_for_test, verify_reality_mldsa65_signature_for_test,
    };
    use crate::reality::{
        build_reality_mldsa65_message, decode_mldsa65_verify_key,
        MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET, MLDSA65_SIGNATURE_LEN,
    };

    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
    let original = vec![0xaa; extension_end + ED25519_SIGNATURE_LEN];
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
    .expect("ML-DSA patch");

    assert_eq!(
        &cert[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET],
        &original[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET]
    );
    assert_ne!(
        &cert[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end],
        &original[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end]
    );
    let tail_start = cert.len() - ED25519_SIGNATURE_LEN;
    assert_eq!(
        &cert[extension_end..tail_start],
        &original[extension_end..tail_start]
    );
    assert_ne!(&cert[tail_start..], &original[tail_start..]);

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

#[test]
fn mldsa65_live_patch_error_does_not_fallback_to_hmac() {
    use crate::reality::{MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET, MLDSA65_SIGNATURE_LEN};

    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
    let original = vec![0xaa; extension_end - 1];
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

    let err_text = err.to_string();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(cert, original);
    assert!(err_text.contains("ML-DSA-65 extension patch"));
    assert!(!err_text.contains(VALID_SEED_B64));
}

#[test]
fn seed_patch_error_does_not_fallback_to_hmac_only() {
    use crate::reality::{MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET, MLDSA65_SIGNATURE_LEN};

    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
    let original = vec![0xaa; extension_end - 1];
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

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(cert, original);
    assert!(err.to_string().contains("ML-DSA-65 extension patch"));
    assert!(!err.to_string().contains(VALID_SEED_B64));
}

#[test]
fn mldsa65_live_patch_does_not_fallback_to_hmac_when_placeholder_missing() {
    let cert = generate_reality_ephemeral_ed25519_certificate_with_layout(
        Some("example.com"),
        RealityEphemeralCertificateLayout::LegacyHmacOnly,
    )
    .expect("legacy certificate");
    let original = cert.der.clone();
    let mut cert_der = original.clone();
    let public_key = cert.public_key_raw;
    let auth_key = [0x22; 32];
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .expect("valid seed")
        .expect("non-empty seed");

    let err = patch_reality_certificate_der_with_mode(RealityCertificatePatchInput {
        cert_der: &mut cert_der,
        ed25519_public_key: &public_key,
        auth_key: &auth_key,
        mode: RealityCertificatePatchMode::HmacPlusMldsa65 {
            mldsa65_seed: &seed,
            client_hello_original: &client_hello,
            server_hello_original: &server_hello,
        },
    })
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(cert_der, original);
    assert!(err.to_string().contains("ML-DSA-65 extension patch"));
    assert!(!err.to_string().contains(VALID_SEED_B64));
}

#[test]
fn no_seed_path_does_not_require_mldsa65_placeholder() {
    let cert = generate_reality_ephemeral_ed25519_certificate_with_layout(
        Some("example.com"),
        RealityEphemeralCertificateLayout::LegacyHmacOnly,
    )
    .expect("legacy certificate");
    let mut cert_der = cert.der.clone();
    let public_key = cert.public_key_raw;
    let auth_key = [0x22; 32];

    patch_reality_certificate_der_with_mode(RealityCertificatePatchInput {
        cert_der: &mut cert_der,
        ed25519_public_key: &public_key,
        auth_key: &auth_key,
        mode: RealityCertificatePatchMode::HmacOnly,
    })
    .expect("HMAC-only patch works without ML-DSA placeholder");

    assert_ne!(cert_der, cert.der);
}
