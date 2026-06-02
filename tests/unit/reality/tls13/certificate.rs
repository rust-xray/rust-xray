use super::*;
use ed25519_dalek::{Verifier, VerifyingKey};

#[test]
fn generate_reality_ephemeral_ed25519_certificate_returns_non_empty_der() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");

    assert!(!cert.der.is_empty());
    assert!(!cert.public_key_der.is_empty());
}

#[test]
fn generate_reality_ephemeral_ed25519_certificate_exposes_raw_public_key() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");

    assert_eq!(cert.public_key_raw.len(), 32);
    assert!(!cert.der.is_empty());
    assert_eq!(
        cert.public_key_raw,
        cert.signing_key.verifying_key().to_bytes()
    );
}

#[test]
fn generate_reality_ephemeral_ed25519_certificate_uses_default_name_when_none() {
    let cert =
        generate_reality_ephemeral_ed25519_certificate(None).expect("valid ephemeral certificate");

    assert!(!cert.der.is_empty());
}

#[test]
fn generated_hmac_only_certificate_der_keeps_legacy_layout() {
    let cert = generate_reality_ephemeral_ed25519_certificate_with_layout(
        Some("example.com"),
        RealityEphemeralCertificateLayout::LegacyHmacOnly,
    )
    .expect("valid legacy certificate");
    let extension_end =
        MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_CERT_EXTENSION_VALUE_LEN;

    assert!(cert.der.len() < extension_end);
    assert_eq!(
        cert.public_key_raw,
        cert.signing_key.verifying_key().to_bytes()
    );
}

#[test]
fn generated_mldsa65_certificate_der_contains_placeholder_patch_range() {
    let cert = generate_reality_ephemeral_ed25519_certificate_with_layout(
        Some("example.com"),
        RealityEphemeralCertificateLayout::Mldsa65ExtensionPlaceholder,
    )
    .expect("valid ML-DSA placeholder certificate");
    let extension_end =
        MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_CERT_EXTENSION_VALUE_LEN;

    assert!(cert.der.len() >= extension_end);
    assert!(
        cert.der[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn generated_mldsa65_certificate_der_patch_writes_signature_at_offset_126() {
    use crate::reality::{patch_reality_cert_der_with_mldsa65_signature, Mldsa65Signature};

    let cert = generate_reality_ephemeral_ed25519_certificate_with_layout(
        Some("example.com"),
        RealityEphemeralCertificateLayout::Mldsa65ExtensionPlaceholder,
    )
    .expect("valid ML-DSA placeholder certificate");
    let mut cert_der = cert.der.clone();
    let original = cert_der.clone();
    let signature = Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_CERT_EXTENSION_VALUE_LEN])
        .expect("test signature");
    let extension_end =
        MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_CERT_EXTENSION_VALUE_LEN;

    patch_reality_cert_der_with_mldsa65_signature(&mut cert_der, &signature)
        .expect("patch placeholder");

    assert_eq!(
        &cert_der[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET],
        &original[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET]
    );
    assert_eq!(
        &cert_der[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end],
        signature.as_bytes()
    );
    assert_eq!(&cert_der[extension_end..], &original[extension_end..]);
}

#[test]
fn build_tls13_certificate_message_starts_with_certificate_handshake_type() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let message = build_tls13_certificate_message(&[cert.der]).expect("valid certificate message");

    assert_eq!(message[0], HANDSHAKE_TYPE_CERTIFICATE);
}

#[test]
fn build_tls13_certificate_message_declared_length_matches_body() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let message = build_tls13_certificate_message(&[cert.der]).expect("valid certificate message");

    let declared_len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
    assert_eq!(declared_len, message.len() - 4);
}

#[test]
fn build_tls13_certificate_message_certificate_request_context_length_is_zero() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let message = build_tls13_certificate_message(&[cert.der]).expect("valid certificate message");

    assert_eq!(message[4], 0);
}

#[test]
fn build_tls13_certificate_message_certificate_list_length_includes_entry() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let certificate_der = cert.der.clone();
    let message = build_tls13_certificate_message(std::slice::from_ref(&certificate_der))
        .expect("valid certificate message");

    let certificate_list_len = u32::from_be_bytes([0, message[5], message[6], message[7]]) as usize;
    let per_entry_overhead = 3 + 2;
    assert_eq!(
        certificate_list_len,
        certificate_der.len() + per_entry_overhead
    );
    assert_eq!(
        &message[8..8 + 3],
        &encode_u24(certificate_der.len()).unwrap()
    );
    assert_eq!(
        &message[8 + 3..8 + 3 + certificate_der.len()],
        certificate_der.as_slice()
    );
}

#[test]
fn debug_does_not_expose_private_key() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let debug = format!("{cert:?}");

    assert!(debug.contains("signing_key"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&format!("{:?}", cert.signing_key.to_bytes())));
}

#[test]
fn tls13_certificate_verify_message_to_sign_starts_with_sixty_four_spaces() {
    let message = tls13_certificate_verify_message_to_sign(&[0xAA; 32]);

    assert_eq!(
        message.len(),
        64 + TLS13_CERTIFICATE_VERIFY_CONTEXT.len() + 1 + 32
    );
    assert!(message[..64].iter().all(|byte| *byte == 0x20));
}

#[test]
fn tls13_certificate_verify_message_to_sign_contains_context_string() {
    let message = tls13_certificate_verify_message_to_sign(&[0xBB; 32]);
    let context_start = 64;

    assert_eq!(
        &message[context_start..context_start + TLS13_CERTIFICATE_VERIFY_CONTEXT.len()],
        TLS13_CERTIFICATE_VERIFY_CONTEXT
    );
    assert_eq!(
        message[context_start + TLS13_CERTIFICATE_VERIFY_CONTEXT.len()],
        0
    );
}

#[test]
fn tls13_certificate_verify_message_to_sign_ends_with_transcript_hash() {
    let transcript_hash = [0xCC; 48];
    let message = tls13_certificate_verify_message_to_sign(&transcript_hash);

    assert_eq!(
        &message[message.len() - transcript_hash.len()..],
        transcript_hash
    );
}

#[test]
fn build_tls13_certificate_verify_ed25519_starts_with_certificate_verify_type() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let message = build_tls13_certificate_verify_ed25519(&cert.signing_key, &[0xDD; 32])
        .expect("valid CertificateVerify message");

    assert_eq!(message[0], HANDSHAKE_TYPE_CERTIFICATE_VERIFY);
}

#[test]
fn build_tls13_certificate_verify_ed25519_uses_ed25519_signature_scheme() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let message = build_tls13_certificate_verify_ed25519(&cert.signing_key, &[0xEE; 32])
        .expect("valid CertificateVerify message");

    assert_eq!(
        u16::from_be_bytes([message[4], message[5]]),
        SIGNATURE_SCHEME_ED25519
    );
}

#[test]
fn build_tls13_certificate_verify_ed25519_signature_length_is_non_zero() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let message = build_tls13_certificate_verify_ed25519(&cert.signing_key, &[0xFF; 32])
        .expect("valid CertificateVerify message");

    let signature_len = u16::from_be_bytes([message[6], message[7]]) as usize;
    assert!(signature_len > 0);
    assert_eq!(signature_len, 64);
    assert_eq!(
        &message[8..8 + signature_len],
        &message[8..8 + signature_len]
    );
}

#[test]
fn build_tls13_certificate_verify_ed25519_signature_verifies_with_public_key() {
    let cert = generate_reality_ephemeral_ed25519_certificate(Some("example.com"))
        .expect("valid ephemeral certificate");
    let transcript_hash = [0x11; 32];
    let signed_message = tls13_certificate_verify_message_to_sign(&transcript_hash);
    let message = build_tls13_certificate_verify_ed25519(&cert.signing_key, &transcript_hash)
        .expect("valid CertificateVerify message");

    let signature_len = u16::from_be_bytes([message[6], message[7]]) as usize;
    let signature_bytes = &message[8..8 + signature_len];
    let signature = ed25519_dalek::Signature::from_bytes(
        signature_bytes
            .try_into()
            .expect("Ed25519 signature is 64 bytes"),
    );
    let verifying_key = VerifyingKey::from(&cert.signing_key);

    verifying_key
        .verify(&signed_message, &signature)
        .expect("CertificateVerify signature verifies");
}
