use super::*;

const TEST_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
const VALID_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const SEED_31_BYTES_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg";
const SEED_33_BYTES_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";

#[test]
fn mldsa65_constants_match_expected_lengths() {
    assert_eq!(MLDSA65_SEED_LEN, 32);
    assert_eq!(MLDSA65_VERIFY_KEY_LEN, 1952);
    assert_eq!(MLDSA65_SIGNATURE_LEN, 3309);
    assert_eq!(MLDSA65_CERT_EXTENSION_VALUE_LEN, 3309);
}

#[test]
fn mldsa65_extension_constants_match_upstream_layout() {
    assert_eq!(MLDSA65_SEED_LEN, 32);
    assert_eq!(MLDSA65_VERIFY_KEY_LEN, 1952);
    assert_eq!(MLDSA65_SIGNATURE_LEN, MLDSA65_CERT_EXTENSION_VALUE_LEN);
    assert_eq!(MLDSA65_CERT_EXTENSION_VALUE_LEN, 3309);
    assert_eq!(MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET, 126);
}

#[test]
fn mldsa65_stub_does_not_mutate_cert_der() {
    let cert_before = vec![0x55; 256];
    let cert_after = cert_before.clone();
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let mldsa65_seed = Mldsa65Seed::from_bytes([0x33; 32]);

    let err = sign_reality_cert_extension_stub(
        &cert_after,
        &mldsa65_seed,
        &public_key,
        &auth_key,
        &client_hello,
        &server_hello,
    )
    .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(cert_after, cert_before);
}

fn valid_seed() -> Mldsa65Seed {
    decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .expect("valid seed")
        .expect("non-empty seed")
}

fn full_patch_range_cert_der() -> Vec<u8> {
    vec![0xaa; MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN]
}

#[test]
fn handshake_data_shape_without_any_inputs_reports_all_missing() {
    let shape = reality_mldsa65_handshake_data_shape(None, None, None, None, None, None);

    assert!(!shape.has_client_hello_original);
    assert_eq!(shape.client_hello_len, 0);
    assert!(!shape.has_server_hello_original);
    assert_eq!(shape.server_hello_len, 0);
    assert!(!shape.has_ed25519_public_key);
    assert!(!shape.has_auth_key);
    assert!(!shape.has_mldsa65_seed);
    assert_eq!(shape.cert_der_len, 0);
    assert!(!shape.cert_der_has_mldsa65_patch_range);

    let err = validate_reality_mldsa65_live_handshake_data_shape(&shape).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("ClientHello"));
}

#[test]
fn handshake_data_shape_with_valid_inputs_passes_validation() {
    let seed = valid_seed();
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let cert_der = full_patch_range_cert_der();

    let shape = reality_mldsa65_handshake_data_shape(
        Some(&client_hello),
        Some(&server_hello),
        Some(&public_key),
        Some(&auth_key),
        Some(&seed),
        Some(&cert_der),
    );

    assert!(shape.has_client_hello_original);
    assert_eq!(shape.client_hello_len, client_hello.len());
    assert!(shape.has_server_hello_original);
    assert_eq!(shape.server_hello_len, server_hello.len());
    assert!(shape.has_ed25519_public_key);
    assert!(shape.has_auth_key);
    assert!(shape.has_mldsa65_seed);
    assert_eq!(shape.cert_der_len, cert_der.len());
    assert!(shape.cert_der_has_mldsa65_patch_range);
    validate_reality_mldsa65_live_handshake_data_shape(&shape).expect("valid shape");
}

#[test]
fn handshake_data_shape_rejects_empty_client_hello() {
    let seed = valid_seed();
    let server_hello = [0x04, 0x05, 0x06];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let cert_der = full_patch_range_cert_der();

    let shape = reality_mldsa65_handshake_data_shape(
        Some(&[]),
        Some(&server_hello),
        Some(&public_key),
        Some(&auth_key),
        Some(&seed),
        Some(&cert_der),
    );

    assert!(!shape.has_client_hello_original);
    assert_eq!(shape.client_hello_len, 0);
    let err = validate_reality_mldsa65_live_handshake_data_shape(&shape).unwrap_err();
    let err_text = err.to_string();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err_text.contains("ClientHello"));
    assert!(!err_text.contains(VALID_SEED_B64));
}

#[test]
fn handshake_data_shape_rejects_empty_server_hello() {
    let seed = valid_seed();
    let client_hello = [0x01, 0x02, 0x03];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let cert_der = full_patch_range_cert_der();

    let shape = reality_mldsa65_handshake_data_shape(
        Some(&client_hello),
        Some(&[]),
        Some(&public_key),
        Some(&auth_key),
        Some(&seed),
        Some(&cert_der),
    );

    assert!(!shape.has_server_hello_original);
    assert_eq!(shape.server_hello_len, 0);
    let err = validate_reality_mldsa65_live_handshake_data_shape(&shape).unwrap_err();
    let err_text = err.to_string();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err_text.contains("ServerHello"));
    assert!(!err_text.contains(VALID_SEED_B64));
}

#[test]
fn handshake_data_shape_rejects_missing_seed() {
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let cert_der = full_patch_range_cert_der();

    let shape = reality_mldsa65_handshake_data_shape(
        Some(&client_hello),
        Some(&server_hello),
        Some(&public_key),
        Some(&auth_key),
        None,
        Some(&cert_der),
    );

    assert!(!shape.has_mldsa65_seed);
    let err = validate_reality_mldsa65_live_handshake_data_shape(&shape).unwrap_err();
    let err_text = err.to_string();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err_text.contains("mldsa65Seed"));
    assert!(!err_text.contains(VALID_SEED_B64));
}

#[test]
fn handshake_data_shape_rejects_short_cert_der() {
    let seed = valid_seed();
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let cert_der =
        vec![0xaa; MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN - 1];

    let shape = reality_mldsa65_handshake_data_shape(
        Some(&client_hello),
        Some(&server_hello),
        Some(&public_key),
        Some(&auth_key),
        Some(&seed),
        Some(&cert_der),
    );

    assert!(!shape.cert_der_has_mldsa65_patch_range);
    let err = validate_reality_mldsa65_live_handshake_data_shape(&shape).unwrap_err();
    let err_text = err.to_string();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err_text.contains("certificate DER"));
    assert!(err_text.contains("patch range"));
}

#[test]
fn handshake_data_shape_debug_does_not_expose_sensitive_bytes() {
    let seed = valid_seed();
    let client_hello = [0xaa, 0xbb, 0xcc, 0xdd];
    let server_hello = [0x10, 0x20, 0x30, 0x40];
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let cert_der = full_patch_range_cert_der();

    let shape = reality_mldsa65_handshake_data_shape(
        Some(&client_hello),
        Some(&server_hello),
        Some(&public_key),
        Some(&auth_key),
        Some(&seed),
        Some(&cert_der),
    );

    let debug = format!("{shape:?}");
    assert!(debug.contains("client_hello_len: 4"));
    assert!(debug.contains("server_hello_len: 4"));
    assert!(!debug.contains(VALID_SEED_B64));
    assert!(!debug.contains("170"));
    assert!(!debug.contains("187"));
    assert!(!debug.contains("0xaa"));
    assert!(!debug.contains("0x22"));
}

#[test]
fn mldsa65_seed_debug_does_not_expose_bytes() {
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .unwrap()
        .unwrap();
    let debug = format!("{seed:?}");
    assert_eq!(debug, "Mldsa65Seed(redacted)");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains(VALID_SEED_B64));
    assert!(!debug.contains("0, 1, 2"));
}

#[test]
fn accepts_valid_mldsa65_seed() {
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY).unwrap();
    assert!(seed.is_some());
    assert_eq!(seed.unwrap().as_bytes().len(), MLDSA65_SEED_LEN);
}

#[test]
fn rejects_invalid_base64() {
    let err = decode_mldsa65_seed(Some("not-valid-base64!!!"), TEST_PRIVATE_KEY).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("invalid mldsa65Seed base64"));
}

#[test]
fn invalid_mldsa65_seed_rejected_before_runtime() {
    let err = decode_mldsa65_seed(Some("not-valid-base64!!!"), TEST_PRIVATE_KEY).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("invalid mldsa65Seed base64"));
    assert!(!err.to_string().contains("feature gate"));
}

#[test]
fn rejects_decoded_31_bytes() {
    let err = decode_mldsa65_seed(Some(SEED_31_BYTES_B64), TEST_PRIVATE_KEY).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected 32 bytes, got 31"));
}

#[test]
fn rejects_decoded_33_bytes() {
    let err = decode_mldsa65_seed(Some(SEED_33_BYTES_B64), TEST_PRIVATE_KEY).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected 32 bytes, got 33"));
}

#[test]
fn empty_seed_is_none() {
    assert!(decode_mldsa65_seed(None, TEST_PRIVATE_KEY)
        .unwrap()
        .is_none());
    assert!(decode_mldsa65_seed(Some(""), TEST_PRIVATE_KEY)
        .unwrap()
        .is_none());
}

#[test]
fn seed_equal_private_key_is_rejected() {
    let err = decode_mldsa65_seed(Some(TEST_PRIVATE_KEY), TEST_PRIVATE_KEY).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("must not equal privateKey"));
}

fn b64url_no_pad(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn mldsa65_verify_key_debug_does_not_expose_bytes() {
    let verify_b64 = b64url_no_pad(&vec![0x42; MLDSA65_VERIFY_KEY_LEN]);
    let verify = decode_mldsa65_verify_key(&verify_b64).unwrap();
    let debug = format!("{verify:?}");
    assert_eq!(debug, "Mldsa65VerifyKey(redacted)");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains(&verify_b64));
    assert!(!debug.contains("66"));
}

#[test]
fn decode_mldsa65_verify_key_rejects_empty_string() {
    let err = decode_mldsa65_verify_key("").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("must not be empty"));
}

#[test]
fn decode_mldsa65_verify_key_rejects_invalid_base64() {
    let err = decode_mldsa65_verify_key("not-valid-base64!!!").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("invalid mldsa65Verify base64"));
}

#[test]
fn decode_mldsa65_verify_key_rejects_wrong_lengths() {
    let verify_1951 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN - 1]);
    let err = decode_mldsa65_verify_key(&verify_1951).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected 1952 bytes, got 1951"));

    let verify_1953 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN + 1]);
    let err = decode_mldsa65_verify_key(&verify_1953).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected 1952 bytes, got 1953"));
}

#[test]
fn decode_mldsa65_verify_key_accepts_1952_bytes() {
    let verify_b64 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN]);
    let verify = decode_mldsa65_verify_key(&verify_b64).unwrap();
    assert_eq!(verify.as_bytes().len(), MLDSA65_VERIFY_KEY_LEN);
}

#[test]
fn sign_reality_mldsa65_message_returns_3309_byte_signature() {
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .unwrap()
        .unwrap();
    let message = [0x42; 64];

    let signature = sign_reality_mldsa65_message(&seed, &message).expect("valid signature");

    assert_eq!(signature.as_bytes().len(), MLDSA65_SIGNATURE_LEN);
    let debug = format!("{signature:?}");
    assert_eq!(debug, "Mldsa65Signature(redacted)");
    assert!(!debug.contains(VALID_SEED_B64));
}

#[test]
fn sign_reality_cert_extension_returns_3309_byte_signature() {
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .unwrap()
        .unwrap();
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];

    let signature =
        sign_reality_cert_extension(&seed, &public_key, &auth_key, &client_hello, &server_hello)
            .expect("valid certificate extension signature");

    assert_eq!(signature.as_bytes().len(), MLDSA65_SIGNATURE_LEN);
}

#[test]
fn patch_reality_cert_der_with_mldsa65_signature_writes_at_fixed_offset() {
    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
    let mut cert_der = vec![0xaa; extension_end + 16];
    let cert_before = cert_der.clone();
    let seed = decode_mldsa65_seed(Some(VALID_SEED_B64), TEST_PRIVATE_KEY)
        .unwrap()
        .unwrap();
    let signature = sign_reality_mldsa65_message(&seed, &[0x33; 64]).expect("valid signature");

    patch_reality_cert_der_with_mldsa65_signature(&mut cert_der, &signature)
        .expect("valid extension write");

    assert_eq!(
        &cert_der[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET],
        &cert_before[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET]
    );
    assert_eq!(
        &cert_der[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end],
        signature.as_bytes()
    );
    assert_eq!(&cert_der[extension_end..], &cert_before[extension_end..]);
}

#[test]
fn patch_reality_cert_der_with_mldsa65_signature_rejects_short_der_without_mutation() {
    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
    let mut cert_der = vec![0xaa; extension_end - 1];
    let cert_before = cert_der.clone();
    let signature = Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_SIGNATURE_LEN]).unwrap();

    let err = patch_reality_cert_der_with_mldsa65_signature(&mut cert_der, &signature).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(cert_der, cert_before);
}

#[test]
fn write_reality_mldsa65_cert_extension_signature_writes_at_offset() {
    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
    let mut cert_der = vec![0xaa; extension_end + 64];
    let signature = Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_SIGNATURE_LEN]).unwrap();

    patch_reality_cert_der_with_mldsa65_signature(&mut cert_der, &signature)
        .expect("valid extension write");

    assert_eq!(
        &cert_der[MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end],
        signature.as_bytes()
    );
    assert_eq!(
        &cert_der[..MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET],
        &[0xaa; 126]
    );
    assert_eq!(&cert_der[extension_end..], &[0xaa; 64]);
}

#[test]
fn write_reality_mldsa65_cert_extension_signature_rejects_too_short_cert() {
    let extension_end = MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET + MLDSA65_SIGNATURE_LEN;
    let mut cert_der = vec![0xaa; extension_end - 1];
    let cert_before = cert_der.clone();
    let signature = Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_SIGNATURE_LEN]).unwrap();

    let err = patch_reality_cert_der_with_mldsa65_signature(&mut cert_der, &signature).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(cert_der, cert_before);
}

#[test]
fn mldsa65_signature_debug_does_not_expose_bytes() {
    let signature = Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_SIGNATURE_LEN]).unwrap();
    let debug = format!("{signature:?}");
    assert_eq!(debug, "Mldsa65Signature(redacted)");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("66"));
}

#[test]
fn mldsa65_signature_debug_redacted() {
    let signature = Mldsa65Signature::from_bytes(vec![0x42; MLDSA65_SIGNATURE_LEN]).unwrap();
    let debug = format!("{signature:?}");
    assert_eq!(debug, "Mldsa65Signature(redacted)");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("66"));
}

#[test]
fn build_reality_mldsa65_message_matches_manual_hmac() {
    let auth_key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x00, 0x01,
    ];
    let ed25519_public_key = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x10, 0x11,
    ];
    let client_hello_original = [0x01, 0x02, 0x03, 0x04];
    let server_hello_original = [0x02, 0x03, 0x04, 0x05];

    let actual = build_reality_mldsa65_message(
        &auth_key,
        &ed25519_public_key,
        &client_hello_original,
        &server_hello_original,
    );

    let mut mac = Hmac::<Sha512>::new_from_slice(&auth_key).expect("valid HMAC key");
    mac.update(&ed25519_public_key);
    mac.update(&client_hello_original);
    mac.update(&server_hello_original);
    let expected: [u8; 64] = mac.finalize().into_bytes().into();

    assert_eq!(actual, expected);
}
