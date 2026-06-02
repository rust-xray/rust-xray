
use super::*;
use crate::reality::tls13::{tls13_cipher_suite, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384};

const RFC5869_SHA256_PRK: [u8; 32] = [
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
];

const DERIVED_SECRET_EMPTY_SHA256: [u8; 32] = [
    0x38, 0x3b, 0x35, 0xaa, 0xbd, 0x60, 0xa0, 0x96, 0x40, 0x00, 0x34, 0x9d, 0x9e, 0x7b, 0x52, 0x43,
    0x4d, 0x9a, 0x3e, 0xbb, 0x55, 0x1c, 0xf6, 0x4a, 0xcb, 0x75, 0x46, 0xf3, 0xe9, 0x43, 0x18, 0xd3,
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
fn empty_hash_sha256_matches_known_digest() {
    assert_eq!(
        empty_hash(Tls13HashAlgorithm::Sha256),
        Sha256::digest([]).as_slice()
    );
}

#[test]
fn empty_hash_sha384_matches_known_digest() {
    assert_eq!(
        empty_hash(Tls13HashAlgorithm::Sha384),
        Sha384::digest([]).as_slice()
    );
}

#[test]
fn derive_handshake_traffic_secrets_output_lengths_match_hash_len_sha256() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let ecdhe = [0x10u8; 32];
    let transcript = [0x20u8; SHA256_OUTPUT_LEN];

    let secrets = derive_handshake_traffic_secrets(suite, &ecdhe, &transcript)
        .expect("valid handshake secrets");

    assert_eq!(secrets.handshake_secret.len(), SHA256_OUTPUT_LEN);
    assert_eq!(
        secrets.client_handshake_traffic_secret.len(),
        SHA256_OUTPUT_LEN
    );
    assert_eq!(
        secrets.server_handshake_traffic_secret.len(),
        SHA256_OUTPUT_LEN
    );
}

#[test]
fn derive_handshake_traffic_secrets_output_lengths_match_hash_len_sha384() {
    let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
    let ecdhe = [0x10u8; 32];
    let transcript = [0x20u8; SHA384_OUTPUT_LEN];

    let secrets = derive_handshake_traffic_secrets(suite, &ecdhe, &transcript)
        .expect("valid handshake secrets");

    assert_eq!(secrets.handshake_secret.len(), SHA384_OUTPUT_LEN);
    assert_eq!(
        secrets.client_handshake_traffic_secret.len(),
        SHA384_OUTPUT_LEN
    );
    assert_eq!(
        secrets.server_handshake_traffic_secret.len(),
        SHA384_OUTPUT_LEN
    );
}

#[test]
fn derive_handshake_traffic_secrets_is_deterministic() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let ecdhe = [0x55u8; 32];
    let transcript = [0x66u8; SHA256_OUTPUT_LEN];

    let first = derive_handshake_traffic_secrets(suite, &ecdhe, &transcript)
        .expect("valid handshake secrets");
    let second = derive_handshake_traffic_secrets(suite, &ecdhe, &transcript)
        .expect("valid handshake secrets");

    assert_eq!(first, second);
}

#[test]
fn derive_handshake_traffic_secrets_different_transcript_changes_traffic_secrets() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let ecdhe = [0x77u8; 32];
    let transcript_a = [0x01u8; SHA256_OUTPUT_LEN];
    let transcript_b = [0x02u8; SHA256_OUTPUT_LEN];

    let secrets_a = derive_handshake_traffic_secrets(suite, &ecdhe, &transcript_a)
        .expect("valid handshake secrets");
    let secrets_b = derive_handshake_traffic_secrets(suite, &ecdhe, &transcript_b)
        .expect("valid handshake secrets");

    assert_eq!(secrets_a.handshake_secret, secrets_b.handshake_secret);
    assert_ne!(
        secrets_a.client_handshake_traffic_secret,
        secrets_b.client_handshake_traffic_secret
    );
    assert_ne!(
        secrets_a.server_handshake_traffic_secret,
        secrets_b.server_handshake_traffic_secret
    );
}

#[test]
fn derive_handshake_traffic_secrets_different_ecdhe_changes_handshake_secret() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let ecdhe_a = [0x88u8; 32];
    let ecdhe_b = [0x99u8; 32];
    let transcript = [0xAAu8; SHA256_OUTPUT_LEN];

    let secrets_a = derive_handshake_traffic_secrets(suite, &ecdhe_a, &transcript)
        .expect("valid handshake secrets");
    let secrets_b = derive_handshake_traffic_secrets(suite, &ecdhe_b, &transcript)
        .expect("valid handshake secrets");

    assert_ne!(secrets_a.handshake_secret, secrets_b.handshake_secret);
    assert_ne!(
        secrets_a.client_handshake_traffic_secret,
        secrets_b.client_handshake_traffic_secret
    );
    assert_ne!(
        secrets_a.server_handshake_traffic_secret,
        secrets_b.server_handshake_traffic_secret
    );
}

#[test]
fn compute_finished_verify_data_output_length_matches_hash_len_sha256() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let finished_key = [0x77u8; SHA256_OUTPUT_LEN];
    let transcript_hash = [0x88u8; SHA256_OUTPUT_LEN];

    let verify_data = compute_finished_verify_data(suite, &finished_key, &transcript_hash)
        .expect("valid finished verify_data");

    assert_eq!(verify_data.len(), hash_len(suite.hash));
    assert_eq!(verify_data.len(), SHA256_OUTPUT_LEN);
}

#[test]
fn compute_finished_verify_data_output_length_matches_hash_len_sha384() {
    let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
    let finished_key = [0x99u8; SHA384_OUTPUT_LEN];
    let transcript_hash = [0xAAu8; SHA384_OUTPUT_LEN];

    let verify_data = compute_finished_verify_data(suite, &finished_key, &transcript_hash)
        .expect("valid finished verify_data");

    assert_eq!(verify_data.len(), hash_len(suite.hash));
    assert_eq!(verify_data.len(), SHA384_OUTPUT_LEN);
}

#[test]
fn compute_finished_verify_data_is_deterministic() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let finished_key = [0xBBu8; SHA256_OUTPUT_LEN];
    let transcript_hash = [0xCCu8; SHA256_OUTPUT_LEN];

    let first = compute_finished_verify_data(suite, &finished_key, &transcript_hash)
        .expect("valid finished verify_data");
    let second = compute_finished_verify_data(suite, &finished_key, &transcript_hash)
        .expect("valid finished verify_data");

    assert_eq!(first, second);
}

#[test]
fn verify_finished_data_accepts_matching_verify_data() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let finished_key = [0xDDu8; SHA256_OUTPUT_LEN];
    let transcript_hash = [0xEEu8; SHA256_OUTPUT_LEN];
    let verify_data =
        compute_finished_verify_data(suite, &finished_key, &transcript_hash).expect("valid");

    assert!(
        verify_finished_data(suite, &finished_key, &transcript_hash, &verify_data)
            .expect("valid verify")
    );
}

#[test]
fn verify_finished_data_rejects_wrong_verify_data() {
    let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
    let finished_key = [0x11u8; SHA384_OUTPUT_LEN];
    let transcript_hash = [0x22u8; SHA384_OUTPUT_LEN];
    let verify_data =
        compute_finished_verify_data(suite, &finished_key, &transcript_hash).expect("valid");

    let mut wrong = verify_data.clone();
    wrong[0] ^= 0x01;

    assert!(
        !verify_finished_data(suite, &finished_key, &transcript_hash, &wrong)
            .expect("valid verify")
    );
}

#[test]
fn derive_master_secret_output_length_matches_hash_len_sha256() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let handshake_secret = [0x33u8; SHA256_OUTPUT_LEN];

    let master_secret = derive_master_secret(suite, &handshake_secret).expect("valid master");

    assert_eq!(master_secret.len(), hash_len(suite.hash));
}

#[test]
fn derive_master_secret_output_length_matches_hash_len_sha384() {
    let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
    let handshake_secret = [0x44u8; SHA384_OUTPUT_LEN];

    let master_secret = derive_master_secret(suite, &handshake_secret).expect("valid master");

    assert_eq!(master_secret.len(), hash_len(suite.hash));
}

#[test]
fn derive_application_traffic_secrets_output_lengths_match_hash_len() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let handshake_secret = [0x55u8; SHA256_OUTPUT_LEN];
    let transcript_hash = [0x66u8; SHA256_OUTPUT_LEN];

    let secrets = derive_application_traffic_secrets(suite, &handshake_secret, &transcript_hash)
        .expect("valid application secrets");

    assert_eq!(secrets.master_secret.len(), hash_len(suite.hash));
    assert_eq!(
        secrets.client_application_traffic_secret.len(),
        hash_len(suite.hash)
    );
    assert_eq!(
        secrets.server_application_traffic_secret.len(),
        hash_len(suite.hash)
    );
}

#[test]
fn derive_application_traffic_secrets_is_deterministic() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let handshake_secret = [0x77u8; SHA256_OUTPUT_LEN];
    let transcript_hash = [0x88u8; SHA256_OUTPUT_LEN];

    let first = derive_application_traffic_secrets(suite, &handshake_secret, &transcript_hash)
        .expect("valid application secrets");
    let second = derive_application_traffic_secrets(suite, &handshake_secret, &transcript_hash)
        .expect("valid application secrets");

    assert_eq!(first, second);
}

#[test]
fn derive_application_traffic_secrets_different_transcript_changes_traffic_secrets() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let handshake_secret = [0x99u8; SHA256_OUTPUT_LEN];
    let transcript_a = [0x01u8; SHA256_OUTPUT_LEN];
    let transcript_b = [0x02u8; SHA256_OUTPUT_LEN];

    let secrets_a = derive_application_traffic_secrets(suite, &handshake_secret, &transcript_a)
        .expect("valid application secrets");
    let secrets_b = derive_application_traffic_secrets(suite, &handshake_secret, &transcript_b)
        .expect("valid application secrets");

    assert_eq!(secrets_a.master_secret, secrets_b.master_secret);
    assert_ne!(
        secrets_a.client_application_traffic_secret,
        secrets_b.client_application_traffic_secret
    );
    assert_ne!(
        secrets_a.server_application_traffic_secret,
        secrets_b.server_application_traffic_secret
    );
}

#[test]
fn derive_traffic_key_different_labels_produce_different_outputs() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let traffic_secret = [0x55u8; SHA256_OUTPUT_LEN];
    let keys = derive_traffic_key(suite, &traffic_secret).expect("valid traffic key");

    assert_ne!(keys.key, keys.iv);
}

#[test]
fn update_traffic_secret_changes_secret_and_derived_keys() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let initial = vec![0x42; SHA256_OUTPUT_LEN];
    let updated = update_traffic_secret(suite, &initial).expect("updated secret");
    assert_ne!(initial, updated);

    let initial_keys = derive_traffic_key(suite, &initial).expect("initial keys");
    let updated_keys = derive_traffic_key(suite, &updated).expect("updated keys");
    assert_ne!(initial_keys.key, updated_keys.key);
    assert_ne!(initial_keys.iv, updated_keys.iv);
}
