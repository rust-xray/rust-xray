
use super::*;

#[test]
fn lookup_tls_aes_128_gcm_sha256() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    assert_eq!(suite.id, 0x1301);
    assert_eq!(suite.name, "TLS_AES_128_GCM_SHA256");
    assert_eq!(suite.hash, Tls13HashAlgorithm::Sha256);
    assert_eq!(suite.aead, Tls13AeadAlgorithm::Aes128Gcm);
    assert_eq!(suite.key_len, 16);
    assert_eq!(suite.iv_len, 12);
}

#[test]
fn lookup_tls_aes_256_gcm_sha384() {
    let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
    assert_eq!(suite.id, 0x1302);
    assert_eq!(suite.name, "TLS_AES_256_GCM_SHA384");
    assert_eq!(suite.hash, Tls13HashAlgorithm::Sha384);
    assert_eq!(suite.aead, Tls13AeadAlgorithm::Aes256Gcm);
    assert_eq!(suite.key_len, 32);
    assert_eq!(suite.iv_len, 12);
}

#[test]
fn lookup_tls_chacha20_poly1305_sha256() {
    let suite = tls13_cipher_suite(TLS_CHACHA20_POLY1305_SHA256).expect("known suite");
    assert_eq!(suite.id, 0x1303);
    assert_eq!(suite.name, "TLS_CHACHA20_POLY1305_SHA256");
    assert_eq!(suite.hash, Tls13HashAlgorithm::Sha256);
    assert_eq!(suite.aead, Tls13AeadAlgorithm::ChaCha20Poly1305);
    assert_eq!(suite.key_len, 32);
    assert_eq!(suite.iv_len, 12);
}

#[test]
fn unknown_cipher_suite_returns_none() {
    assert!(tls13_cipher_suite(0x0000).is_none());
    assert!(tls13_cipher_suite(TLS_AES_128_CCM_SHA256).is_none());
    assert!(tls13_cipher_suite(TLS_AES_128_CCM_8_SHA256).is_none());
}

#[test]
fn resolve_rejects_ccm_cipher_suites_with_explicit_message() {
    for (id, name) in [
        (TLS_AES_128_CCM_SHA256, "TLS_AES_128_CCM_SHA256"),
        (TLS_AES_128_CCM_8_SHA256, "TLS_AES_128_CCM_8_SHA256"),
    ] {
        let err = resolve_tls13_cipher_suite(id).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        let message = err.to_string();
        assert!(message.contains("CCM"), "{message}");
        assert!(message.contains(name), "{message}");
        assert!(message.contains(&format!("0x{id:04x}")), "{message}");
        assert!(message.contains("TLS_AES_128_GCM_SHA256"), "{message}");
        assert!(
            message.contains("TLS_CHACHA20_POLY1305_SHA256"),
            "{message}"
        );
    }
}

#[test]
fn resolve_accepts_supported_suites() {
    for id in [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ] {
        resolve_tls13_cipher_suite(id).expect("supported suite");
    }
}
