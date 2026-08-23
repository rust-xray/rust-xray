use super::*;
use crate::codec::{Codec, Reader};
use crate::protocol::enums::ProtocolVersion;
use crate::protocol::structs::{ClientHelloPayload, Random, SessionId};

const TEST_AUTH_KEY: [u8; 32] = [7u8; 32];

fn build_test_aead_session(
    auth_key: &[u8; 32],
    random: [u8; 32],
    raw_client_hello_message: &mut [u8],
    client_version: [u8; 4],
    unix_time: u32,
    short_id: [u8; 8],
) -> [u8; 32] {
    let mut plaintext = [0u8; REALITY_PLAINTEXT_LEN];
    plaintext[0..4].copy_from_slice(&client_version);
    plaintext[4..8].copy_from_slice(&unix_time.to_be_bytes());
    plaintext[8..16].copy_from_slice(&short_id);

    raw_client_hello_message
        [REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN]
        .fill(0);

    let cipher = Aes256Gcm::new_from_slice(auth_key).expect("valid test key");
    let nonce = Nonce::from_slice(&random[20..20 + REALITY_NONCE_LEN]);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: raw_client_hello_message,
            },
        )
        .expect("encrypt test vector");

    ciphertext.try_into().expect("32-byte ciphertext+tag")
}

fn session_id_from_32_bytes(data: [u8; 32]) -> SessionId {
    let mut encoded = Vec::with_capacity(33);
    encoded.push(32);
    encoded.extend_from_slice(&data);
    let mut rd = Reader::init(&encoded);
    SessionId::read(&mut rd).expect("32-byte session id")
}

fn hello_with_session_id_and_random(session_id: SessionId, random: Random) -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random,
        session_id,
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: Vec::new(),
    }
}

fn valid_aead_test_vector() -> (ClientHelloPayload, Vec<u8>, RealityClientAuth) {
    let auth_key = TEST_AUTH_KEY;
    let mut random = [0u8; 32];
    random[20..32].copy_from_slice(&[0xAA; 12]);

    let client_version = [1, 8, 0, 0];
    let unix_time = 1_700_000_000;
    let short_id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    let mut raw_client_hello_message = vec![0u8; 80];
    raw_client_hello_message[0] = 0x01;

    let ciphertext = build_test_aead_session(
        &auth_key,
        random,
        &mut raw_client_hello_message,
        client_version,
        unix_time,
        short_id,
    );
    raw_client_hello_message
        [REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN]
        .copy_from_slice(&ciphertext);

    let session_id = session_id_from_32_bytes(ciphertext);
    let hello = hello_with_session_id_and_random(session_id, Random(random));

    let expected = RealityClientAuth {
        client_version,
        unix_time,
        short_id,
    };

    (hello, raw_client_hello_message, expected)
}

#[test]
fn open_reality_session_id_opens_valid_ciphertext() {
    let (hello, raw_client_hello_message, expected) = valid_aead_test_vector();

    let result =
        open_reality_session_id(&hello, &raw_client_hello_message, &TEST_AUTH_KEY).unwrap();

    assert_eq!(result, RealitySessionOpenResult::Opened(expected));
}

#[test]
fn wrong_auth_key_returns_auth_failed() {
    let (hello, raw_client_hello_message, _) = valid_aead_test_vector();
    let wrong_key = [8u8; 32];

    let result = open_reality_session_id(&hello, &raw_client_hello_message, &wrong_key).unwrap();

    assert_eq!(result, RealitySessionOpenResult::AuthFailed);
}

#[test]
fn wrong_aad_returns_auth_failed() {
    let (hello, mut raw_client_hello_message, _) = valid_aead_test_vector();
    raw_client_hello_message[10] ^= 1;

    let result =
        open_reality_session_id(&hello, &raw_client_hello_message, &TEST_AUTH_KEY).unwrap();

    assert_eq!(result, RealitySessionOpenResult::AuthFailed);
}

#[test]
fn short_session_id_returns_auth_failed() {
    let hello = hello_with_session_id_and_random(SessionId::empty(), Random([0u8; 32]));
    let raw_client_hello_message = vec![0u8; 80];

    let result =
        open_reality_session_id(&hello, &raw_client_hello_message, &TEST_AUTH_KEY).unwrap();

    assert_eq!(result, RealitySessionOpenResult::AuthFailed);
}

#[test]
fn too_short_raw_client_hello_message_returns_invalid_data() {
    let (hello, _, _) = valid_aead_test_vector();

    let err = open_reality_session_id(&hello, &[0u8; 40], &TEST_AUTH_KEY).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

fn validation_cfg<'a>(
    short_ids: &'a [Vec<u8>],
    max_time_diff_ms: u64,
) -> RealityValidationConfig<'a> {
    validation_cfg_with_versions(short_ids, max_time_diff_ms, None, None)
}

fn validation_cfg_with_versions<'a>(
    short_ids: &'a [Vec<u8>],
    max_time_diff_ms: u64,
    min_client_ver: Option<&'a str>,
    max_client_ver: Option<&'a str>,
) -> RealityValidationConfig<'a> {
    RealityValidationConfig {
        short_ids,
        max_time_diff_ms,
        min_client_ver,
        max_client_ver,
    }
}

#[test]
fn short_id_matches_exact_and_prefix() {
    let decrypted = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    assert!(short_id_matches(
        &decrypted,
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    ));
    assert!(short_id_matches(&decrypted, &[0x01, 0x23]));
    assert!(!short_id_matches(&decrypted, &[0x01, 0x24]));
    assert!(short_id_matches(&decrypted, &[]));
}

#[test]
fn validate_short_id_exact_eight_byte_match() {
    let short_ids = vec![vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]];
    let cfg = validation_cfg(&short_ids, 0);
    let auth = RealityClientAuth {
        client_version: [0; 4],
        unix_time: 1_700_000_000,
        short_id: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    };

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_short_id_prefix_match() {
    let short_ids = vec![vec![0x01, 0x23]];
    let cfg = validation_cfg(&short_ids, 0);
    let auth = RealityClientAuth {
        client_version: [0; 4],
        unix_time: 1_700_000_000,
        short_id: [0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00],
    };

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_empty_configured_short_id_matches_any_decrypted() {
    let short_ids = vec![Vec::new()];
    let cfg = validation_cfg(&short_ids, 0);
    let auth = RealityClientAuth {
        client_version: [0; 4],
        unix_time: 1_700_000_000,
        short_id: [0xFF; 8],
    };

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_short_id_mismatch_returns_false() {
    let short_ids = vec![vec![0x01, 0x23]];
    let cfg = validation_cfg(&short_ids, 0);
    let auth = RealityClientAuth {
        client_version: [0; 4],
        unix_time: 1_700_000_000,
        short_id: [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    };

    assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_empty_short_ids_list_returns_false() {
    let short_ids: Vec<Vec<u8>> = vec![];
    let cfg = validation_cfg(&short_ids, 0);
    let auth = RealityClientAuth {
        client_version: [0; 4],
        unix_time: 1_700_000_000,
        short_id: [0u8; 8],
    };

    assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_max_time_diff_disabled_when_zero() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg(&short_ids, 0);
    let auth = RealityClientAuth {
        client_version: [0; 4],
        unix_time: 1,
        short_id: {
            let mut short_id = [0u8; 8];
            short_id[0] = 0x01;
            short_id
        },
    };

    assert!(validate_reality_client_auth(&auth, cfg, u64::MAX).unwrap());
}

#[test]
fn validate_max_time_diff_inside_window() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg(&short_ids, 5_000);
    let auth = RealityClientAuth {
        client_version: [0; 4],
        unix_time: 1_700_000_000,
        short_id: {
            let mut short_id = [0u8; 8];
            short_id[0] = 0x01;
            short_id
        },
    };
    let auth_unix_ms = u64::from(auth.unix_time).saturating_mul(1000);
    let now_unix_ms = auth_unix_ms + 2_000;

    assert!(validate_reality_client_auth(&auth, cfg, now_unix_ms).unwrap());
}

#[test]
fn validate_max_time_diff_outside_window() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg(&short_ids, 1_000);
    let auth = RealityClientAuth {
        client_version: [0; 4],
        unix_time: 1_700_000_000,
        short_id: {
            let mut short_id = [0u8; 8];
            short_id[0] = 0x01;
            short_id
        },
    };
    let auth_unix_ms = u64::from(auth.unix_time).saturating_mul(1000);
    let now_unix_ms = auth_unix_ms + 2_000;

    assert!(!validate_reality_client_auth(&auth, cfg, now_unix_ms).unwrap());
}

fn auth_with_version(client_version: [u8; 4]) -> RealityClientAuth {
    RealityClientAuth {
        client_version,
        unix_time: 1_700_000_000,
        short_id: {
            let mut short_id = [0u8; 8];
            short_id[0] = 0x01;
            short_id
        },
    }
}

#[test]
fn validate_client_version_no_min_max_passes() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg(&short_ids, 0);
    let auth = auth_with_version([1, 8, 0, 0]);

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_client_version_min_passes() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(&short_ids, 0, Some("1.8.0"), None);
    let auth = auth_with_version([1, 8, 0, 0]);

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_client_version_min_fails() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(&short_ids, 0, Some("1.9.0"), None);
    let auth = auth_with_version([1, 8, 0, 0]);

    assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_client_version_max_passes() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(&short_ids, 0, None, Some("1.8.0"));
    let auth = auth_with_version([1, 8, 0, 0]);

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_client_version_max_fails() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(&short_ids, 0, None, Some("1.7.0"));
    let auth = auth_with_version([1, 8, 0, 0]);

    assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_client_version_invalid_min_returns_invalid_input() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(&short_ids, 0, Some("1.300.0"), None);
    let auth = auth_with_version([1, 8, 0, 0]);

    let err = validate_reality_client_auth(&auth, cfg, 0).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn validate_client_version_invalid_max_returns_invalid_input() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(&short_ids, 0, None, Some("1.300.0"));
    let auth = auth_with_version([1, 8, 0, 0]);

    let err = validate_reality_client_auth(&auth, cfg, 0).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn validate_default_min_client_ver_rejects_below_26_3_27() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(
        &short_ids,
        0,
        Some(crate::config::xray::DEFAULT_REALITY_MIN_CLIENT_VER),
        None,
    );
    let auth = auth_with_version([26, 3, 26, 0]);

    assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_default_min_client_ver_accepts_26_3_27() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(
        &short_ids,
        0,
        Some(crate::config::xray::DEFAULT_REALITY_MIN_CLIENT_VER),
        None,
    );
    let auth = auth_with_version([26, 3, 27, 0]);

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_default_min_client_ver_accepts_above_26_3_27() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(
        &short_ids,
        0,
        Some(crate::config::xray::DEFAULT_REALITY_MIN_CLIENT_VER),
        None,
    );
    let auth = auth_with_version([26, 3, 28, 0]);

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_default_min_client_ver_accepts_26_4_0() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(
        &short_ids,
        0,
        Some(crate::config::xray::DEFAULT_REALITY_MIN_CLIENT_VER),
        None,
    );
    let auth = auth_with_version([26, 4, 0, 0]);

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_default_min_client_ver_accepts_27_0_0() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(
        &short_ids,
        0,
        Some(crate::config::xray::DEFAULT_REALITY_MIN_CLIENT_VER),
        None,
    );
    let auth = auth_with_version([27, 0, 0, 0]);

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}

#[test]
fn validate_explicit_zero_min_client_ver_accepts_legacy_client() {
    let short_ids = vec![vec![0x01]];
    let cfg = validation_cfg_with_versions(&short_ids, 0, Some("0.0.0"), None);
    let auth = auth_with_version([1, 8, 0, 0]);

    assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
}
