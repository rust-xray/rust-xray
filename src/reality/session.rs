use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use tracing::debug;

use crate::protocol::structs::ClientHelloPayload;

use super::client_version::{parse_reality_client_version, version_ge, version_le};

#[derive(Clone, PartialEq, Eq)]
pub struct RealityClientAuth {
    pub client_version: [u8; 4],
    pub unix_time: u32,
    pub short_id: [u8; 8],
}

impl std::fmt::Debug for RealityClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityClientAuth")
            .field("client_version", &self.client_version)
            .field("unix_time", &self.unix_time)
            .field(
                "short_id",
                &format!("<{} bytes>", short_id_prefix_len(&self.short_id)),
            )
            .finish()
    }
}

pub fn short_id_prefix_len(short_id: &[u8; 8]) -> usize {
    short_id
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|index| index + 1)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RealitySessionOpenResult {
    Opened(RealityClientAuth),
    AuthFailed,
}

const REALITY_SESSION_ID_OFFSET: usize = 39;
const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_PLAINTEXT_LEN: usize = 16;

pub(crate) fn open_reality_session_id(
    hello: &ClientHelloPayload,
    raw_client_hello_message: &[u8],
    auth_key: &[u8; 32],
) -> std::io::Result<RealitySessionOpenResult> {
    let session_id = hello.session_id.as_bytes();

    if session_id.len() != REALITY_SESSION_ID_LEN {
        debug!(
            len = session_id.len(),
            "REALITY session_id open skipped: session_id must be 32 bytes"
        );
        return Ok(RealitySessionOpenResult::AuthFailed);
    }

    if raw_client_hello_message.len() < REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello handshake message too short for REALITY session_id AAD",
        ));
    }

    let mut aad = raw_client_hello_message.to_vec();
    aad[REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN].fill(0);

    let cipher = Aes256Gcm::new_from_slice(auth_key).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("REALITY AES-GCM key invalid: {e}"),
        )
    })?;
    let nonce = Nonce::from_slice(&hello.random.0[20..32]);

    let plaintext = match cipher.decrypt(
        nonce,
        Payload {
            msg: session_id,
            aad: &aad,
        },
    ) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            debug!("REALITY session_id AEAD open failed");
            return Ok(RealitySessionOpenResult::AuthFailed);
        }
    };

    if plaintext.len() != REALITY_PLAINTEXT_LEN {
        debug!(
            len = plaintext.len(),
            "REALITY session_id plaintext has unexpected length"
        );
        return Ok(RealitySessionOpenResult::AuthFailed);
    }

    let mut client_version = [0u8; 4];
    client_version.copy_from_slice(&plaintext[0..4]);

    let unix_time = u32::from_be_bytes(plaintext[4..8].try_into().expect("4-byte timestamp"));

    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plaintext[8..16]);

    Ok(RealitySessionOpenResult::Opened(RealityClientAuth {
        client_version,
        unix_time,
        short_id,
    }))
}

pub struct RealityValidationConfig<'a> {
    pub server_names: &'a [String],
    pub short_ids: &'a [Vec<u8>],
    pub max_time_diff_ms: u64,
    pub min_client_ver: Option<&'a str>,
    pub max_client_ver: Option<&'a str>,
}

fn short_id_matches(decrypted: &[u8; 8], configured: &[u8]) -> bool {
    configured.len() <= decrypted.len() && &decrypted[..configured.len()] == configured
}

/// Validates REALITY client auth metadata after AEAD session_id decrypt.
///
/// Returns `Ok(true)` when all configured checks pass, `Ok(false)` otherwise.
///
/// TODO: Validate `server_names` once SNI policy is wired into auth checks.
pub fn validate_reality_client_auth(
    auth: &RealityClientAuth,
    cfg: RealityValidationConfig<'_>,
    now_unix_ms: u64,
) -> std::io::Result<bool> {
    let _ = cfg.server_names;

    let min_version = cfg
        .min_client_ver
        .map(parse_reality_client_version)
        .transpose()?;
    let max_version = cfg
        .max_client_ver
        .map(parse_reality_client_version)
        .transpose()?;

    if cfg.short_ids.is_empty() {
        debug!("shortId validation failed: no configured shortIds");
        return Ok(false);
    }

    if !cfg
        .short_ids
        .iter()
        .any(|configured| short_id_matches(&auth.short_id, configured))
    {
        debug!("shortId validation failed");
        return Ok(false);
    }

    if let Some(min) = min_version {
        if !version_ge(auth.client_version, min) {
            debug!(
                client_version = ?auth.client_version,
                min_client_ver = ?cfg.min_client_ver,
                "minClientVer validation failed"
            );
            return Ok(false);
        }
    }

    if let Some(max) = max_version {
        if !version_le(auth.client_version, max) {
            debug!(
                client_version = ?auth.client_version,
                max_client_ver = ?cfg.max_client_ver,
                "maxClientVer validation failed"
            );
            return Ok(false);
        }
    }

    if cfg.max_time_diff_ms == 0 {
        return Ok(true);
    }

    let auth_unix_ms = u64::from(auth.unix_time) * 1000;
    let diff_ms = now_unix_ms.abs_diff(auth_unix_ms);

    if diff_ms > cfg.max_time_diff_ms {
        debug!(
            diff_ms,
            max_time_diff_ms = cfg.max_time_diff_ms,
            "maxTimeDiff validation failed"
        );
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Codec, Reader};
    use crate::protocol::enums::ProtocolVersion;
    use crate::protocol::structs::{ClientHelloPayload, Random, SessionId};

    const TEST_AUTH_KEY: [u8; 32] = [7u8; 32];

    fn build_minimal_handshake_message(random: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
        let payload_len = 2 + 32 + 1 + REALITY_SESSION_ID_LEN;
        let mut msg = Vec::with_capacity(HANDSHAKE_HEADER_LEN + payload_len);
        msg.push(0x01);
        msg.extend_from_slice(&(payload_len as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.extend_from_slice(random);
        msg.push(REALITY_SESSION_ID_LEN as u8);
        msg.extend_from_slice(session_id);
        msg
    }

    const HANDSHAKE_HEADER_LEN: usize = 4;

    fn seal_reality_session_id(
        auth_key: &[u8; 32],
        random: &[u8; 32],
        raw_client_hello_message: &mut [u8],
        plaintext: &[u8; REALITY_PLAINTEXT_LEN],
    ) -> [u8; REALITY_SESSION_ID_LEN] {
        let mut aad = raw_client_hello_message.to_vec();
        aad[REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN].fill(0);

        let cipher = Aes256Gcm::new_from_slice(auth_key).expect("valid test key");
        let nonce = Nonce::from_slice(&random[20..32]);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
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

    fn hello_with_session_id_and_random(
        session_id: SessionId,
        random: Random,
    ) -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random,
            session_id,
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: Vec::new(),
        }
    }

    fn valid_test_vector() -> (ClientHelloPayload, Vec<u8>, RealityClientAuth) {
        let mut random = [0u8; 32];
        random[20..32].copy_from_slice(&[0xAA; 12]);

        let mut plaintext = [0u8; REALITY_PLAINTEXT_LEN];
        plaintext[0] = 1;
        plaintext[1] = 8;
        plaintext[4..8].copy_from_slice(&1_700_000_000u32.to_be_bytes());
        plaintext[8] = 0xAB;
        plaintext[9] = 0xCD;

        let mut handshake_message = build_minimal_handshake_message(&random, &[0u8; 32]);
        let ciphertext =
            seal_reality_session_id(&TEST_AUTH_KEY, &random, &mut handshake_message, &plaintext);

        let session_id = session_id_from_32_bytes(ciphertext);
        let hello = hello_with_session_id_and_random(session_id, Random(random));
        handshake_message
            [REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN]
            .copy_from_slice(&ciphertext);

        let expected = RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0xAB;
                short_id[1] = 0xCD;
                short_id
            },
        };

        (hello, handshake_message, expected)
    }

    #[test]
    fn open_reality_session_id_decrypts_valid_vector() {
        let (hello, handshake_message, expected) = valid_test_vector();

        let result = open_reality_session_id(&hello, &handshake_message, &TEST_AUTH_KEY).unwrap();

        assert_eq!(result, RealitySessionOpenResult::Opened(expected));
    }

    #[test]
    fn open_reality_session_id_returns_auth_failed_for_short_session_id() {
        let hello = hello_with_session_id_and_random(SessionId::empty(), Random([0u8; 32]));

        let result = open_reality_session_id(&hello, &[], &TEST_AUTH_KEY).unwrap();

        assert_eq!(result, RealitySessionOpenResult::AuthFailed);
    }

    #[test]
    fn open_reality_session_id_returns_auth_failed_for_wrong_auth_key() {
        let (hello, handshake_message, _) = valid_test_vector();
        let wrong_key = [8u8; 32];

        let result = open_reality_session_id(&hello, &handshake_message, &wrong_key).unwrap();

        assert_eq!(result, RealitySessionOpenResult::AuthFailed);
    }

    #[test]
    fn open_reality_session_id_returns_auth_failed_for_wrong_aad() {
        let (hello, mut handshake_message, _) = valid_test_vector();
        handshake_message[0] = 0x02;

        let result = open_reality_session_id(&hello, &handshake_message, &TEST_AUTH_KEY).unwrap();

        assert_eq!(result, RealitySessionOpenResult::AuthFailed);
    }

    #[test]
    fn open_reality_session_id_returns_invalid_data_for_short_handshake_message() {
        let (hello, _, _) = valid_test_vector();

        let err = open_reality_session_id(&hello, &[0u8; 40], &TEST_AUTH_KEY).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    fn validation_cfg<'a>(
        server_names: &'a [String],
        short_ids: &'a [Vec<u8>],
        max_time_diff_ms: u64,
    ) -> RealityValidationConfig<'a> {
        validation_cfg_with_versions(server_names, short_ids, max_time_diff_ms, None, None)
    }

    fn validation_cfg_with_versions<'a>(
        server_names: &'a [String],
        short_ids: &'a [Vec<u8>],
        max_time_diff_ms: u64,
        min_client_ver: Option<&'a str>,
        max_client_ver: Option<&'a str>,
    ) -> RealityValidationConfig<'a> {
        RealityValidationConfig {
            server_names,
            short_ids,
            max_time_diff_ms,
            min_client_ver,
            max_client_ver,
        }
    }

    #[test]
    fn validate_reality_client_auth_short_id_match() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01, 0x23], vec![0xab, 0xcd]];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
        let auth = RealityClientAuth {
            client_version: [0; 4],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0xab;
                short_id[1] = 0xcd;
                short_id
            },
        };

        assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_short_id_mismatch() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01, 0x23]];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
        let auth = RealityClientAuth {
            client_version: [0; 4],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0xff;
                short_id
            },
        };

        assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_empty_configured_short_id_matches_any() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![Vec::new()];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
        let auth = RealityClientAuth {
            client_version: [0; 4],
            unix_time: 1_700_000_000,
            short_id: [0xFF; 8],
        };

        assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_empty_short_ids() {
        let server_names = vec!["example.com".to_string()];
        let short_ids: Vec<Vec<u8>> = vec![];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
        let auth = RealityClientAuth {
            client_version: [0; 4],
            unix_time: 1_700_000_000,
            short_id: [0u8; 8],
        };

        assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_max_time_diff_disabled_when_zero() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
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
    fn validate_reality_client_auth_time_inside_window() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg(&server_names, &short_ids, 5_000);
        let auth = RealityClientAuth {
            client_version: [0; 4],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0x01;
                short_id
            },
        };
        let now_unix_ms = u64::from(auth.unix_time) * 1000 + 2_000;

        assert!(validate_reality_client_auth(&auth, cfg, now_unix_ms).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_time_outside_window() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg(&server_names, &short_ids, 1_000);
        let auth = RealityClientAuth {
            client_version: [0; 4],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0x01;
                short_id
            },
        };
        let now_unix_ms = u64::from(auth.unix_time) * 1000 + 2_000;

        assert!(!validate_reality_client_auth(&auth, cfg, now_unix_ms).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_min_client_ver_pass() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg_with_versions(&server_names, &short_ids, 0, Some("1.8.0"), None);
        let auth = RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0x01;
                short_id
            },
        };

        assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_min_client_ver_fail() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg_with_versions(&server_names, &short_ids, 0, Some("1.9.0"), None);
        let auth = RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0x01;
                short_id
            },
        };

        assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_max_client_ver_pass() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg_with_versions(&server_names, &short_ids, 0, None, Some("1.8.0"));
        let auth = RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0x01;
                short_id
            },
        };

        assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_max_client_ver_fail() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg_with_versions(&server_names, &short_ids, 0, None, Some("1.7.0"));
        let auth = RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: {
                let mut short_id = [0u8; 8];
                short_id[0] = 0x01;
                short_id
            },
        };

        assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_invalid_min_client_ver_returns_error() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg_with_versions(&server_names, &short_ids, 0, Some("1.300.0"), None);
        let auth = RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: [0x01; 8],
        };

        let err = validate_reality_client_auth(&auth, cfg, 0).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
