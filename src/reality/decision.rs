use std::time::{SystemTime, UNIX_EPOCH};

use tracing::debug;

use crate::protocol::enums::ProtocolVersion;
use crate::protocol::structs::ClientHelloPayload;

use super::auth::{derive_reality_auth_key, extract_x25519_keyshare, RealityAuthResult};
use super::session::{
    open_reality_session_id, validate_reality_client_auth, RealityClientAuth,
    RealitySessionOpenResult, RealityValidationConfig,
};
use super::sni::{extract_sni_hostname, server_name_allowed};

#[derive(Debug)]
pub struct RealityAccepted {
    pub auth: RealityAuthResult,
    pub client: RealityClientAuth,
    pub sni: Option<String>,
}

#[derive(Debug)]
pub enum RealityDecision {
    Accepted(RealityAccepted),
    Fallback,
}

pub struct RealityInspectConfig<'a> {
    pub private_key: &'a str,
    pub server_names: &'a [String],
    pub short_ids: &'a [Vec<u8>],
    pub max_time_diff_ms: u64,
    pub min_client_ver: Option<&'a str>,
    pub max_client_ver: Option<&'a str>,
    /// When set, overrides wall-clock time for maxTimeDiff validation (tests only).
    pub now_unix_ms: Option<u64>,
}

fn log_client_hello_diagnostics(hello: &ClientHelloPayload) {
    match hello.versions_extension() {
        Some(versions) if versions.contains(&ProtocolVersion::TLSv1_3) => {
            debug!("TLS 1.3 supported in supported_versions");
        }
        Some(_) => debug!("TLS 1.3 unsupported in supported_versions"),
        None => debug!("supported_versions extension missing"),
    }

    match extract_x25519_keyshare(hello) {
        Some(_) => debug!("X25519 keyshare found"),
        None => debug!("X25519 keyshare missing or invalid length"),
    }
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub fn inspect_reality_client_hello(
    hello: &ClientHelloPayload,
    raw_client_hello_message: &[u8],
    cfg: RealityInspectConfig<'_>,
) -> std::io::Result<RealityDecision> {
    let sni = match extract_sni_hostname(hello) {
        Some(sni) => sni,
        None => {
            debug!("REALITY fallback: SNI missing");
            return Ok(RealityDecision::Fallback);
        }
    };

    if !server_name_allowed(&sni, cfg.server_names) {
        debug!(%sni, "REALITY fallback: SNI not allowed");
        return Ok(RealityDecision::Fallback);
    }

    debug!(%sni, "REALITY SNI allowed");

    log_client_hello_diagnostics(hello);

    let Some(auth) = derive_reality_auth_key(hello, cfg.private_key)? else {
        return Ok(RealityDecision::Fallback);
    };

    match open_reality_session_id(hello, raw_client_hello_message, &auth.auth_key)? {
        RealitySessionOpenResult::Opened(client_auth) => {
            debug!(
                client_version = ?client_auth.client_version,
                unix_time = client_auth.unix_time,
                "REALITY session_id open ok"
            );

            let now_unix_ms = cfg.now_unix_ms.unwrap_or_else(current_unix_ms);

            let policy_ok = validate_reality_client_auth(
                &client_auth,
                RealityValidationConfig {
                    short_ids: cfg.short_ids,
                    max_time_diff_ms: cfg.max_time_diff_ms,
                    min_client_ver: cfg.min_client_ver,
                    max_client_ver: cfg.max_client_ver,
                },
                now_unix_ms,
            )?;

            if !policy_ok {
                debug!("REALITY policy validation failed");
                return Ok(RealityDecision::Fallback);
            }

            Ok(RealityDecision::Accepted(RealityAccepted {
                auth,
                client: client_auth,
                sni: Some(sni),
            }))
        }
        RealitySessionOpenResult::AuthFailed => {
            debug!("REALITY session_id auth failed");
            Ok(RealityDecision::Fallback)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Codec, Reader};
    use crate::pki_types::DnsName;
    use crate::protocol::enums::{NamedGroup, ProtocolVersion};
    use crate::protocol::structs::{
        ClientExtension, ClientHelloPayload, KeyShareEntry, Random, SessionId,
    };
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    const PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
    const REALITY_SESSION_ID_OFFSET: usize = 39;
    const REALITY_SESSION_ID_LEN: usize = 32;
    const REALITY_PLAINTEXT_LEN: usize = 16;
    const HANDSHAKE_HEADER_LEN: usize = 4;

    fn session_id_from_32_bytes(data: [u8; 32]) -> SessionId {
        let mut encoded = Vec::with_capacity(33);
        encoded.push(32);
        encoded.extend_from_slice(&data);
        let mut rd = Reader::init(&encoded);
        SessionId::read(&mut rd).expect("32-byte session id")
    }

    fn reality_candidate_hello(random: Random) -> ClientHelloPayload {
        reality_candidate_hello_with_sni(random, "example.com")
    }

    fn reality_candidate_hello_with_sni(random: Random, hostname: &str) -> ClientHelloPayload {
        let dns = DnsName::try_from(hostname).expect("valid dns name");
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random,
            session_id: SessionId::empty(),
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: vec![
                ClientExtension::make_sni(&dns),
                ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
                ClientExtension::KeyShare(vec![KeyShareEntry::new(NamedGroup::X25519, [1u8; 32])]),
            ],
        }
    }

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

    fn seal_reality_session_id(
        auth_key: &[u8; 32],
        random: &[u8; 32],
        raw_client_hello_message: &mut [u8],
        plaintext: &[u8; REALITY_PLAINTEXT_LEN],
    ) -> [u8; 32] {
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

    fn build_valid_reality_client(
        unix_time: u32,
        short_id_prefix: &[u8],
    ) -> (ClientHelloPayload, Vec<u8>) {
        let mut random = [0u8; 32];
        random[20..32].copy_from_slice(&[0xAA; 12]);

        let hello = reality_candidate_hello(Random(random));
        let auth_key = derive_reality_auth_key(&hello, PRIVATE_KEY)
            .unwrap()
            .expect("valid REALITY candidate")
            .auth_key;

        let mut plaintext = [0u8; REALITY_PLAINTEXT_LEN];
        plaintext[0] = 1;
        plaintext[1] = 8;
        plaintext[4..8].copy_from_slice(&unix_time.to_be_bytes());
        plaintext[8..8 + short_id_prefix.len()].copy_from_slice(short_id_prefix);

        let mut handshake_message = build_minimal_handshake_message(&random, &[0u8; 32]);
        let ciphertext =
            seal_reality_session_id(&auth_key, &random, &mut handshake_message, &plaintext);

        let session_id = session_id_from_32_bytes(ciphertext);
        let hello = ClientHelloPayload {
            session_id,
            ..reality_candidate_hello(Random(random))
        };
        handshake_message
            [REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN]
            .copy_from_slice(&ciphertext);

        (hello, handshake_message)
    }

    fn inspect_cfg<'a>(
        server_names: &'a [String],
        short_ids: &'a [Vec<u8>],
        max_time_diff_ms: u64,
        now_unix_ms: Option<u64>,
    ) -> RealityInspectConfig<'a> {
        inspect_cfg_with_versions(
            server_names,
            short_ids,
            max_time_diff_ms,
            None,
            None,
            now_unix_ms,
        )
    }

    fn inspect_cfg_with_versions<'a>(
        server_names: &'a [String],
        short_ids: &'a [Vec<u8>],
        max_time_diff_ms: u64,
        min_client_ver: Option<&'a str>,
        max_client_ver: Option<&'a str>,
        now_unix_ms: Option<u64>,
    ) -> RealityInspectConfig<'a> {
        RealityInspectConfig {
            private_key: PRIVATE_KEY,
            server_names,
            short_ids,
            max_time_diff_ms,
            min_client_ver,
            max_client_ver,
            now_unix_ms,
        }
    }

    #[test]
    fn inspect_reality_client_hello_allowed_sni_reaches_crypto_path() {
        let mut random = [0u8; 32];
        random[20..32].copy_from_slice(&[0xAA; 12]);
        let mut hello = reality_candidate_hello(Random(random));
        hello.session_id = session_id_from_32_bytes([0xFF; 32]);
        let handshake_message = build_minimal_handshake_message(&random, &[0u8; 32]);
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &short_ids, 0, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Fallback));
    }

    #[test]
    fn inspect_reality_client_hello_accepts_valid_aead_with_matching_short_id() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &short_ids, 0, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Accepted(_)));
    }

    #[test]
    fn inspect_reality_client_hello_accepted_includes_client_metadata() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &short_ids, 0, None),
        )
        .unwrap();

        match result {
            RealityDecision::Accepted(accepted) => {
                assert_eq!(accepted.sni.as_deref(), Some("example.com"));
                assert_eq!(accepted.client.client_version, [1, 8, 0, 0]);
                assert_eq!(accepted.client.unix_time, 1_700_000_000);
                assert_eq!(accepted.client.short_id[0], 0xAB);
                assert_eq!(accepted.client.short_id[1], 0xCD);
            }
            RealityDecision::Fallback => panic!("expected Accepted"),
        }
    }

    #[test]
    fn inspect_reality_client_hello_accepts_empty_configured_short_id() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![Vec::new()];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xFF, 0xEE]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &short_ids, 0, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Accepted(_)));
    }

    #[test]
    fn inspect_reality_client_hello_fallbacks_on_short_id_mismatch() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01, 0x02]];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &short_ids, 0, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Fallback));
    }

    #[test]
    fn inspect_reality_client_hello_accepts_when_max_time_diff_inside_window() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let unix_time = 1_700_000_000;
        let now_unix_ms = u64::from(unix_time) * 1000 + 2_000;
        let (hello, handshake_message) = build_valid_reality_client(unix_time, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &short_ids, 5_000, Some(now_unix_ms)),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Accepted(_)));
    }

    #[test]
    fn inspect_reality_client_hello_fallbacks_when_max_time_diff_outside_window() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let unix_time = 1_700_000_000;
        let now_unix_ms = u64::from(unix_time) * 1000 + 2_000;
        let (hello, handshake_message) = build_valid_reality_client(unix_time, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &short_ids, 1_000, Some(now_unix_ms)),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Fallback));
    }

    #[test]
    fn inspect_reality_client_hello_fallbacks_when_sni_missing() {
        let mut random = [0u8; 32];
        random[20..32].copy_from_slice(&[0xAA; 12]);
        let hello = ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random(random),
            session_id: SessionId::empty(),
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: vec![
                ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
                ClientExtension::KeyShare(vec![KeyShareEntry::new(NamedGroup::X25519, [1u8; 32])]),
            ],
        };
        let handshake_message = build_minimal_handshake_message(&random, &[0u8; 32]);
        let server_names = vec!["example.com".to_string()];

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &[vec![0xAB]], 0, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Fallback));
    }

    #[test]
    fn inspect_reality_client_hello_fallbacks_when_sni_not_allowed() {
        let mut random = [0u8; 32];
        random[20..32].copy_from_slice(&[0xAA; 12]);
        let hello = reality_candidate_hello_with_sni(Random(random), "wrong.example.com");
        let handshake_message = build_minimal_handshake_message(&random, &[0u8; 32]);
        let server_names = vec!["example.com".to_string()];

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &[vec![0xAB]], 0, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Fallback));
    }

    #[test]
    fn inspect_reality_client_hello_fallbacks_when_server_names_empty() {
        let mut random = [0u8; 32];
        random[20..32].copy_from_slice(&[0xAA; 12]);
        let hello = reality_candidate_hello(Random(random));
        let handshake_message = build_minimal_handshake_message(&random, &[0u8; 32]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&[], &[vec![0xAB]], 0, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Fallback));
    }

    #[test]
    fn inspect_reality_client_hello_accepts_case_insensitive_sni_match() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let mut random = [0u8; 32];
        random[20..32].copy_from_slice(&[0xAA; 12]);

        let hello = reality_candidate_hello_with_sni(Random(random), "EXAMPLE.COM");
        let auth_key = derive_reality_auth_key(&hello, PRIVATE_KEY)
            .unwrap()
            .expect("valid REALITY candidate")
            .auth_key;

        let mut plaintext = [0u8; REALITY_PLAINTEXT_LEN];
        plaintext[0] = 1;
        plaintext[1] = 8;
        plaintext[4..8].copy_from_slice(&1_700_000_000u32.to_be_bytes());
        plaintext[8] = 0xAB;
        plaintext[9] = 0xCD;

        let mut handshake_message = build_minimal_handshake_message(&random, &[0u8; 32]);
        let ciphertext =
            seal_reality_session_id(&auth_key, &random, &mut handshake_message, &plaintext);

        let session_id = session_id_from_32_bytes(ciphertext);
        let hello = ClientHelloPayload {
            session_id,
            ..reality_candidate_hello_with_sni(Random(random), "EXAMPLE.COM")
        };
        handshake_message
            [REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN]
            .copy_from_slice(&ciphertext);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg(&server_names, &short_ids, 0, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Accepted(_)));
    }

    #[test]
    fn inspect_reality_client_hello_accepts_when_min_client_ver_passes() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg_with_versions(&server_names, &short_ids, 0, Some("1.8.0"), None, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Accepted(_)));
    }

    #[test]
    fn inspect_reality_client_hello_fallbacks_when_min_client_ver_fails() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg_with_versions(&server_names, &short_ids, 0, Some("1.9.0"), None, None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Fallback));
    }

    #[test]
    fn inspect_reality_client_hello_accepts_when_max_client_ver_passes() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg_with_versions(&server_names, &short_ids, 0, None, Some("1.8.0"), None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Accepted(_)));
    }

    #[test]
    fn inspect_reality_client_hello_fallbacks_when_max_client_ver_fails() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);

        let result = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg_with_versions(&server_names, &short_ids, 0, None, Some("1.7.0"), None),
        )
        .unwrap();

        assert!(matches!(result, RealityDecision::Fallback));
    }

    #[test]
    fn inspect_reality_client_hello_invalid_min_client_ver_returns_invalid_input() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0xAB, 0xCD]];
        let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);

        let err = inspect_reality_client_hello(
            &hello,
            &handshake_message,
            inspect_cfg_with_versions(&server_names, &short_ids, 0, Some("1.300.0"), None, None),
        )
        .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
