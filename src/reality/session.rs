use tracing::{debug, warn};

use crate::protocol::structs::ClientHelloPayload;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityClientAuth {
    pub short_id: Vec<u8>,
    // TODO: Verify REALITY timestamp units when AEAD session_id open is implemented.
    pub unix_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RealitySessionOpenResult {
    Opened(RealityClientAuth),
    AuthFailed,
    NotImplemented,
}

/// Minimum TLS Session ID length used by REALITY clients (32-byte AES-GCM ciphertext).
const REALITY_SESSION_ID_LEN: usize = 32;

pub(crate) fn open_reality_session_id(
    hello: &ClientHelloPayload,
    raw_client_hello_payload: &[u8],
    auth_key: &[u8; 42],
) -> std::io::Result<RealitySessionOpenResult> {
    let session_id = hello.session_id.as_bytes();

    if session_id.len() < REALITY_SESSION_ID_LEN {
        debug!(
            len = session_id.len(),
            "REALITY session_id open skipped: session_id too short"
        );
        return Ok(RealitySessionOpenResult::AuthFailed);
    }

    let _ = (raw_client_hello_payload, auth_key, &hello.random.0);

    // TODO(AEAD session_id decrypt): Do not guess AEAD parameters. Port them 1:1 from upstream
    // Xray-core/REALITY Go code. Until every item below is verified against upstream, keep
    // returning `RealitySessionOpenResult::NotImplemented` — do not return `Opened`.
    //
    // Upstream search zones (read the actual Go source; line numbers drift):
    //   - XTLS/Xray-core `transport/internet/reality/` (REALITY inbound / config wiring)
    //   - XTLS/REALITY modified `crypto/tls` server handshake path
    //   - Go code around REALITY server-side sessionId decrypt / AuthKey use (e.g. `tls.go`
    //     server path near session_id open, historically ~lines 236–249 in XTLS/REALITY)
    //
    // Verify 1:1 before returning `Opened(RealityClientAuth { .. })`:
    //   - exact AEAD algorithm (e.g. AES-GCM variant, tag size, cipher block size)
    //   - exact key material split from HKDF output (`auth_key` is 42 bytes here; confirm
    //     whether the full 42-byte `auth_key` is used or only an AES-256 key slice)
    //   - exact nonce source (which ClientHello.random byte range, endianness, length)
    //   - exact AAD bytes (raw ClientHello on the wire vs parsed payload; include/exclude
    //     handshake header; match Go `hello.original` semantics exactly)
    //   - exact session_id ciphertext bytes (TLS SessionId field length vs REALITY ciphertext)
    //   - exact plaintext layout after successful open (offsets for client version, timestamp,
    //     shortId; padding/trailing bytes; total plaintext length)
    //   - exact timestamp units (seconds vs milliseconds; signed vs unsigned; endianness)
    //   - exact shortId extraction (length, padding, empty shortId handling)
    //   - exact client version validation (allowed range, comparison with config min/max)
    //
    // Suggested Go reference shape (DO NOT treat as authoritative — confirm in upstream):
    //   block, _ := aes.NewCipher(authKey)          // key slice TBD from HKDF output
    //   aead, _ := cipher.NewGCM(block)
    //   aead.Open(plainText[:0], hello.random[20:32], sessionIdCiphertext, hello.original)
    //
    // After port: populate `RealityClientAuth` from decrypted plaintext, then call
    // `validate_reality_client_auth` before `inspect_reality_client_hello` returns Accepted.

    warn!("REALITY session_id open not implemented yet");
    Ok(RealitySessionOpenResult::NotImplemented)
}

pub struct RealityValidationConfig<'a> {
    pub server_names: &'a [String],
    pub short_ids: &'a [Vec<u8>],
    pub max_time_diff_ms: u64,
}

/// Validates REALITY client auth metadata after AEAD session_id decrypt.
///
/// Returns `Ok(true)` when all configured checks pass, `Ok(false)` otherwise.
///
/// TODO: Validate `server_names` once `RealityClientAuth` carries SNI/client version.
pub fn validate_reality_client_auth(
    auth: &RealityClientAuth,
    cfg: RealityValidationConfig<'_>,
    now_unix_ms: u64,
) -> std::io::Result<bool> {
    let _ = cfg.server_names;

    if cfg.short_ids.is_empty() {
        return Ok(false);
    }

    if !cfg
        .short_ids
        .iter()
        .any(|configured| configured.as_slice() == auth.short_id.as_slice())
    {
        return Ok(false);
    }

    if cfg.max_time_diff_ms == 0 {
        return Ok(true);
    }

    // TODO: Verify REALITY timestamp units when AEAD session_id open is implemented.
    // Go reference stores Unix seconds (u32); validation compares in milliseconds.
    let auth_unix_ms = auth.unix_time.saturating_mul(1000);
    let diff_ms = now_unix_ms.abs_diff(auth_unix_ms);

    Ok(diff_ms <= cfg.max_time_diff_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::enums::ProtocolVersion;
    use crate::protocol::structs::{ClientHelloPayload, Random, SessionId};

    struct FixedRandom;

    impl crate::protocol::rand::SecureRandom for FixedRandom {
        fn fill(&self, buf: &mut [u8]) -> Result<(), crate::protocol::rand::GetRandomFailed> {
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = i as u8;
            }
            Ok(())
        }
    }

    fn hello_with_session_id(session_id: SessionId) -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random([0u8; 32]),
            session_id,
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn open_reality_session_id_returns_auth_failed_for_short_session_id() {
        let hello = hello_with_session_id(SessionId::empty());
        let auth_key = [0u8; 42];

        let result = open_reality_session_id(&hello, &[], &auth_key).unwrap();

        assert_eq!(result, RealitySessionOpenResult::AuthFailed);
    }

    #[test]
    fn open_reality_session_id_returns_not_implemented_for_candidate_session_id() {
        let hello = hello_with_session_id(SessionId::random(&FixedRandom).unwrap());
        let auth_key = [0u8; 42];

        let result = open_reality_session_id(&hello, &[], &auth_key).unwrap();

        assert_eq!(result, RealitySessionOpenResult::NotImplemented);
    }

    fn validation_cfg<'a>(
        server_names: &'a [String],
        short_ids: &'a [Vec<u8>],
        max_time_diff_ms: u64,
    ) -> RealityValidationConfig<'a> {
        RealityValidationConfig {
            server_names,
            short_ids,
            max_time_diff_ms,
        }
    }

    #[test]
    fn validate_reality_client_auth_short_id_match() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01, 0x23], vec![0xab, 0xcd]];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
        let auth = RealityClientAuth {
            short_id: vec![0xab, 0xcd],
            unix_time: 1_700_000_000,
        };

        assert!(validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_short_id_mismatch() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01, 0x23]];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
        let auth = RealityClientAuth {
            short_id: vec![0xff],
            unix_time: 1_700_000_000,
        };

        assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_empty_short_ids() {
        let server_names = vec!["example.com".to_string()];
        let short_ids: Vec<Vec<u8>> = vec![];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
        let auth = RealityClientAuth {
            short_id: vec![],
            unix_time: 1_700_000_000,
        };

        assert!(!validate_reality_client_auth(&auth, cfg, 0).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_max_time_diff_disabled_when_zero() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg(&server_names, &short_ids, 0);
        let auth = RealityClientAuth {
            short_id: vec![0x01],
            unix_time: 1,
        };

        assert!(validate_reality_client_auth(&auth, cfg, u64::MAX).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_time_inside_window() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg(&server_names, &short_ids, 5_000);
        let auth = RealityClientAuth {
            short_id: vec![0x01],
            unix_time: 1_700_000_000,
        };
        let now_unix_ms = auth.unix_time * 1000 + 2_000;

        assert!(validate_reality_client_auth(&auth, cfg, now_unix_ms).unwrap());
    }

    #[test]
    fn validate_reality_client_auth_time_outside_window() {
        let server_names = vec!["example.com".to_string()];
        let short_ids = vec![vec![0x01]];
        let cfg = validation_cfg(&server_names, &short_ids, 1_000);
        let auth = RealityClientAuth {
            short_id: vec![0x01],
            unix_time: 1_700_000_000,
        };
        let now_unix_ms = auth.unix_time * 1000 + 2_000;

        assert!(!validate_reality_client_auth(&auth, cfg, now_unix_ms).unwrap());
    }
}
