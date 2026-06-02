
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
fn reality_accepted_debug_redacts_auth_key() {
    use crate::reality::auth::RealityAuthResult;

    let accepted = RealityAccepted {
        auth: RealityAuthResult {
            auth_key: [0xAB; 32],
            client_public_key: [0xCD; 32],
        },
        client: RealityClientAuth {
            client_version: [1, 8, 0, 0],
            unix_time: 1_700_000_000,
            short_id: [0x01, 0x02, 0, 0, 0, 0, 0, 0],
        },
        sni: Some("example.com".to_string()),
    };

    let debug = format!("{accepted:?}");

    assert!(debug.contains("auth_key"));
    assert!(debug.contains("client_public_key"));
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("client_version"));
    assert!(debug.contains("example.com"));
    assert!(!debug.contains("[171, 171, 171"));
    assert!(!debug.contains("[205, 205, 205"));
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

/// Documents inbound policy implemented in `main::handle_tls_client`:
/// - `RealityDecision::Fallback` → VLESS fallback relay (same as smoke bad shortId/SNI).
/// - `inspect_reality_client_hello` I/O error → fallback relay with reason `REALITY inspect error`.
/// - TLS record present but ClientHello parse error → fallback relay without inspect (reason `ClientHello parse error`).
/// Accepted REALITY clients never take the fallback relay path.
#[test]
fn client_hello_policy_matrix_fallback_vs_inspect_error() {
    let server_names = vec!["example.com".to_string()];
    let short_ids = vec![vec![0xAB, 0xCD]];

    let (hello_no_sni, msg_no_sni) = {
        let (mut hello, msg) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);
        hello
            .extensions
            .retain(|ext| !matches!(ext, ClientExtension::ServerName(_)));
        (hello, msg)
    };
    let missing_sni = inspect_reality_client_hello(
        &hello_no_sni,
        &msg_no_sni,
        inspect_cfg_with_versions(&server_names, &short_ids, 0, None, None, None),
    )
    .unwrap();
    assert!(matches!(missing_sni, RealityDecision::Fallback));

    let (hello_no_ks, msg_no_ks) = {
        let random = Random([0x22; 32]);
        let hello = ClientHelloPayload {
            extensions: vec![
                ClientExtension::make_sni(&DnsName::try_from("example.com").unwrap()),
                ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
            ],
            ..reality_candidate_hello(random)
        };
        let msg = build_minimal_handshake_message(&random.0, &[0u8; 32]);
        (hello, msg)
    };
    let no_keyshare = inspect_reality_client_hello(
        &hello_no_ks,
        &msg_no_ks,
        inspect_cfg_with_versions(&server_names, &short_ids, 0, None, None, None),
    )
    .unwrap();
    assert!(matches!(no_keyshare, RealityDecision::Fallback));

    let (hello, handshake_message) = build_valid_reality_client(1_700_000_000, &[0xAB, 0xCD]);
    let inspect_err = inspect_reality_client_hello(
        &hello,
        &handshake_message,
        inspect_cfg_with_versions(
            &server_names,
            &short_ids,
            0,
            Some("not.a.version"),
            None,
            None,
        ),
    )
    .unwrap_err();
    assert_eq!(inspect_err.kind(), std::io::ErrorKind::InvalidInput);
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
