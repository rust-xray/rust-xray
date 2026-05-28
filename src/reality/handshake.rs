use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

use crate::protocol::structs::ClientHelloPayload;
use crate::tls::records::build_handshake_record;
use crate::tls::{
    parse_complete_tls_records_prefix, parse_server_hello_key_share,
    parse_tls_server_hello_handshake, TlsRecord, TlsRecordContentType, TlsServerHello,
    EXTENSION_KEY_SHARE, EXTENSION_SUPPORTED_VERSIONS, NAMED_GROUP_X25519,
};

use super::decision::RealityAccepted;
use super::stages;
use super::tls13::RealityTls13ServerState;

const DEST_HANDSHAKE_READ_CAP: usize = 64 * 1024;
const DEST_HANDSHAKE_READ_CHUNK: usize = 4 * 1024;

const TLS_RECORD_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
const X25519_KEY_EXCHANGE_LEN: usize = 32;

const TLS13_SERVER_HANDSHAKE_NOT_IMPLEMENTED_MSG: &str =
    "REALITY TLS 1.3 server handshake is not implemented yet; observed dest ServerHello is valid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityDestHandshake {
    pub raw_server_bytes: Vec<u8>,
    pub records: Vec<TlsRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityObservedServerHello {
    pub server_hello: TlsServerHello,
    pub raw_handshake_message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchedRealityHandshake {
    pub raw_client_bytes: Vec<u8>,
}

/// Generated partial TLS 1.3 server handshake bytes (ServerHello + encrypted EE/Finished).
///
/// This is **not** a complete or interoperable REALITY/TLS handshake: Certificate,
/// CertificateVerify, client Finished verification, and application-data keys are
/// missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialTls13Handshake {
    pub server_hello_record: Vec<u8>,
    pub encrypted_handshake_records: Vec<u8>,
}

impl PartialTls13Handshake {
    pub fn total_len(&self) -> usize {
        self.server_hello_record.len() + self.encrypted_handshake_records.len()
    }

    pub fn concat(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_len());
        bytes.extend_from_slice(&self.server_hello_record);
        bytes.extend_from_slice(&self.encrypted_handshake_records);
        bytes
    }
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn unsupported(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Unsupported, message.into())
}

/// Extracts and validates the first destination ServerHello handshake message.
pub fn extract_observed_server_hello(
    dest_handshake: &RealityDestHandshake,
) -> std::io::Result<RealityObservedServerHello> {
    let handshake_record = dest_handshake
        .records
        .iter()
        .find(|record| record.content_type == TlsRecordContentType::Handshake)
        .ok_or_else(|| invalid_data("destination handshake has no TLS Handshake record"))?;

    let raw_handshake_message = handshake_record.payload.clone();
    let server_hello = parse_tls_server_hello_handshake(&raw_handshake_message)?;
    validate_observed_server_hello(&server_hello)?;

    Ok(RealityObservedServerHello {
        server_hello,
        raw_handshake_message,
    })
}

fn validate_observed_server_hello(server_hello: &TlsServerHello) -> std::io::Result<()> {
    if server_hello.legacy_version != TLS_RECORD_LEGACY_VERSION {
        return Err(invalid_data(format!(
            "destination ServerHello legacy_version must be 0x0303, got 0x{:02x}{:02x}",
            server_hello.legacy_version[0], server_hello.legacy_version[1]
        )));
    }

    if server_hello.compression_method != 0 {
        return Err(invalid_data(format!(
            "destination ServerHello compression_method must be 0, got {}",
            server_hello.compression_method
        )));
    }

    let supported_versions = server_hello
        .get_extension(EXTENSION_SUPPORTED_VERSIONS)
        .ok_or_else(|| {
            invalid_data("destination ServerHello missing supported_versions extension")
        })?;

    if !supported_versions
        .windows(TLS13_VERSION.len())
        .any(|window| window == TLS13_VERSION)
    {
        return Err(invalid_data(
            "destination ServerHello supported_versions does not indicate TLS 1.3",
        ));
    }

    let key_share_data = server_hello
        .get_extension(EXTENSION_KEY_SHARE)
        .ok_or_else(|| invalid_data("destination ServerHello missing key_share extension"))?;

    let key_share = parse_server_hello_key_share(key_share_data)?;

    if key_share.group != NAMED_GROUP_X25519 {
        return Err(unsupported(format!(
            "destination ServerHello key_share group 0x{:04x} is not supported yet (expected X25519)",
            key_share.group
        )));
    }

    if key_share.key_exchange.len() != X25519_KEY_EXCHANGE_LEN {
        return Err(invalid_data(format!(
            "destination ServerHello X25519 key_exchange must be {} bytes, got {}",
            X25519_KEY_EXCHANGE_LEN,
            key_share.key_exchange.len()
        )));
    }

    Ok(())
}

fn contains_ccs_and_handshake(records: &[TlsRecord]) -> bool {
    let has_ccs = records
        .iter()
        .any(|r| r.content_type == TlsRecordContentType::ChangeCipherSpec);
    let has_handshake = records
        .iter()
        .any(|r| r.content_type == TlsRecordContentType::Handshake);
    has_ccs && has_handshake
}

fn contains_application_data_after_server_hello(records: &[TlsRecord]) -> bool {
    let mut seen_server_hello = false;
    for record in records {
        if contains_tls13_server_hello(std::slice::from_ref(record)) {
            seen_server_hello = true;
        }
        if seen_server_hello && record.content_type == TlsRecordContentType::ApplicationData {
            return true;
        }
    }
    false
}

fn should_stop_fetching(records: &[TlsRecord]) -> bool {
    if contains_application_data_after_server_hello(records) {
        return true;
    }
    if contains_ccs_and_handshake(records) {
        return true;
    }
    if contains_tls13_server_hello(records) {
        return true;
    }
    false
}

pub(crate) fn contains_tls13_server_hello(records: &[TlsRecord]) -> bool {
    records.iter().any(|record| {
        record.content_type == TlsRecordContentType::Handshake
            && record.payload.first() == Some(&0x02)
    })
}

/// Forwards the client ClientHello record to `dest` and reads TLS records until a
/// handshake observation stop condition is met.
pub async fn fetch_dest_handshake(
    dest: &mut TcpStream,
    client_hello_record: &[u8],
) -> std::io::Result<RealityDestHandshake> {
    dest.write_all(client_hello_record).await?;

    let mut raw_server_bytes = Vec::new();
    let mut hit_read_cap = false;

    loop {
        let (records, consumed) = parse_complete_tls_records_prefix(&raw_server_bytes)?;

        if should_stop_fetching(&records) {
            raw_server_bytes.truncate(consumed);
            return Ok(RealityDestHandshake {
                records,
                raw_server_bytes,
            });
        }

        if raw_server_bytes.len() >= DEST_HANDSHAKE_READ_CAP {
            hit_read_cap = true;
            raw_server_bytes.truncate(consumed);
            break;
        }

        let remaining = DEST_HANDSHAKE_READ_CAP - raw_server_bytes.len();
        let chunk_len = remaining.min(DEST_HANDSHAKE_READ_CHUNK);
        let mut chunk = vec![0u8; chunk_len];
        let read_len = dest.read(&mut chunk).await?;
        if read_len == 0 {
            if records.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "destination closed connection before sending handshake response",
                ));
            }
            raw_server_bytes.truncate(consumed);
            break;
        }
        raw_server_bytes.extend_from_slice(&chunk[..read_len]);
    }

    let (records, consumed) = parse_complete_tls_records_prefix(&raw_server_bytes)?;
    raw_server_bytes.truncate(consumed);

    if hit_read_cap && !contains_tls13_server_hello(&records) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "destination handshake read limit reached without ServerHello",
        ));
    }

    Ok(RealityDestHandshake {
        raw_server_bytes,
        records,
    })
}

/// - Read client Finished
/// - Hand off decrypted stream to VLESS
pub fn prepare_reality_tls13_state(
    dest_handshake: RealityDestHandshake,
    accepted: RealityAccepted,
) -> std::io::Result<RealityTls13ServerState> {
    let observed = extract_observed_server_hello(&dest_handshake)?;
    let state = RealityTls13ServerState::new(accepted, observed)?;

    info!(
        stage = stages::TLS13_STATE_CREATED,
        cipher_suite = state.suite.name,
        cipher_suite_id = format!("0x{:04x}", state.suite.id),
        sni = ?state.accepted.sni,
        client_version = ?state.accepted.client.client_version,
        observed_server_hello_message_len =
            state.observed_server_hello.raw_handshake_message.len(),
        "REALITY TLS 1.3 server state created"
    );

    Ok(state)
}

/// Builds partial TLS 1.3 server handshake records after dest ServerHello observation.
///
/// Updates transcript with plaintext handshake messages. Does not send bytes to the
/// client and does not complete the REALITY/TLS protocol.
pub fn generate_partial_tls13_handshake(
    state: &mut RealityTls13ServerState,
    client_hello_payload: &ClientHelloPayload,
    client_handshake_message: &[u8],
) -> std::io::Result<PartialTls13Handshake> {
    state.prepare_server_hello(client_hello_payload)?;
    let server_hello_message = state
        .server_hello_message
        .as_ref()
        .ok_or_else(|| invalid_data("TLS 1.3 ServerHello message missing after prepare"))?
        .clone();
    let server_hello_record = build_handshake_record(&server_hello_message)?;

    let transcript_hash = state.update_transcript_client_server_hello(client_handshake_message)?;
    state.derive_handshake_secrets(&transcript_hash)?;
    let encrypted_handshake_records = state.build_encrypted_server_handshake_records(
        crate::reality::RealityCertificatePatchMode::HmacOnly,
    )?;

    Ok(PartialTls13Handshake {
        server_hello_record,
        encrypted_handshake_records,
    })
}

/// Validates the observed destination ServerHello for REALITY camouflage input.
///
/// This does **not** patch or relay destination bytes to the client. A full REALITY
/// accepted path requires a TLS 1.3 server handshake state machine, not a single-buffer
/// ServerHello patch.
///
/// # TODO: REALITY accepted path — TLS 1.3 server handshake
///
/// - Port or implement TLS 1.3 server handshake state machine
/// - Generate ServerHello
/// - Derive handshake secrets
/// - Send EncryptedExtensions
/// - Send ephemeral certificate
/// - CertificateVerify
/// - Finished
/// - Read client Finished
/// - Hand off decrypted stream to VLESS
pub fn patch_reality_server_hello(
    dest_handshake: RealityDestHandshake,
    accepted: RealityAccepted,
) -> std::io::Result<PatchedRealityHandshake> {
    let _state = prepare_reality_tls13_state(dest_handshake, accepted)?;
    Err(unsupported(TLS13_SERVER_HANDSHAKE_NOT_IMPLEMENTED_MSG))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::auth::RealityAuthResult;
    use crate::reality::decision::RealityAccepted;
    use crate::reality::session::RealityClientAuth;
    use crate::reality::tls13::{Tls13HashAlgorithm, TLS_AES_128_GCM_SHA256};
    use crate::tls::TlsRecordContentType;
    use std::io::ErrorKind;

    fn build_server_hello_handshake_message(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        build_server_hello_handshake_message_with_cipher(extensions, TLS_AES_128_GCM_SHA256)
    }

    fn build_server_hello_handshake_message_with_cipher(
        extensions: &[(u16, &[u8])],
        cipher_suite: u16,
    ) -> Vec<u8> {
        let random = [0x11; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
        body.extend_from_slice(&random);
        body.push(0); // session_id_echo length
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0); // compression_method

        let mut extension_bytes = Vec::new();
        for (extension_type, data) in extensions {
            extension_bytes.extend_from_slice(&extension_type.to_be_bytes());
            extension_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            extension_bytes.extend_from_slice(data);
        }
        body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension_bytes);

        let mut message = Vec::with_capacity(4 + body.len());
        message.push(0x02);
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    fn x25519_key_share_bytes(key_exchange: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
        data.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
        data.extend_from_slice(key_exchange);
        data
    }

    fn valid_tls13_x25519_server_hello_message() -> Vec<u8> {
        build_server_hello_handshake_message(&[
            (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
            (
                EXTENSION_KEY_SHARE,
                &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
            ),
        ])
    }

    fn dest_handshake_from_server_hello_message(message: &[u8]) -> RealityDestHandshake {
        let record = handshake_record(message);
        RealityDestHandshake {
            raw_server_bytes: record.raw.clone(),
            records: vec![record],
        }
    }

    fn handshake_record(payload: &[u8]) -> TlsRecord {
        let mut raw = Vec::with_capacity(5 + payload.len());
        raw.push(0x16);
        raw.extend_from_slice(&[0x03, 0x03]);
        raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(payload);
        TlsRecord {
            content_type: TlsRecordContentType::Handshake,
            legacy_version: [0x03, 0x03],
            payload: payload.to_vec(),
            raw,
        }
    }

    fn application_data_record(payload: &[u8]) -> TlsRecord {
        let mut raw = Vec::with_capacity(5 + payload.len());
        raw.push(0x17);
        raw.extend_from_slice(&[0x03, 0x03]);
        raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(payload);
        TlsRecord {
            content_type: TlsRecordContentType::ApplicationData,
            legacy_version: [0x03, 0x03],
            payload: payload.to_vec(),
            raw,
        }
    }

    fn sample_accepted() -> RealityAccepted {
        RealityAccepted {
            auth: RealityAuthResult {
                auth_key: [0u8; 32],
                client_public_key: [0u8; 32],
            },
            client: RealityClientAuth {
                client_version: [1, 8, 0, 0],
                unix_time: 1_700_000_000,
                short_id: [0xAB, 0xCD, 0, 0, 0, 0, 0, 0],
            },
            sni: Some("example.com".to_string()),
        }
    }

    #[test]
    fn contains_tls13_server_hello_true_for_server_hello_payload() {
        let records = vec![handshake_record(&[0x02, 0x00, 0x00, 0x01])];
        assert!(contains_tls13_server_hello(&records));
    }

    #[test]
    fn contains_tls13_server_hello_false_for_client_hello_payload() {
        let records = vec![handshake_record(&[0x01, 0x00, 0x00, 0x01])];
        assert!(!contains_tls13_server_hello(&records));
    }

    #[test]
    fn contains_tls13_server_hello_false_for_application_data() {
        let records = vec![application_data_record(&[0xde, 0xad])];
        assert!(!contains_tls13_server_hello(&records));
    }

    #[test]
    fn reality_dest_handshake_stores_records() {
        let server_hello = handshake_record(&[0x02, 0x00, 0x00, 0x01]);
        let app_data = application_data_record(&[0xaa, 0xbb]);
        let mut raw_server_bytes = server_hello.raw.clone();
        raw_server_bytes.extend_from_slice(&app_data.raw);

        let dest_handshake = RealityDestHandshake {
            raw_server_bytes: raw_server_bytes.clone(),
            records: vec![server_hello.clone(), app_data.clone()],
        };

        assert_eq!(dest_handshake.raw_server_bytes, raw_server_bytes);
        assert_eq!(dest_handshake.records.len(), 2);
        assert_eq!(dest_handshake.records[0], server_hello);
        assert_eq!(dest_handshake.records[1], app_data);
    }

    #[test]
    fn extract_observed_server_hello_accepts_valid_tls13_x25519() {
        let message = valid_tls13_x25519_server_hello_message();
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let observed = extract_observed_server_hello(&dest_handshake).expect("valid ServerHello");

        assert_eq!(observed.raw_handshake_message, message);
        assert_eq!(
            observed.server_hello.legacy_version,
            TLS_RECORD_LEGACY_VERSION
        );
        assert_eq!(observed.server_hello.compression_method, 0);
        assert_eq!(
            observed
                .server_hello
                .get_extension(EXTENSION_SUPPORTED_VERSIONS),
            Some(TLS13_VERSION.as_slice())
        );
        assert_eq!(
            observed
                .server_hello
                .get_extension(EXTENSION_KEY_SHARE)
                .map(parse_server_hello_key_share)
                .transpose()
                .expect("valid key_share")
                .expect("key_share present")
                .group,
            NAMED_GROUP_X25519
        );
    }

    #[test]
    fn extract_observed_server_hello_rejects_missing_supported_versions() {
        let message = build_server_hello_handshake_message(&[(
            EXTENSION_KEY_SHARE,
            &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
        )]);
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("supported_versions"));
    }

    #[test]
    fn extract_observed_server_hello_rejects_non_tls13_supported_versions() {
        let message = build_server_hello_handshake_message(&[
            (EXTENSION_SUPPORTED_VERSIONS, &[0x03, 0x03]),
            (
                EXTENSION_KEY_SHARE,
                &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
            ),
        ]);
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("TLS 1.3"));
    }

    #[test]
    fn extract_observed_server_hello_rejects_missing_key_share() {
        let message =
            build_server_hello_handshake_message(&[(EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION)]);
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("key_share"));
    }

    #[test]
    fn extract_observed_server_hello_rejects_non_x25519_key_share() {
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&0x0017u16.to_be_bytes()); // secp256r1
        key_share.extend_from_slice(&65u16.to_be_bytes());
        key_share.extend_from_slice(&[0x33; 65]);

        let message = build_server_hello_handshake_message(&[
            (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
            (EXTENSION_KEY_SHARE, &key_share),
        ]);
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("X25519"));
    }

    #[test]
    fn extract_observed_server_hello_rejects_x25519_key_share_wrong_length() {
        let message = build_server_hello_handshake_message(&[
            (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
            (EXTENSION_KEY_SHARE, &x25519_key_share_bytes(&[0x22; 31])),
        ]);
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = extract_observed_server_hello(&dest_handshake).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn prepare_reality_tls13_state_creates_state_for_valid_observed_server_hello() {
        let dest_handshake =
            dest_handshake_from_server_hello_message(&valid_tls13_x25519_server_hello_message());
        let state = prepare_reality_tls13_state(dest_handshake, sample_accepted())
            .expect("valid TLS 1.3 state");

        assert_eq!(state.suite.id, TLS_AES_128_GCM_SHA256);
        assert_eq!(state.suite.name, "TLS_AES_128_GCM_SHA256");
        assert_eq!(state.transcript.algorithm(), Tls13HashAlgorithm::Sha256);
        assert_eq!(state.accepted.sni, Some("example.com".to_string()));
    }

    #[test]
    fn prepare_reality_tls13_state_rejects_invalid_server_hello() {
        let message =
            build_server_hello_handshake_message(&[(EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION)]);
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = prepare_reality_tls13_state(dest_handshake, sample_accepted()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("key_share"));
    }

    #[test]
    fn prepare_reality_tls13_state_rejects_unknown_cipher_suite() {
        let message = build_server_hello_handshake_message_with_cipher(
            &[
                (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
                (
                    EXTENSION_KEY_SHARE,
                    &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
                ),
            ],
            0x1304,
        );
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = prepare_reality_tls13_state(dest_handshake, sample_accepted()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("0x1304"));
    }

    #[test]
    fn patch_reality_server_hello_returns_unsupported_for_valid_observed_server_hello() {
        let dest_handshake =
            dest_handshake_from_server_hello_message(&valid_tls13_x25519_server_hello_message());

        let err = patch_reality_server_hello(dest_handshake, sample_accepted()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("TLS 1.3 server handshake"));
        assert_eq!(err.to_string(), TLS13_SERVER_HANDSHAKE_NOT_IMPLEMENTED_MSG);
    }

    #[test]
    fn patch_reality_server_hello_returns_validation_error_before_unsupported() {
        let message =
            build_server_hello_handshake_message(&[(EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION)]);
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = patch_reality_server_hello(dest_handshake, sample_accepted()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("key_share"));
    }

    #[test]
    fn patch_reality_server_hello_returns_unsupported_for_non_x25519_before_final_message() {
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&0x0017u16.to_be_bytes());
        key_share.extend_from_slice(&65u16.to_be_bytes());
        key_share.extend_from_slice(&[0x33; 65]);

        let message = build_server_hello_handshake_message(&[
            (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
            (EXTENSION_KEY_SHARE, &key_share),
        ]);
        let dest_handshake = dest_handshake_from_server_hello_message(&message);

        let err = patch_reality_server_hello(dest_handshake, sample_accepted()).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("X25519"));
        assert_ne!(err.to_string(), TLS13_SERVER_HANDSHAKE_NOT_IMPLEMENTED_MSG);
    }

    fn client_hello_with_x25519_keyshare() -> ClientHelloPayload {
        use crate::protocol::enums::{NamedGroup, ProtocolVersion};
        use crate::protocol::structs::{ClientExtension, KeyShareEntry, Random, SessionId};

        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random([0x33; 32]),
            session_id: SessionId::empty(),
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: vec![ClientExtension::KeyShare(vec![KeyShareEntry::new(
                NamedGroup::X25519,
                (0u8..32).collect::<Vec<u8>>(),
            )])],
        }
    }

    fn sample_client_handshake_message() -> Vec<u8> {
        vec![0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00]
    }

    #[test]
    fn generate_partial_tls13_handshake_returns_non_empty_records() {
        let dest_handshake =
            dest_handshake_from_server_hello_message(&valid_tls13_x25519_server_hello_message());
        let mut state = prepare_reality_tls13_state(dest_handshake, sample_accepted())
            .expect("valid TLS 1.3 state");

        let partial = generate_partial_tls13_handshake(
            &mut state,
            &client_hello_with_x25519_keyshare(),
            &sample_client_handshake_message(),
        )
        .expect("valid partial TLS 1.3 handshake");

        assert!(!partial.server_hello_record.is_empty());
        assert!(!partial.encrypted_handshake_records.is_empty());
        assert_eq!(partial.server_hello_record[0], 0x16);
        assert_eq!(partial.encrypted_handshake_records[0], 0x17);
        assert!(partial.total_len() > partial.server_hello_record.len());
        assert_eq!(partial.concat().len(), partial.total_len());
    }
}
