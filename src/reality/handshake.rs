use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

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

    debug!(
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
#[path = "../../tests/unit/reality/handshake.rs"]
mod tests;
