use std::fmt;
use std::io::{Error, ErrorKind};

use tokio::io::{AsyncRead, AsyncWriteExt};
use tracing::info;

use crate::protocol::structs::ClientHelloPayload;
use crate::reality::handshake::RealityObservedServerHello;
use crate::reality::RealityAccepted;
use crate::tls::records::build_handshake_record;
use crate::tls::TlsRecordContentType;

use super::certificate::{
    build_tls13_certificate_message, build_tls13_certificate_verify_ed25519,
    generate_reality_ephemeral_ed25519_certificate,
};
use super::cipher_suite::{tls13_cipher_suite, Tls13CipherSuite};
use super::key_schedule::{
    compute_finished_verify_data, derive_application_traffic_secrets, derive_finished_key,
    derive_handshake_traffic_secrets, derive_traffic_key, hash_len, verify_finished_data,
    Tls13ApplicationSecrets, Tls13HandshakeSecrets,
};
use super::key_share::{
    encode_key_share_extension_body, extract_client_x25519_key_share,
    generate_x25519_server_key_share, Tls13ServerKeyShare,
};
use super::messages::{
    build_encrypted_extensions_empty, build_finished, build_tls13_server_hello,
    Tls13ServerHelloParams, HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_SERVER_HELLO,
};
use super::record_crypto::{Tls13RecordDecryptor, Tls13RecordEncryptor};
use super::stream::{read_tls_record_from_stream, RealityTls13ApplicationStream};
use super::transcript::TranscriptHash;

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

const HANDSHAKE_NOT_IMPLEMENTED_MSG: &str =
    "REALITY TLS 1.3 server state machine is not implemented yet";

/// REALITY accepted-path TLS 1.3 server handshake state container.
///
/// Upstream equivalent: Go `serverHandshakeStateTLS13` in XTLS/REALITY.
pub struct RealityTls13ServerState {
    pub accepted: RealityAccepted,
    pub observed_server_hello: RealityObservedServerHello,
    pub suite: Tls13CipherSuite,
    pub transcript: TranscriptHash,
    pub server_key_share: Option<Tls13ServerKeyShare>,
    pub server_hello_message: Option<Vec<u8>>,
    pub handshake_secrets: Option<Tls13HandshakeSecrets>,
    pub server_finished_message: Option<Vec<u8>>,
    pub client_finished_verified: bool,
    pub application_secrets: Option<Tls13ApplicationSecrets>,
}

struct ObservedServerHelloDebug<'a>(&'a RealityObservedServerHello);

impl fmt::Debug for ObservedServerHelloDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityObservedServerHello")
            .field(
                "cipher_suite",
                &format!("0x{:04x}", self.0.server_hello.cipher_suite),
            )
            .field(
                "raw_handshake_message_len",
                &self.0.raw_handshake_message.len(),
            )
            .finish()
    }
}

impl fmt::Debug for RealityTls13ServerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityTls13ServerState")
            .field("sni", &self.accepted.sni)
            .field("client_version", &self.accepted.client.client_version)
            .field("suite", &self.suite.name)
            .field("transcript", &self.transcript)
            .field(
                "observed_server_hello",
                &ObservedServerHelloDebug(&self.observed_server_hello),
            )
            .field("server_key_share", &self.server_key_share)
            .field(
                "server_hello_message_len",
                &self
                    .server_hello_message
                    .as_ref()
                    .map(|message| message.len()),
            )
            .field(
                "handshake_secrets",
                &self.handshake_secrets.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "server_finished_message_len",
                &self
                    .server_finished_message
                    .as_ref()
                    .map(|message| message.len()),
            )
            .field("client_finished_verified", &self.client_finished_verified)
            .field(
                "application_secrets",
                &self.application_secrets.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl RealityTls13ServerState {
    pub fn new(
        accepted: RealityAccepted,
        observed_server_hello: RealityObservedServerHello,
    ) -> std::io::Result<Self> {
        let suite = tls13_cipher_suite(observed_server_hello.server_hello.cipher_suite)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    format!(
                        "unsupported destination ServerHello cipher suite: 0x{:04x}",
                        observed_server_hello.server_hello.cipher_suite
                    ),
                )
            })?;
        let transcript = TranscriptHash::new(suite.hash);

        Ok(Self {
            accepted,
            observed_server_hello,
            suite,
            transcript,
            server_key_share: None,
            server_hello_message: None,
            handshake_secrets: None,
            server_finished_message: None,
            client_finished_verified: false,
            application_secrets: None,
        })
    }

    pub fn prepare_server_hello(
        &mut self,
        client_hello: &ClientHelloPayload,
    ) -> std::io::Result<&[u8]> {
        let client_public_key =
            extract_client_x25519_key_share(client_hello)?.ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "TLS 1.3 accepted ServerHello requires client X25519 key_share",
                )
            })?;

        let server_key_share = generate_x25519_server_key_share(client_public_key)?;
        let key_share_extension_body = encode_key_share_extension_body(&server_key_share)?;

        // TODO: transcript must include full ClientHello handshake message and generated
        // ServerHello handshake message in exact order. Do not update transcript here until
        // raw ClientHello message bytes are available in state.

        let params = Tls13ServerHelloParams {
            // TODO: verify exact upstream REALITY random/camouflage behavior
            random: self.observed_server_hello.server_hello.random,
            session_id_echo: client_hello.session_id.as_bytes().to_vec(),
            cipher_suite: self.suite.id,
            key_share_extension_body,
        };

        let message = build_tls13_server_hello(&params)?;

        self.server_key_share = Some(server_key_share);
        self.server_hello_message = Some(message);

        Ok(self.server_hello_message.as_deref().unwrap())
    }

    pub fn update_transcript_client_server_hello(
        &mut self,
        client_hello_message: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        if client_hello_message.first() != Some(&HANDSHAKE_TYPE_CLIENT_HELLO) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "TLS 1.3 transcript ClientHello message must start with handshake type 0x01",
            ));
        }

        let server_hello_message = self.server_hello_message.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 transcript update requires generated ServerHello message",
            )
        })?;

        if server_hello_message.first() != Some(&HANDSHAKE_TYPE_SERVER_HELLO) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "TLS 1.3 transcript ServerHello message must start with handshake type 0x02",
            ));
        }

        self.transcript.update(client_hello_message);
        self.transcript.update(server_hello_message);

        Ok(self.transcript.digest())
    }

    pub fn derive_handshake_secrets(&mut self, transcript_hash: &[u8]) -> std::io::Result<()> {
        let server_key_share = self.server_key_share.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 handshake secret derivation requires server ECDHE key share",
            )
        })?;

        let secrets = derive_handshake_traffic_secrets(
            self.suite,
            &server_key_share.shared_secret,
            transcript_hash,
        )?;
        self.handshake_secrets = Some(secrets);
        Ok(())
    }

    /// Builds encrypted EncryptedExtensions, Certificate, CertificateVerify, and Finished
    /// TLS records for the server.
    ///
    /// Transcript is updated with plaintext handshake messages, not encrypted records.
    pub fn build_encrypted_server_handshake_records(&mut self) -> std::io::Result<Vec<u8>> {
        let server_handshake_traffic_secret = self
            .handshake_secrets
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "TLS 1.3 encrypted handshake records require derived handshake secrets",
                )
            })?
            .server_handshake_traffic_secret
            .clone();

        let traffic_keys = derive_traffic_key(self.suite, &server_handshake_traffic_secret)?;
        let mut encryptor = Tls13RecordEncryptor::new(self.suite, traffic_keys)?;

        // TODO: REALITY upstream patches/generated cert using HMAC-SHA512 over AuthKey and
        // Ed25519 public key — see `crate::reality::certificate::patch_reality_certificate_der`.

        let encrypted_extensions = build_encrypted_extensions_empty()?;
        self.transcript.update(&encrypted_extensions);

        let ephemeral_cert =
            generate_reality_ephemeral_ed25519_certificate(self.accepted.sni.as_deref())?;
        // TODO(upstream REALITY): patch cert DER via `patch_reality_certificate_der` once the
        // exact signature offset is ported; requires auth_key + ClientHello/ServerHello bytes.
        let certificate = build_tls13_certificate_message(&[ephemeral_cert.der])?;
        self.transcript.update(&certificate);

        let certificate_verify_transcript_hash = self.transcript.digest();
        let certificate_verify = build_tls13_certificate_verify_ed25519(
            &ephemeral_cert.signing_key,
            &certificate_verify_transcript_hash,
        )?;
        self.transcript.update(&certificate_verify);

        let finished_key = derive_finished_key(self.suite, &server_handshake_traffic_secret)?;
        let transcript_hash = self.transcript.digest();
        let verify_data =
            compute_finished_verify_data(self.suite, &finished_key, &transcript_hash)?;
        let finished = build_finished(&verify_data)?;

        let encrypted_extensions_record =
            encryptor.encrypt_handshake_message(&encrypted_extensions)?;
        let certificate_record = encryptor.encrypt_handshake_message(&certificate)?;
        let certificate_verify_record = encryptor.encrypt_handshake_message(&certificate_verify)?;
        let finished_record = encryptor.encrypt_handshake_message(&finished)?;

        self.transcript.update(&finished);
        self.server_finished_message = Some(finished);

        let mut records = encrypted_extensions_record;
        records.extend_from_slice(&certificate_record);
        records.extend_from_slice(&certificate_verify_record);
        records.extend_from_slice(&finished_record);
        Ok(records)
    }

    pub fn build_server_finished_message(&mut self) -> std::io::Result<Vec<u8>> {
        let server_handshake_traffic_secret = self
            .handshake_secrets
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "TLS 1.3 server Finished requires derived handshake secrets",
                )
            })?
            .server_handshake_traffic_secret
            .clone();

        let finished_key = derive_finished_key(self.suite, &server_handshake_traffic_secret)?;
        let transcript_hash = self.transcript.digest();
        let verify_data =
            compute_finished_verify_data(self.suite, &finished_key, &transcript_hash)?;
        let finished = build_finished(&verify_data)?;

        self.transcript.update(&finished);
        self.server_finished_message = Some(finished.clone());

        Ok(finished)
    }

    pub fn verify_client_finished_message(
        &mut self,
        finished_message: &[u8],
    ) -> std::io::Result<bool> {
        let client_handshake_traffic_secret = self
            .handshake_secrets
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "TLS 1.3 client Finished verification requires derived handshake secrets",
                )
            })?
            .client_handshake_traffic_secret
            .clone();

        let expected_hash_len = hash_len(self.suite.hash);
        let verify_data = parse_finished_verify_data(finished_message, expected_hash_len)?;

        let finished_key = derive_finished_key(self.suite, &client_handshake_traffic_secret)?;
        let transcript_hash = self.transcript.digest();
        let verified =
            verify_finished_data(self.suite, &finished_key, &transcript_hash, &verify_data)?;

        if verified {
            self.transcript.update(finished_message);
            self.client_finished_verified = true;
        }

        Ok(verified)
    }

    pub fn derive_application_secrets(&mut self) -> std::io::Result<()> {
        if !self.client_finished_verified {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 application secret derivation requires verified client Finished",
            ));
        }

        let handshake_secret = self
            .handshake_secrets
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "TLS 1.3 application secret derivation requires derived handshake secrets",
                )
            })?
            .handshake_secret
            .clone();

        let transcript_hash = self.transcript.digest();
        let secrets =
            derive_application_traffic_secrets(self.suite, &handshake_secret, &transcript_hash)?;
        self.application_secrets = Some(secrets);
        Ok(())
    }

    pub fn handshake_not_implemented(&self) -> Error {
        Error::new(ErrorKind::Unsupported, HANDSHAKE_NOT_IMPLEMENTED_MSG)
    }
}

/// Completes the REALITY accepted-path TLS 1.3 handshake and returns an application stream.
///
/// Unsupported features return [`ErrorKind::Unsupported`] with a precise message. Accepted-path
/// callers must not fall back after entering this flow.
pub async fn complete_reality_tls13_handshake<S>(
    mut stream: S,
    client_hello_payload: &ClientHelloPayload,
    client_hello_message: &[u8],
    mut state: RealityTls13ServerState,
) -> std::io::Result<RealityTls13ApplicationStream<S>>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    info!(
        sni = ?state.accepted.sni,
        cipher_suite = state.suite.name,
        "REALITY TLS 1.3 handshake: preparing ServerHello"
    );
    state.prepare_server_hello(client_hello_payload)?;

    let server_hello_message = state
        .server_hello_message
        .as_ref()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "TLS 1.3 ServerHello message missing after prepare",
            )
        })?
        .clone();
    let server_hello_record = build_handshake_record(&server_hello_message)?;

    info!("REALITY TLS 1.3 handshake: writing ServerHello record");
    stream.write_all(&server_hello_record).await?;

    info!("REALITY TLS 1.3 handshake: updating transcript and deriving handshake secrets");
    let transcript_hash = state.update_transcript_client_server_hello(client_hello_message)?;
    state.derive_handshake_secrets(&transcript_hash)?;

    info!("REALITY TLS 1.3 handshake: building encrypted server handshake messages");
    let encrypted_handshake_records = state.build_encrypted_server_handshake_records()?;

    info!(
        encrypted_handshake_records_len = encrypted_handshake_records.len(),
        "REALITY TLS 1.3 handshake: writing encrypted server handshake records"
    );
    stream.write_all(&encrypted_handshake_records).await?;
    stream.flush().await?;

    info!("REALITY TLS 1.3 handshake: reading encrypted client Finished record");
    let client_finished_record = read_tls_record_from_stream(&mut stream).await?;
    if client_finished_record.content_type != TlsRecordContentType::ApplicationData {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "TLS 1.3 client Finished must be sent as ApplicationData record, got {:?}",
                client_finished_record.content_type
            ),
        ));
    }

    let client_handshake_traffic_secret = state
        .handshake_secrets
        .as_ref()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 client Finished decrypt requires derived handshake secrets",
            )
        })?
        .client_handshake_traffic_secret
        .clone();
    let client_handshake_keys = derive_traffic_key(state.suite, &client_handshake_traffic_secret)?;
    let mut client_handshake_decryptor =
        Tls13RecordDecryptor::new(state.suite, client_handshake_keys)?;
    let client_finished_message =
        client_handshake_decryptor.decrypt_handshake_record(&client_finished_record)?;

    info!("REALITY TLS 1.3 handshake: verifying client Finished");
    let verified = state.verify_client_finished_message(&client_finished_message)?;
    if !verified {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 client Finished verification failed",
        ));
    }

    info!("REALITY TLS 1.3 handshake: deriving application traffic secrets");
    state.derive_application_secrets()?;

    let application_secrets = state.application_secrets.as_ref().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 application secrets missing after derivation",
        )
    })?;

    let read_keys = derive_traffic_key(
        state.suite,
        &application_secrets.client_application_traffic_secret,
    )?;
    let write_keys = derive_traffic_key(
        state.suite,
        &application_secrets.server_application_traffic_secret,
    )?;
    let read_decryptor = Tls13RecordDecryptor::new(state.suite, read_keys)?;
    let write_encryptor = Tls13RecordEncryptor::new(state.suite, write_keys)?;

    info!("REALITY TLS 1.3 handshake: complete, application stream ready");
    Ok(RealityTls13ApplicationStream::new(
        stream,
        read_decryptor,
        write_encryptor,
    ))
}

fn parse_finished_verify_data(
    finished_message: &[u8],
    expected_hash_len: usize,
) -> std::io::Result<Vec<u8>> {
    if finished_message.first() != Some(&HANDSHAKE_TYPE_FINISHED) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 Finished message must start with handshake type 0x14",
        ));
    }

    if finished_message.len() < 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 Finished message truncated",
        ));
    }

    let body_len = u32::from_be_bytes([
        0,
        finished_message[1],
        finished_message[2],
        finished_message[3],
    ]) as usize;

    if body_len != expected_hash_len {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "TLS 1.3 Finished verify_data must be {expected_hash_len} bytes, got {body_len}"
            ),
        ));
    }

    if finished_message.len() != 4 + body_len {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 Finished message length mismatch",
        ));
    }

    Ok(finished_message[4..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::enums::{NamedGroup, ProtocolVersion};
    use crate::protocol::structs::{
        ClientExtension, ClientHelloPayload, KeyShareEntry, Random, SessionId,
    };
    use crate::reality::auth::RealityAuthResult;
    use crate::reality::handshake::{
        extract_observed_server_hello, RealityDestHandshake, RealityObservedServerHello,
    };
    use crate::reality::session::RealityClientAuth;
    use crate::reality::tls13::cipher_suite::TLS_AES_128_GCM_SHA256;
    use crate::reality::tls13::hash_len;
    use crate::reality::tls13::messages::build_encrypted_extensions_empty;
    use crate::reality::tls13::transcript::Tls13HashAlgorithm;
    use crate::tls::records::{parse_tls_records, TLS_RECORD_APPLICATION_DATA};
    use crate::tls::{
        parse_tls_server_hello_handshake, TlsRecord, TlsRecordContentType, EXTENSION_KEY_SHARE,
        EXTENSION_SUPPORTED_VERSIONS, NAMED_GROUP_X25519,
    };

    const TLS_RECORD_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
    const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
    const X25519_KEY_EXCHANGE_LEN: usize = 32;

    fn build_server_hello_handshake_message(
        cipher_suite: u16,
        extensions: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let random = [0x11; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);

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

    fn valid_observed_server_hello(cipher_suite: u16) -> RealityObservedServerHello {
        let message = build_server_hello_handshake_message(
            cipher_suite,
            &[
                (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
                (
                    EXTENSION_KEY_SHARE,
                    &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
                ),
            ],
        );
        let mut raw = Vec::with_capacity(5 + message.len());
        raw.push(0x16);
        raw.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
        raw.extend_from_slice(&(message.len() as u16).to_be_bytes());
        raw.extend_from_slice(&message);

        let dest_handshake = RealityDestHandshake {
            raw_server_bytes: raw.clone(),
            records: vec![TlsRecord {
                content_type: TlsRecordContentType::Handshake,
                legacy_version: TLS_RECORD_LEGACY_VERSION,
                payload: message.clone(),
                raw,
            }],
        };

        extract_observed_server_hello(&dest_handshake).expect("valid observed ServerHello")
    }

    fn sample_accepted() -> RealityAccepted {
        RealityAccepted {
            auth: RealityAuthResult {
                auth_key: [0xde; 32],
                client_public_key: [0xad; 32],
            },
            client: RealityClientAuth {
                client_version: [1, 8, 0, 0],
                unix_time: 1_700_000_000,
                short_id: [0xAB, 0xCD, 0, 0, 0, 0, 0, 0],
            },
            sni: Some("example.com".to_string()),
        }
    }

    fn client_hello_with_x25519_keyshare(
        payload: Vec<u8>,
        session_id: SessionId,
    ) -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random([0x33; 32]),
            session_id,
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: vec![ClientExtension::KeyShare(vec![KeyShareEntry::new(
                NamedGroup::X25519,
                payload,
            )])],
        }
    }

    fn client_hello_without_keyshare() -> ClientHelloPayload {
        ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random([0x33; 32]),
            session_id: SessionId::empty(),
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn new_works_with_observed_server_hello_cipher_suite_0x1301() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let state = RealityTls13ServerState::new(sample_accepted(), observed).expect("valid state");

        assert_eq!(state.suite.id, TLS_AES_128_GCM_SHA256);
        assert_eq!(state.suite.name, "TLS_AES_128_GCM_SHA256");
        assert_eq!(state.transcript.algorithm(), Tls13HashAlgorithm::Sha256);
        assert_eq!(state.accepted.sni, Some("example.com".to_string()));
        assert!(state.server_key_share.is_none());
        assert!(state.server_hello_message.is_none());
        assert!(state.handshake_secrets.is_none());
        assert!(state.server_finished_message.is_none());
        assert!(!state.client_finished_verified);
        assert!(state.application_secrets.is_none());
    }

    #[test]
    fn new_rejects_unknown_cipher_suite() {
        let observed = valid_observed_server_hello(0x1304);
        let err = RealityTls13ServerState::new(sample_accepted(), observed).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("0x1304"));
    }

    #[test]
    fn debug_does_not_include_auth_key_or_raw_handshake_bytes() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let state = RealityTls13ServerState::new(sample_accepted(), observed.clone()).unwrap();
        let debug = format!("{state:?}");

        assert!(!debug.contains("auth_key"));
        assert!(!debug.contains("0xde"));
        assert!(!debug.contains(&format!("{:?}", observed.raw_handshake_message)));
        assert!(debug.contains("TLS_AES_128_GCM_SHA256"));
        assert!(debug.contains("example.com"));
        assert!(debug.contains("[1, 8, 0, 0]"));
        assert!(debug.contains("raw_handshake_message_len"));
    }

    #[test]
    fn handshake_not_implemented_returns_unsupported() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
        let err = state.handshake_not_implemented();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.to_string(), HANDSHAKE_NOT_IMPLEMENTED_MSG);
    }

    #[test]
    fn prepare_server_hello_builds_handshake_message_and_stores_state() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
        let client_key: [u8; 32] = core::array::from_fn(|i| 0x44 + i as u8);
        let client_hello =
            client_hello_with_x25519_keyshare(client_key.to_vec(), SessionId::empty());

        let message = state
            .prepare_server_hello(&client_hello)
            .expect("valid ServerHello plan")
            .to_vec();

        assert_eq!(message[0], HANDSHAKE_TYPE_SERVER_HELLO);
        assert!(state.server_key_share.is_some());
        assert_eq!(
            state.server_hello_message.as_deref(),
            Some(message.as_slice())
        );
    }

    #[test]
    fn prepare_server_hello_requires_client_x25519_key_share() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();

        let err = state
            .prepare_server_hello(&client_hello_without_keyshare())
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("X25519 key_share"));
        assert!(state.server_key_share.is_none());
        assert!(state.server_hello_message.is_none());
    }

    #[test]
    fn prepare_server_hello_message_parses_as_tls13_server_hello() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
        let client_key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let client_hello =
            client_hello_with_x25519_keyshare(client_key.to_vec(), SessionId::empty());

        let message = state
            .prepare_server_hello(&client_hello)
            .expect("valid ServerHello plan")
            .to_vec();
        let parsed = parse_tls_server_hello_handshake(&message).expect("parsable ServerHello");

        assert_eq!(parsed.cipher_suite, TLS_AES_128_GCM_SHA256);
        assert_eq!(parsed.random, [0x11; 32]);
        assert_eq!(parsed.session_id_echo, client_hello.session_id.as_bytes());
        assert!(parsed.get_extension(EXTENSION_SUPPORTED_VERSIONS).is_some());
        assert!(parsed.get_extension(EXTENSION_KEY_SHARE).is_some());
    }

    fn sample_client_hello_handshake_message() -> Vec<u8> {
        vec![0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00]
    }

    fn state_with_prepared_server_hello() -> RealityTls13ServerState {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
        let client_key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let client_hello =
            client_hello_with_x25519_keyshare(client_key.to_vec(), SessionId::empty());
        state
            .prepare_server_hello(&client_hello)
            .expect("valid ServerHello plan");
        state
    }

    fn state_with_fixed_server_hello_message(
        server_hello_message: Vec<u8>,
    ) -> RealityTls13ServerState {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
        state.server_hello_message = Some(server_hello_message);
        state
    }

    #[test]
    fn update_transcript_client_server_hello_changes_digest() {
        let mut state = state_with_prepared_server_hello();
        let empty_digest = state.transcript.digest();
        let client_hello_message = sample_client_hello_handshake_message();

        let digest = state
            .update_transcript_client_server_hello(&client_hello_message)
            .expect("valid transcript update");

        assert_ne!(digest, empty_digest);
        assert_eq!(digest.len(), 32);
        assert_eq!(
            state.transcript.len(),
            client_hello_message.len()
                + state
                    .server_hello_message
                    .as_ref()
                    .expect("server hello stored")
                    .len()
        );
    }

    #[test]
    fn update_transcript_client_server_hello_is_deterministic() {
        let client_hello_message = sample_client_hello_handshake_message();
        let server_hello_message = vec![0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00];

        let mut first = state_with_fixed_server_hello_message(server_hello_message.clone());
        let first_digest = first
            .update_transcript_client_server_hello(&client_hello_message)
            .expect("valid transcript update");

        let mut second = state_with_fixed_server_hello_message(server_hello_message);
        let second_digest = second
            .update_transcript_client_server_hello(&client_hello_message)
            .expect("valid transcript update");

        assert_eq!(first_digest, second_digest);
    }

    #[test]
    fn update_transcript_client_server_hello_rejects_wrong_client_handshake_type() {
        let mut state = state_with_prepared_server_hello();
        let err = state
            .update_transcript_client_server_hello(&[0x02, 0x00, 0x00, 0x01, 0x00])
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("0x01"));
    }

    #[test]
    fn update_transcript_client_server_hello_requires_server_hello_message() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();

        let err = state
            .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("ServerHello message"));
    }

    #[test]
    fn derive_handshake_secrets_stores_traffic_secrets() {
        let mut state = state_with_prepared_server_hello();
        let transcript_hash = state
            .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
            .expect("valid transcript update");

        state
            .derive_handshake_secrets(&transcript_hash)
            .expect("valid handshake secret derivation");

        let secrets = state
            .handshake_secrets
            .as_ref()
            .expect("handshake secrets stored");
        assert_eq!(secrets.handshake_secret.len(), 32);
        assert_eq!(secrets.client_handshake_traffic_secret.len(), 32);
        assert_eq!(secrets.server_handshake_traffic_secret.len(), 32);
        assert_ne!(
            secrets.client_handshake_traffic_secret,
            secrets.server_handshake_traffic_secret
        );
    }

    #[test]
    fn derive_handshake_secrets_requires_server_key_share() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let mut state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();

        let err = state.derive_handshake_secrets(&[0x01; 32]).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("ECDHE key share"));
        assert!(state.handshake_secrets.is_none());
    }

    fn state_with_handshake_secrets() -> RealityTls13ServerState {
        let mut state = state_with_prepared_server_hello();
        let transcript_hash = state
            .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
            .expect("valid transcript update");
        state
            .derive_handshake_secrets(&transcript_hash)
            .expect("valid handshake secret derivation");
        state
    }

    #[test]
    fn build_encrypted_server_handshake_records_non_empty() {
        let mut state = state_with_handshake_secrets();
        let records = state
            .build_encrypted_server_handshake_records()
            .expect("valid encrypted handshake records");

        assert!(!records.is_empty());
    }

    #[test]
    fn build_encrypted_server_handshake_records_first_record_is_application_data() {
        let mut state = state_with_handshake_secrets();
        let records = state
            .build_encrypted_server_handshake_records()
            .expect("valid encrypted handshake records");

        assert_eq!(records[0], TLS_RECORD_APPLICATION_DATA);
        let parsed = parse_tls_records(&records).expect("parsable encrypted records");
        assert_eq!(parsed.len(), 4);
        assert_eq!(
            parsed[0].content_type,
            TlsRecordContentType::ApplicationData
        );
    }

    #[test]
    fn build_encrypted_server_handshake_records_updates_transcript_with_plaintext_messages() {
        let mut state = state_with_handshake_secrets();
        let transcript_len_before = state.transcript.len();

        state
            .build_encrypted_server_handshake_records()
            .expect("valid encrypted handshake records");

        assert!(state.transcript.len() > transcript_len_before);
        assert!(state.server_finished_message.is_some());
    }

    #[test]
    fn build_encrypted_server_handshake_records_requires_handshake_secrets() {
        let mut state = state_with_prepared_server_hello();
        state
            .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
            .expect("valid transcript update");

        let err = state
            .build_encrypted_server_handshake_records()
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("handshake secrets"));
    }

    fn state_ready_for_server_finished() -> RealityTls13ServerState {
        let mut state = state_with_handshake_secrets();
        let encrypted_extensions = build_encrypted_extensions_empty().expect("valid EE");
        state.transcript.update(&encrypted_extensions);
        state
    }

    fn build_valid_client_finished_message(state: &RealityTls13ServerState) -> Vec<u8> {
        let secrets = state.handshake_secrets.as_ref().expect("handshake secrets");
        let finished_key =
            derive_finished_key(state.suite, &secrets.client_handshake_traffic_secret)
                .expect("client finished key");
        let transcript_hash = state.transcript.digest();
        let verify_data =
            compute_finished_verify_data(state.suite, &finished_key, &transcript_hash)
                .expect("client verify_data");
        build_finished(&verify_data).expect("client Finished message")
    }

    #[test]
    fn build_server_finished_message_length_matches_hash_len() {
        let mut state = state_ready_for_server_finished();
        let finished = state
            .build_server_finished_message()
            .expect("valid server Finished message");

        assert_eq!(finished[0], HANDSHAKE_TYPE_FINISHED);
        assert_eq!(finished.len(), 4 + hash_len(state.suite.hash));
        assert_eq!(
            state.server_finished_message.as_deref(),
            Some(finished.as_slice())
        );
    }

    #[test]
    fn build_server_finished_message_requires_handshake_secrets() {
        let mut state = state_with_prepared_server_hello();
        state
            .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
            .expect("valid transcript update");

        let err = state.build_server_finished_message().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("handshake secrets"));
        assert!(state.server_finished_message.is_none());
    }

    #[test]
    fn verify_client_finished_message_accepts_valid_data() {
        let mut state = state_ready_for_server_finished();
        state
            .build_server_finished_message()
            .expect("valid server Finished message");
        let client_finished = build_valid_client_finished_message(&state);

        let verified = state
            .verify_client_finished_message(&client_finished)
            .expect("valid client Finished verification");

        assert!(verified);
        assert!(state.client_finished_verified);
    }

    #[test]
    fn verify_client_finished_message_rejects_wrong_data() {
        let mut state = state_ready_for_server_finished();
        state
            .build_server_finished_message()
            .expect("valid server Finished message");
        let mut client_finished = build_valid_client_finished_message(&state);
        client_finished[7] ^= 0x01;

        let verified = state
            .verify_client_finished_message(&client_finished)
            .expect("client Finished verification result");

        assert!(!verified);
        assert!(!state.client_finished_verified);
    }

    #[test]
    fn verify_client_finished_message_updates_transcript_only_on_success() {
        let mut state = state_ready_for_server_finished();
        state
            .build_server_finished_message()
            .expect("valid server Finished message");
        let transcript_len_before = state.transcript.len();
        let mut invalid_finished = build_valid_client_finished_message(&state);
        invalid_finished[8] ^= 0x02;

        let verified = state
            .verify_client_finished_message(&invalid_finished)
            .expect("client Finished verification result");
        assert!(!verified);
        assert_eq!(state.transcript.len(), transcript_len_before);

        let valid_finished = build_valid_client_finished_message(&state);
        let verified = state
            .verify_client_finished_message(&valid_finished)
            .expect("client Finished verification result");
        assert!(verified);
        assert_eq!(
            state.transcript.len(),
            transcript_len_before + valid_finished.len()
        );
    }

    #[test]
    fn verify_client_finished_message_requires_handshake_secrets() {
        let mut state = state_with_prepared_server_hello();
        let err = state
            .verify_client_finished_message(&[0x14, 0x00, 0x00, 0x20])
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("handshake secrets"));
        assert!(!state.client_finished_verified);
    }

    fn state_with_verified_client_finished() -> RealityTls13ServerState {
        let mut state = state_ready_for_server_finished();
        state
            .build_server_finished_message()
            .expect("valid server Finished message");
        let client_finished = build_valid_client_finished_message(&state);
        assert!(state
            .verify_client_finished_message(&client_finished)
            .expect("client Finished verification result"));
        state
    }

    #[test]
    fn derive_application_secrets_stores_traffic_secrets() {
        let mut state = state_with_verified_client_finished();
        state
            .derive_application_secrets()
            .expect("valid application secret derivation");

        let secrets = state
            .application_secrets
            .as_ref()
            .expect("application secrets stored");
        assert_eq!(secrets.master_secret.len(), hash_len(state.suite.hash));
        assert_eq!(
            secrets.client_application_traffic_secret.len(),
            hash_len(state.suite.hash)
        );
        assert_eq!(
            secrets.server_application_traffic_secret.len(),
            hash_len(state.suite.hash)
        );
        assert_ne!(
            secrets.client_application_traffic_secret,
            secrets.server_application_traffic_secret
        );
    }

    #[test]
    fn derive_application_secrets_requires_verified_client_finished() {
        let mut state = state_ready_for_server_finished();
        state
            .build_server_finished_message()
            .expect("valid server Finished message");

        let err = state.derive_application_secrets().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("client Finished"));
        assert!(state.application_secrets.is_none());
    }

    #[test]
    fn derive_application_secrets_requires_handshake_secrets() {
        let mut state = state_with_prepared_server_hello();
        state.client_finished_verified = true;

        let err = state.derive_application_secrets().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("handshake secrets"));
        assert!(state.application_secrets.is_none());
    }
}
