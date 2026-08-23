use std::fmt;
use std::fmt::Write as _;
use std::io::{Error, ErrorKind};

use tokio::io::{AsyncRead, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::protocol::structs::ClientHelloPayload;
use crate::reality::certificate::{
    certificate_der_has_ed25519_signature_tail, patch_reality_certificate_der_with_mode,
    select_reality_certificate_patch_mode, RealityCertificatePatchInput,
    RealityCertificatePatchMode,
};
use crate::reality::handshake::RealityObservedServerHello;
use crate::reality::mldsa65::Mldsa65Seed;
use crate::reality::post_handshake::{
    emit_post_handshake_camouflage_records, post_handshake_probe_key, resolve_ccs_tolerance,
    resolve_post_handshake_wire_lengths,
};
use crate::reality::stages::{self, stage_error, RealityAcceptedStage};
use crate::reality::target_server_flight::{
    ObservedEncryptedHandshakeSlot, ObservedTargetTls13ServerFlight,
};
use crate::reality::RealityAccepted;
use crate::tls::records::{build_change_cipher_spec_record, build_handshake_record};
use crate::tls::{TlsRecord, TLS_RECORD_ALERT, TLS_RECORD_HANDSHAKE};

use super::certificate::{
    build_tls13_certificate_message, build_tls13_certificate_verify_ed25519,
    generate_reality_ephemeral_ed25519_certificate_with_layout, RealityEphemeralCertificateLayout,
};
use super::cipher_suite::{resolve_tls13_cipher_suite, Tls13CipherSuite};
use super::key_schedule::{
    compute_finished_verify_data, derive_application_traffic_secrets, derive_finished_key,
    derive_handshake_traffic_secrets, derive_traffic_key, hash_len, verify_finished_data,
    Tls13ApplicationSecrets, Tls13HandshakeSecrets,
};
use super::key_share::{
    encode_key_share_extension_body, generate_server_key_share_for_observed_group,
    Tls13ServerKeyShare,
};
use super::messages::{
    build_encrypted_extensions_empty, build_finished, build_tls13_server_hello,
    Tls13ServerHelloParams, HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_SERVER_HELLO,
};
use super::record_crypto::{
    parse_tls13_handshake_inner_plaintext, tls13_inner_plaintext_body,
    tls13_inner_plaintext_content_type, Tls13RecordDecryptor, Tls13RecordEncryptor,
};
use super::stream::{read_client_finished_tls_record_from_stream, RealityTls13ApplicationStream};
use super::transcript::TranscriptHash;

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// REALITY accepted-path TLS 1.3 server handshake state container.
///
/// Upstream equivalent: Go `serverHandshakeStateTLS13` in XTLS/REALITY.
pub struct RealityTls13ServerState {
    pub accepted: RealityAccepted,
    pub observed_server_hello: RealityObservedServerHello,
    pub observed_server_flight: ObservedTargetTls13ServerFlight,
    pub suite: Tls13CipherSuite,
    pub transcript: TranscriptHash,
    pub server_key_share: Option<Tls13ServerKeyShare>,
    pub server_hello_message: Option<Vec<u8>>,
    pub handshake_secrets: Option<Tls13HandshakeSecrets>,
    pub server_finished_message: Option<Vec<u8>>,
    pub client_finished_verified: bool,
    pub application_secret_transcript_hash: Option<Vec<u8>>,
    pub application_secrets: Option<Tls13ApplicationSecrets>,
    /// Initial TLS 1.3 server application-data write sequence after the handshake flight.
    ///
    /// Incremented when a position-6 camouflage record is sent under the server application
    /// traffic secret (upstream REALITY switches write keys before this record).
    /// Fallback/probe destination (`realitySettings.dest`) for post-handshake cache lookup.
    pub post_handshake_dest_addr: String,
    pub server_application_write_sequence: u64,
}

struct ObservedServerHelloDebug<'a>(&'a RealityObservedServerHello);

impl fmt::Debug for ObservedServerHelloDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityObservedServerHello")
            .field(
                "cipher_suite",
                &format!("0x{:04x}", self.0.server_hello.cipher_suite),
            )
            .field("selected_key_share_group", &self.0.selected_key_share_group)
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
                "application_secret_transcript_hash",
                &self
                    .application_secret_transcript_hash
                    .as_ref()
                    .map(|hash| format!("<{} bytes>", hash.len())),
            )
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
        observed_server_flight: ObservedTargetTls13ServerFlight,
    ) -> std::io::Result<Self> {
        let suite = resolve_tls13_cipher_suite(observed_server_hello.server_hello.cipher_suite)?;
        let transcript = TranscriptHash::new(suite.hash);

        Ok(Self {
            accepted,
            observed_server_hello,
            observed_server_flight,
            suite,
            transcript,
            server_key_share: None,
            server_hello_message: None,
            handshake_secrets: None,
            server_finished_message: None,
            client_finished_verified: false,
            application_secret_transcript_hash: None,
            application_secrets: None,
            post_handshake_dest_addr: String::new(),
            server_application_write_sequence: 0,
        })
    }

    pub fn prepare_server_hello(
        &mut self,
        client_hello: &ClientHelloPayload,
    ) -> std::io::Result<&[u8]> {
        let selected_group = self.observed_server_hello.selected_key_share_group;
        let server_key_share =
            generate_server_key_share_for_observed_group(selected_group, client_hello)?;
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
            server_key_share.shared_secret(),
            transcript_hash,
        )?;
        self.handshake_secrets = Some(secrets);
        Ok(())
    }

    /// Builds encrypted EncryptedExtensions, Certificate, CertificateVerify, and Finished
    /// TLS records for the server.
    ///
    /// Transcript is updated with plaintext handshake messages, not encrypted records.
    pub fn build_encrypted_server_handshake_records(
        &mut self,
        certificate_patch_mode: RealityCertificatePatchMode<'_>,
    ) -> std::io::Result<Vec<u8>> {
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

        let encrypted_extensions = build_encrypted_extensions_empty()?;
        self.transcript.update(&encrypted_extensions);

        let certificate_layout = match &certificate_patch_mode {
            RealityCertificatePatchMode::HmacOnly => {
                RealityEphemeralCertificateLayout::LegacyHmacOnly
            }
            RealityCertificatePatchMode::HmacPlusMldsa65 { .. } => {
                RealityEphemeralCertificateLayout::Mldsa65ExtensionPlaceholder
            }
        };
        let ephemeral_cert = generate_reality_ephemeral_ed25519_certificate_with_layout(
            self.accepted.sni.as_deref(),
            certificate_layout,
        )?;
        let mut cert_der = ephemeral_cert.der.clone();
        if !certificate_der_has_ed25519_signature_tail(&cert_der) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "REALITY ephemeral certificate DER lacks Ed25519 signature tail layout",
            ));
        }
        patch_reality_certificate_der_with_mode(RealityCertificatePatchInput {
            cert_der: &mut cert_der,
            ed25519_public_key: &ephemeral_cert.public_key_raw,
            auth_key: &self.accepted.auth.auth_key,
            mode: certificate_patch_mode,
        })?;
        debug!(
            cert_der_len = cert_der.len(),
            cert_public_key_len = ephemeral_cert.public_key_raw.len(),
            "REALITY certificate signature patched"
        );
        let certificate = build_tls13_certificate_message(&[cert_der])?;
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

        let encrypted_extensions_record = self.encrypt_observed_handshake_record(
            &mut encryptor,
            &encrypted_extensions,
            ObservedEncryptedHandshakeSlot::EncryptedExtensions,
        )?;
        let certificate_record = self.encrypt_observed_handshake_record(
            &mut encryptor,
            &certificate,
            ObservedEncryptedHandshakeSlot::Certificate,
        )?;
        let certificate_verify_record = self.encrypt_observed_handshake_record(
            &mut encryptor,
            &certificate_verify,
            ObservedEncryptedHandshakeSlot::CertificateVerify,
        )?;
        let finished_record = self.encrypt_observed_handshake_record(
            &mut encryptor,
            &finished,
            ObservedEncryptedHandshakeSlot::Finished,
        )?;

        self.transcript.update(&finished);
        self.server_finished_message = Some(finished);

        let mut records = encrypted_extensions_record;
        records.extend_from_slice(&certificate_record);
        records.extend_from_slice(&certificate_verify_record);
        records.extend_from_slice(&finished_record);

        if let Some(position6_record) = self.build_position6_camouflage_record()? {
            records.extend_from_slice(&position6_record);
        }

        Ok(records)
    }

    /// Builds optional positional record #6 camouflage encrypted under the server application
    /// traffic secret (upstream REALITY `typeNewSessionTicket` writer trigger semantics).
    fn build_position6_camouflage_record(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let Some(desired_wire_len) = self
            .observed_server_flight
            .observed_position6_camouflage_wire_len()
        else {
            return Ok(None);
        };

        let handshake_secret = self
            .handshake_secrets
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "TLS 1.3 position-6 camouflage record requires derived handshake secrets",
                )
            })?
            .handshake_secret
            .clone();
        let transcript_hash = self.transcript.digest();
        let server_application_traffic_secret =
            derive_application_traffic_secrets(self.suite, &handshake_secret, &transcript_hash)?
                .server_application_traffic_secret;
        let traffic_keys = derive_traffic_key(self.suite, &server_application_traffic_secret)?;
        let mut encryptor = Tls13RecordEncryptor::new(self.suite, traffic_keys)?;
        let record = encryptor
            .encrypt_camouflage_position6_record_with_desired_wire_len(desired_wire_len)?;
        self.server_application_write_sequence = encryptor.sequence;
        Ok(Some(record))
    }

    fn encrypt_observed_handshake_record(
        &self,
        encryptor: &mut Tls13RecordEncryptor,
        handshake_message: &[u8],
        slot: ObservedEncryptedHandshakeSlot,
    ) -> std::io::Result<Vec<u8>> {
        let desired_wire_len = self
            .observed_server_flight
            .observed_wire_len_for_encrypted_handshake_slot(slot);
        encryptor
            .encrypt_handshake_message_with_desired_wire_len(handshake_message, desired_wire_len)
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
        let transcript_hash_before_client_finished = self.transcript.digest();
        let verified = verify_finished_data(
            self.suite,
            &finished_key,
            &transcript_hash_before_client_finished,
            &verify_data,
        )?;

        if verified {
            self.application_secret_transcript_hash = Some(transcript_hash_before_client_finished);
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

        let transcript_hash = self.application_secret_transcript_hash.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "TLS 1.3 application secret derivation requires transcript hash before client Finished",
            )
        })?;
        let secrets =
            derive_application_traffic_secrets(self.suite, &handshake_secret, transcript_hash)?;
        self.application_secrets = Some(secrets);
        Ok(())
    }
}

/// Assembles the cleartext server handshake flight: ServerHello, dummy CCS, encrypted records.
pub(crate) fn assemble_server_handshake_flight_out(
    server_hello_record: &[u8],
    encrypted_handshake_records: &[u8],
) -> Vec<u8> {
    let change_cipher_spec_record = build_change_cipher_spec_record();
    let mut out = Vec::with_capacity(
        server_hello_record.len()
            + change_cipher_spec_record.len()
            + encrypted_handshake_records.len(),
    );
    out.extend_from_slice(server_hello_record);
    out.extend_from_slice(&change_cipher_spec_record);
    out.extend_from_slice(encrypted_handshake_records);
    out
}

/// Completes the REALITY accepted-path TLS 1.3 handshake and returns an application stream.
///
/// Unsupported features return [`ErrorKind::Unsupported`] with a precise message. Accepted-path
/// callers must not fall back after entering this flow.
pub async fn complete_reality_tls13_handshake<S>(
    mut stream: S,
    client_hello_payload: &ClientHelloPayload,
    client_hello_message: &[u8],
    _client_hello_original: &[u8],
    _server_hello_original: &[u8],
    mldsa65_seed: Option<&Mldsa65Seed>,
    mut state: RealityTls13ServerState,
) -> std::io::Result<RealityTls13ApplicationStream<S>>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    state
        .prepare_server_hello(client_hello_payload)
        .map_err(|err| stage_error(RealityAcceptedStage::ServerHello, err))?;

    let server_hello_message = state.server_hello_message.as_ref().ok_or_else(|| {
        stage_error(
            RealityAcceptedStage::ServerHello,
            Error::new(
                ErrorKind::InvalidData,
                "ServerHello message missing after prepare",
            ),
        )
    })?;
    let server_hello_for_mldsa65 = server_hello_message.clone();
    let server_hello_record = build_handshake_record(server_hello_message)
        .map_err(|err| stage_error(RealityAcceptedStage::ServerHello, err))?;

    debug!(
        stage = stages::TLS13_SERVER_HELLO_GENERATED,
        sni = ?state.accepted.sni,
        cipher_suite = state.suite.name,
        server_hello_message_len = server_hello_message.len(),
        server_hello_record_len = server_hello_record.len(),
        "generated ServerHello"
    );

    let transcript_hash = state
        .update_transcript_client_server_hello(client_hello_message)
        .map_err(|err| stage_error(RealityAcceptedStage::Transcript, err))?;

    debug!(
        stage = stages::TLS13_TRANSCRIPT_CLIENT_SERVER_HELLO_UPDATED,
        cipher_suite = state.suite.name,
        transcript_hash_len = transcript_hash.len(),
        "updated ClientHello/ServerHello transcript"
    );

    state
        .derive_handshake_secrets(&transcript_hash)
        .map_err(|err| stage_error(RealityAcceptedStage::HandshakeSecrets, err))?;

    debug!(
        stage = stages::TLS13_HANDSHAKE_SECRETS_DERIVED,
        cipher_suite = state.suite.name,
        "derived handshake traffic secrets"
    );

    let certificate_patch_mode = select_reality_certificate_patch_mode(
        mldsa65_seed,
        client_hello_message,
        &server_hello_for_mldsa65,
    )
    .map_err(|err| stage_error(RealityAcceptedStage::ServerHandshakeRecords, err))?;

    let encrypted_handshake_records = state
        .build_encrypted_server_handshake_records(certificate_patch_mode)
        .map_err(|err| stage_error(RealityAcceptedStage::ServerHandshakeRecords, err))?;

    debug!(
        stage = stages::TLS13_SERVER_ENCRYPTED_HANDSHAKE_BUILT,
        cipher_suite = state.suite.name,
        encrypted_handshake_records_len = encrypted_handshake_records.len(),
        "built encrypted server handshake records"
    );

    let server_handshake_out =
        assemble_server_handshake_flight_out(&server_hello_record, &encrypted_handshake_records);
    stream
        .write_all(&server_handshake_out)
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::ServerHandshakeRecords, err))?;
    stream
        .flush()
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::ServerHandshakeRecords, err))?;

    debug!(
        stage = stages::TLS13_SERVER_ENCRYPTED_HANDSHAKE_SENT,
        encrypted_handshake_records_len = encrypted_handshake_records.len(),
        "sent encrypted server handshake records"
    );

    let probe_key = post_handshake_probe_key(
        state.post_handshake_dest_addr.as_str(),
        state.accepted.sni.as_deref().unwrap_or(""),
        client_hello_payload,
    );
    let useless_tolerance = resolve_ccs_tolerance(&probe_key).await;
    let client_finished_record =
        read_client_finished_tls_record_from_stream(&mut stream, useless_tolerance)
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::ClientFinishedRead, err))?;

    let client_handshake_traffic_secret = state
        .handshake_secrets
        .as_ref()
        .ok_or_else(|| {
            stage_error(
                RealityAcceptedStage::ClientFinishedRead,
                Error::new(
                    ErrorKind::InvalidInput,
                    "client Finished decrypt requires derived handshake secrets",
                ),
            )
        })?
        .client_handshake_traffic_secret
        .clone();
    let client_handshake_keys =
        derive_traffic_key(state.suite, &client_handshake_traffic_secret)
            .map_err(|err| stage_error(RealityAcceptedStage::ClientFinishedRead, err))?;
    let mut client_handshake_decryptor =
        Tls13RecordDecryptor::new(state.suite, client_handshake_keys)
            .map_err(|err| stage_error(RealityAcceptedStage::ClientFinishedRead, err))?;
    let client_finished_message = decrypt_client_finished_handshake_message(
        &mut client_handshake_decryptor,
        &client_finished_record,
    )
    .map_err(|err| stage_error(RealityAcceptedStage::ClientFinishedRead, err))?;

    debug!(
        stage = stages::TLS13_CLIENT_FINISHED_READ,
        client_finished_message_len = client_finished_message.len(),
        "decrypted client Finished handshake message"
    );

    let verified = state
        .verify_client_finished_message(&client_finished_message)
        .map_err(|err| stage_error(RealityAcceptedStage::ClientFinishedVerify, err))?;
    if !verified {
        return Err(stage_error(
            RealityAcceptedStage::ClientFinishedVerify,
            Error::new(
                ErrorKind::InvalidData,
                "client Finished verification failed",
            ),
        ));
    }

    debug!(
        stage = stages::TLS13_CLIENT_FINISHED_VERIFIED,
        cipher_suite = state.suite.name,
        "client Finished verified"
    );

    state
        .derive_application_secrets()
        .map_err(|err| stage_error(RealityAcceptedStage::ApplicationSecrets, err))?;

    debug!(
        stage = stages::TLS13_APPLICATION_SECRETS_DERIVED,
        cipher_suite = state.suite.name,
        "derived application traffic secrets"
    );

    let application_secrets = state.application_secrets.as_ref().ok_or_else(|| {
        stage_error(
            RealityAcceptedStage::ApplicationSecrets,
            Error::new(
                ErrorKind::InvalidData,
                "application secrets missing after derivation",
            ),
        )
    })?;

    let write_keys = derive_traffic_key(
        state.suite,
        &application_secrets.server_application_traffic_secret,
    )
    .map_err(|err| stage_error(RealityAcceptedStage::ApplicationStream, err))?;
    let mut write_encryptor = Tls13RecordEncryptor::with_traffic_secret(
        state.suite,
        write_keys,
        application_secrets
            .server_application_traffic_secret
            .clone(),
    )
    .map_err(|err| stage_error(RealityAcceptedStage::ApplicationStream, err))?;
    write_encryptor.sequence = state.server_application_write_sequence;

    if let Some(server_name) = state.accepted.sni.as_deref() {
        let dest_addr = state.post_handshake_dest_addr.as_str();
        let probe_key = post_handshake_probe_key(dest_addr, server_name, client_hello_payload);
        let cached_wire_lengths = resolve_post_handshake_wire_lengths(&probe_key).await;
        emit_post_handshake_camouflage_records(
            &mut stream,
            state.suite,
            &mut write_encryptor,
            &cached_wire_lengths,
        )
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::ApplicationStream, err))?;
        state.server_application_write_sequence = write_encryptor.sequence;
    }

    let read_keys = derive_traffic_key(
        state.suite,
        &application_secrets.client_application_traffic_secret,
    )
    .map_err(|err| stage_error(RealityAcceptedStage::ApplicationStream, err))?;

    let read_decryptor = Tls13RecordDecryptor::with_traffic_secret(
        state.suite,
        read_keys,
        application_secrets
            .client_application_traffic_secret
            .clone(),
    )
    .map_err(|err| stage_error(RealityAcceptedStage::ApplicationStream, err))?;

    info!(
        stage = stages::TLS13_APPLICATION_STREAM_READY,
        cipher_suite = state.suite.name,
        sni = ?state.accepted.sni,
        "application stream ready"
    );

    Ok(RealityTls13ApplicationStream::new_with_tolerance(
        stream,
        read_decryptor,
        write_encryptor,
        useless_tolerance,
    ))
}

fn debug_tls13_plaintext_enabled() -> bool {
    std::env::var("RUST_XRAY_DEBUG_TLS13_PLAINTEXT")
        .as_deref()
        .ok()
        .is_some_and(|value| value == "1")
}

fn hex_encode_diagnostics(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn decrypt_client_finished_handshake_message(
    decryptor: &mut Tls13RecordDecryptor,
    record: &TlsRecord,
) -> std::io::Result<Vec<u8>> {
    let encrypted_record_len = record.raw.len();
    let sequence = decryptor.sequence;

    let inner_plaintext = decryptor
        .decrypt_record_payload(record)
        .map_err(|err| client_finished_decrypt_error(encrypted_record_len, sequence, err))?;

    if tls13_inner_plaintext_content_type(&inner_plaintext) == Some(TLS_RECORD_ALERT) {
        let alert_bytes = tls13_inner_plaintext_body(&inner_plaintext).unwrap_or_default();
        warn!(
            stage = stages::TLS13_CLIENT_FINISHED_READ,
            inner_content_type = TLS_RECORD_ALERT,
            alert_bytes_hex = hex_encode_diagnostics(&alert_bytes),
            encrypted_record_len = encrypted_record_len,
            sequence = sequence,
            "decrypted client Finished candidate contains TLS alert"
        );
        return Err(Error::new(
            ErrorKind::InvalidData,
            "client Finished candidate contains encrypted TLS alert",
        ));
    }

    let handshake_message = parse_tls13_handshake_inner_plaintext(&inner_plaintext)
        .map_err(|err| client_finished_decrypt_error(encrypted_record_len, sequence, err))?;

    if handshake_message.first() != Some(&HANDSHAKE_TYPE_FINISHED) {
        warn!(
            stage = stages::TLS13_CLIENT_FINISHED_READ,
            inner_content_type = tls13_inner_plaintext_content_type(&inner_plaintext)
                .unwrap_or(TLS_RECORD_HANDSHAKE),
            handshake_type = handshake_message.first().copied(),
            encrypted_record_len = encrypted_record_len,
            sequence = sequence,
            "decrypted client Finished candidate is not Finished handshake type"
        );
        if debug_tls13_plaintext_enabled() {
            debug!(
                stage = stages::TLS13_CLIENT_FINISHED_READ,
                decrypted_bytes_hex = hex_encode_diagnostics(&handshake_message),
                "decrypted client Finished candidate plaintext"
            );
        }
    }

    Ok(handshake_message)
}

fn client_finished_decrypt_error(encrypted_record_len: usize, sequence: u64, err: Error) -> Error {
    Error::new(
        err.kind(),
        format!(
            "client Finished decrypt failed (encrypted_record_len={encrypted_record_len}, sequence={sequence}): {err}"
        ),
    )
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
#[path = "../../../tests/unit/reality/tls13/state.rs"]
mod tests;
