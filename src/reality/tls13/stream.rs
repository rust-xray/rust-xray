//! TLS 1.3 application-data stream adapter skeleton for the REALITY accepted path.
//!
//! This wraps an underlying byte stream, decrypting client ApplicationData records into
//! plaintext reads and encrypting plaintext writes into server ApplicationData records.
//!
//! # Limitations
//!
//! - One TLS record per [`AsyncWrite::poll_write`] call; no coalescing or partial-plaintext
//!   write buffering beyond the encrypted record write buffer.
//! - Reads at least one full TLS record before returning decrypted plaintext.
//! - Handles encrypted TLS alerts on the application stream (close_notify, fatal).
//! - Wired into VLESS via `handle_vless_tcp_inbound` on the REALITY accepted path.

use std::fmt::Write as _;
use std::io::{self, Error, ErrorKind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{
    split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf,
};
use tracing::{debug, info, warn};

use crate::reality::stages;
use crate::tls::records::{
    TLS_RECORD_ALERT, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC,
    TLS_RECORD_HANDSHAKE,
};
use crate::tls::{TlsRecord, TlsRecordContentType};

use super::messages::{
    parse_key_update_handshake, HANDSHAKE_TYPE_KEY_UPDATE, KEY_UPDATE_REQUESTED,
};
use super::record_crypto::{
    tls13_inner_plaintext_metadata, tls13_inner_plaintext_parts, tls13_record_aad_bytes,
    tls13_record_nonce_hex, Tls13RecordDecryptor, Tls13RecordEncryptor,
};

const TLS_RECORD_HEADER_LEN: usize = 5;
const MAX_DUMMY_CHANGE_CIPHER_SPEC_BEFORE_CLIENT_FINISHED: usize = 4;
const TLS13_DUMMY_CHANGE_CIPHER_SPEC_PAYLOAD: [u8; 1] = [0x01];
const MAX_DEBUG_VLESS_PLAINTEXT_BYTES: usize = 64;
const MAX_DEBUG_TLS_RECORD_PREFIX_BYTES: usize = 32;
const TLS13_AEAD_TAG_LEN: usize = 16;
const TLS13_APPLICATION_STREAM_DIRECTION: &str = "client_to_server";
const TLS13_APPLICATION_STREAM_WRITE_DIRECTION: &str = "server_to_client";
const TLS_ALERT_LEVEL_WARNING: u8 = 1;
const TLS_ALERT_LEVEL_FATAL: u8 = 2;
const TLS_ALERT_CLOSE_NOTIFY: u8 = 0;

#[derive(Debug)]
enum ApplicationStreamRecord {
    Plaintext(Vec<u8>),
    PeerClosed,
    PostHandshakeConsumed,
}

fn debug_vless_plaintext_enabled() -> bool {
    std::env::var("RUST_XRAY_DEBUG_VLESS_PLAINTEXT")
        .as_deref()
        .ok()
        .is_some_and(|value| value == "1")
}

fn vless_plaintext_debug_preview(plaintext: &[u8]) -> (String, usize) {
    let preview_len = plaintext.len().min(MAX_DEBUG_VLESS_PLAINTEXT_BYTES);
    (hex_encode(&plaintext[..preview_len]), preview_len)
}

fn debug_tls_record_prefix_enabled() -> bool {
    std::env::var("RUST_XRAY_DEBUG_TLS_RECORD_PREFIX")
        .as_deref()
        .ok()
        .is_some_and(|value| value == "1")
}

fn legacy_version_hex(version: [u8; 2]) -> String {
    format!("{:02x}{:02x}", version[0], version[1])
}

fn tls_record_header_hex(raw: &[u8]) -> String {
    hex_encode(&raw[..TLS_RECORD_HEADER_LEN.min(raw.len())])
}

fn encrypted_payload_prefix_hex(payload: &[u8]) -> String {
    let preview_len = payload.len().min(MAX_DEBUG_TLS_RECORD_PREFIX_BYTES);
    hex_encode(&payload[..preview_len])
}

fn encrypted_payload_suffix_hex(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let suffix_len = payload.len().min(MAX_DEBUG_TLS_RECORD_PREFIX_BYTES);
    hex_encode(&payload[payload.len() - suffix_len..])
}

fn plaintext_prefix_hex(plaintext: &[u8]) -> String {
    let preview_len = plaintext.len().min(MAX_DEBUG_TLS_RECORD_PREFIX_BYTES);
    hex_encode(&plaintext[..preview_len])
}

fn tls_record_payload_len(record: &[u8]) -> usize {
    record.len().checked_sub(TLS_RECORD_HEADER_LEN).unwrap_or(0)
}

fn log_application_stream_encrypt_start(
    encrypt_sequence: u64,
    plaintext_len: usize,
    cipher_suite: &str,
    plaintext: &[u8],
) {
    if debug_tls_record_prefix_enabled() {
        info!(
            stage = stages::TLS13_APPLICATION_STREAM_ENCRYPT,
            direction = TLS13_APPLICATION_STREAM_WRITE_DIRECTION,
            encrypt_sequence,
            plaintext_len,
            cipher_suite,
            plaintext_prefix_hex = plaintext_prefix_hex(plaintext),
            debug_tls_record_prefix_enabled = true,
            "encrypt TLS application-stream record"
        );
    } else {
        info!(
            stage = stages::TLS13_APPLICATION_STREAM_ENCRYPT,
            direction = TLS13_APPLICATION_STREAM_WRITE_DIRECTION,
            encrypt_sequence,
            plaintext_len,
            cipher_suite,
            "encrypt TLS application-stream record"
        );
    }
}

fn log_application_stream_encrypt_complete(record: &[u8]) {
    let encrypted_record_payload_len = tls_record_payload_len(record);
    let record_total_len = record.len();

    if debug_tls_record_prefix_enabled() {
        info!(
            stage = stages::TLS13_APPLICATION_STREAM_ENCRYPT,
            direction = TLS13_APPLICATION_STREAM_WRITE_DIRECTION,
            encrypted_record_payload_len,
            record_total_len,
            record_header_hex = tls_record_header_hex(record),
            debug_tls_record_prefix_enabled = true,
            "encrypted TLS application-stream record"
        );
    } else {
        info!(
            stage = stages::TLS13_APPLICATION_STREAM_ENCRYPT,
            direction = TLS13_APPLICATION_STREAM_WRITE_DIRECTION,
            encrypted_record_payload_len,
            record_total_len,
            "encrypted TLS application-stream record"
        );
    }
}

fn log_application_stream_writer_flush() {
    info!(
        stage = stages::TLS13_APPLICATION_STREAM_FLUSH,
        direction = TLS13_APPLICATION_STREAM_WRITE_DIRECTION,
        "flush TLS application-stream writer"
    );
}

fn log_application_stream_writer_shutdown(
    pending_ciphertext_len: usize,
    transport_shutdown_called: bool,
) {
    info!(
        stage = stages::TLS13_APPLICATION_STREAM_SHUTDOWN,
        direction = TLS13_APPLICATION_STREAM_WRITE_DIRECTION,
        pending_ciphertext_len,
        transport_shutdown_called,
        "TLS application-stream writer shutdown"
    );
}

fn tls_inner_content_type_name(content_type: u8) -> &'static str {
    match content_type {
        TLS_RECORD_CHANGE_CIPHER_SPEC => "change_cipher_spec",
        TLS_RECORD_ALERT => "alert",
        TLS_RECORD_HANDSHAKE => "handshake",
        TLS_RECORD_APPLICATION_DATA => "application_data",
        other => {
            if other == 0 {
                "invalid_zero"
            } else {
                "unknown"
            }
        }
    }
}

fn log_application_stream_decrypt_attempt(
    meta: &ApplicationStreamRecordMeta,
    cipher_suite: &str,
    decryptor: &Tls13RecordDecryptor,
    record: &TlsRecord,
) {
    let payload_len = u16::try_from(record.payload.len()).unwrap_or(u16::MAX);
    let aad = tls13_record_aad_bytes(record.legacy_version, payload_len);
    let aad_hex = hex_encode(&aad);

    if debug_tls_record_prefix_enabled() {
        let nonce_hex = tls13_record_nonce_hex(&decryptor.keys.iv, decryptor.sequence)
            .unwrap_or_else(|_| "invalid".to_string());
        info!(
            stage = stages::TLS13_APPLICATION_STREAM_DECRYPT,
            direction = TLS13_APPLICATION_STREAM_DIRECTION,
            decrypt_sequence_before = meta.decrypt_sequence,
            record_header_hex = tls_record_header_hex(&record.raw),
            aad_hex,
            nonce_hex,
            legacy_version_hex = meta.legacy_version_hex(),
            record_payload_len = meta.record_payload_len,
            record_total_len = meta.record_total_len,
            cipher_suite,
            debug_tls_record_prefix_enabled = true,
            "attempting client application-data TLS record decrypt"
        );
    } else {
        info!(
            stage = stages::TLS13_APPLICATION_STREAM_DECRYPT,
            direction = TLS13_APPLICATION_STREAM_DIRECTION,
            decrypt_sequence_before = meta.decrypt_sequence,
            aad_hex,
            legacy_version_hex = meta.legacy_version_hex(),
            record_payload_len = meta.record_payload_len,
            record_total_len = meta.record_total_len,
            cipher_suite,
            "attempting client application-data TLS record decrypt"
        );
    }
}

fn log_application_stream_inner_plaintext(
    decrypt_sequence: u64,
    read_sequence_after: u64,
    inner_plaintext: &[u8],
    cipher_suite: &str,
) {
    let (body, content_type, padding_len) = match tls13_inner_plaintext_metadata(inner_plaintext) {
        Ok(metadata) => metadata,
        Err(err) => {
            warn!(
                stage = stages::TLS13_APPLICATION_STREAM_DECRYPT,
                direction = TLS13_APPLICATION_STREAM_DIRECTION,
                decrypt_sequence,
                read_sequence_after,
                inner_plaintext_len = inner_plaintext.len(),
                cipher_suite,
                error = %err,
                "failed to parse TLSInnerPlaintext after AEAD decrypt"
            );
            return;
        }
    };

    info!(
        stage = stages::TLS13_APPLICATION_STREAM_DECRYPT,
        direction = TLS13_APPLICATION_STREAM_DIRECTION,
        decrypt_sequence,
        read_sequence_after,
        inner_plaintext_len = inner_plaintext.len(),
        inner_content_type = tls_inner_content_type_name(content_type),
        inner_content_type_byte = content_type,
        inner_content_len = body.len(),
        inner_padding_len = padding_len,
        cipher_suite,
        "parsed TLSInnerPlaintext after AEAD decrypt"
    );
}

struct ApplicationStreamRecordMeta {
    decrypt_sequence: u64,
    content_type: TlsRecordContentType,
    content_type_name: String,
    legacy_version: [u8; 2],
    record_payload_len: usize,
    record_total_len: usize,
}

impl ApplicationStreamRecordMeta {
    fn from_record(record: &TlsRecord, decrypt_sequence: u64) -> Self {
        Self {
            decrypt_sequence,
            content_type: record.content_type,
            content_type_name: tls_record_content_type_name(record.content_type),
            legacy_version: record.legacy_version,
            record_payload_len: record.payload.len(),
            record_total_len: record.raw.len(),
        }
    }

    fn legacy_version_hex(&self) -> String {
        legacy_version_hex(self.legacy_version)
    }

    fn content_type_byte(&self) -> u8 {
        match self.content_type {
            TlsRecordContentType::ChangeCipherSpec => TLS_RECORD_CHANGE_CIPHER_SPEC,
            TlsRecordContentType::Alert => TLS_RECORD_ALERT,
            TlsRecordContentType::Handshake => TLS_RECORD_HANDSHAKE,
            TlsRecordContentType::ApplicationData => TLS_RECORD_APPLICATION_DATA,
            TlsRecordContentType::Unknown(byte) => byte,
        }
    }
}

fn log_application_stream_record(meta: &ApplicationStreamRecordMeta) {
    info!(
        stage = stages::TLS13_APPLICATION_STREAM_RECORD,
        direction = TLS13_APPLICATION_STREAM_DIRECTION,
        decrypt_sequence = meta.decrypt_sequence,
        record_content_type = %meta.content_type_name,
        record_content_type_byte = meta.content_type_byte(),
        legacy_version_hex = meta.legacy_version_hex(),
        record_payload_len = meta.record_payload_len,
        record_total_len = meta.record_total_len,
        "read client TLS application-stream record"
    );
}

fn log_application_stream_record_decrypt_failure(
    record: &TlsRecord,
    meta: &ApplicationStreamRecordMeta,
) {
    if !debug_tls_record_prefix_enabled() {
        return;
    }

    info!(
        stage = stages::TLS13_APPLICATION_STREAM_RECORD,
        direction = TLS13_APPLICATION_STREAM_DIRECTION,
        decrypt_sequence = meta.decrypt_sequence,
        record_content_type = %meta.content_type_name,
        legacy_version_hex = meta.legacy_version_hex(),
        record_payload_len = meta.record_payload_len,
        record_total_len = meta.record_total_len,
        record_header_hex = tls_record_header_hex(&record.raw),
        encrypted_payload_prefix_hex = encrypted_payload_prefix_hex(&record.payload),
        encrypted_payload_suffix_hex = encrypted_payload_suffix_hex(&record.payload),
        debug_tls_record_prefix_enabled = true,
        "TLS application-stream record decrypt failed"
    );
}

fn validate_client_application_record(record: &TlsRecord) -> io::Result<()> {
    if record.content_type != TlsRecordContentType::ApplicationData {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "TLS application stream requires ApplicationData outer record, got {}",
                tls_record_content_type_name(record.content_type),
            ),
        ));
    }

    if record.payload.len() < TLS13_AEAD_TAG_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS application record too short for AEAD tag",
        ));
    }

    Ok(())
}

fn application_stream_record_error(
    err: Error,
    meta: &ApplicationStreamRecordMeta,
    cipher_suite: &str,
) -> Error {
    Error::new(
        err.kind(),
        format!(
            "{} (stage={}, direction={}, decrypt_sequence={}, record_content_type={}, legacy_version_hex={}, record_payload_len={}, record_total_len={}, cipher_suite={})",
            err,
            stages::TLS13_APPLICATION_STREAM_DECRYPT,
            TLS13_APPLICATION_STREAM_DIRECTION,
            meta.decrypt_sequence,
            meta.content_type_name,
            meta.legacy_version_hex(),
            meta.record_payload_len,
            meta.record_total_len,
            cipher_suite,
        ),
    )
}

fn application_stream_decrypt_error(
    err: Error,
    meta: &ApplicationStreamRecordMeta,
    cipher_suite: &str,
) -> Error {
    application_stream_record_error(err, meta, cipher_suite)
}

fn handle_application_stream_inner_plaintext(
    read_decryptor: &mut Tls13RecordDecryptor,
    inner_plaintext: &[u8],
    decrypt_sequence: u64,
    server_key_update_requested: &AtomicBool,
) -> io::Result<ApplicationStreamRecord> {
    let (body, content_type) = tls13_inner_plaintext_parts(inner_plaintext)?;

    match content_type {
        TLS_RECORD_APPLICATION_DATA => Ok(ApplicationStreamRecord::Plaintext(body)),
        TLS_RECORD_ALERT => parse_application_stream_tls_alert(&body, decrypt_sequence),
        TLS_RECORD_HANDSHAKE => handle_application_stream_post_handshake(
            read_decryptor,
            &body,
            decrypt_sequence,
            server_key_update_requested,
        ),
        other => Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS 1.3 unexpected inner content type: {other}"),
        )),
    }
}

fn handle_application_stream_post_handshake(
    read_decryptor: &mut Tls13RecordDecryptor,
    handshake_message: &[u8],
    decrypt_sequence: u64,
    server_key_update_requested: &AtomicBool,
) -> io::Result<ApplicationStreamRecord> {
    match handshake_message.first().copied() {
        Some(HANDSHAKE_TYPE_KEY_UPDATE) => {
            let request_update = parse_key_update_handshake(handshake_message).map_err(|err| {
                Error::new(err.kind(), format!("TLS 1.3 KeyUpdate parse failed: {err}"))
            })?;

            info!(
                stage = stages::TLS13_APPLICATION_STREAM_KEY_UPDATE,
                direction = TLS13_APPLICATION_STREAM_DIRECTION,
                decrypt_sequence,
                request_update,
                "received TLS 1.3 KeyUpdate on application stream"
            );

            read_decryptor.apply_receiving_traffic_key_update()?;

            if request_update == KEY_UPDATE_REQUESTED {
                server_key_update_requested.store(true, Ordering::SeqCst);
            }

            Ok(ApplicationStreamRecord::PostHandshakeConsumed)
        }
        Some(handshake_type) => Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS 1.3 unsupported post-handshake message type: 0x{handshake_type:02x}"),
        )),
        None => Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 post-handshake message is empty",
        )),
    }
}

fn parse_application_stream_tls_alert(
    alert_bytes: &[u8],
    decrypt_sequence: u64,
) -> io::Result<ApplicationStreamRecord> {
    if alert_bytes.len() < 2 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS alert inner plaintext too short",
        ));
    }

    let alert_level = alert_bytes[0];
    let alert_description = alert_bytes[1];

    info!(
        stage = stages::TLS13_APPLICATION_STREAM_ALERT,
        alert_level, alert_description, decrypt_sequence, "received TLS application-stream alert"
    );

    match alert_level {
        TLS_ALERT_LEVEL_WARNING => {
            debug!(
                stage = stages::TLS13_APPLICATION_STREAM_ALERT,
                alert_level,
                alert_description,
                decrypt_sequence,
                close_notify = alert_description == TLS_ALERT_CLOSE_NOTIFY,
                "TLS warning alert on application stream"
            );
            Ok(ApplicationStreamRecord::PeerClosed)
        }
        TLS_ALERT_LEVEL_FATAL => Err(Error::new(
            ErrorKind::ConnectionAborted,
            format!("TLS alert received: level=fatal description={alert_description}"),
        )),
        level => Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS alert received: unknown level={level} description={alert_description}"),
        )),
    }
}

fn parse_tls_record_content_type(byte: u8) -> TlsRecordContentType {
    match byte {
        20 => TlsRecordContentType::ChangeCipherSpec,
        21 => TlsRecordContentType::Alert,
        22 => TlsRecordContentType::Handshake,
        23 => TlsRecordContentType::ApplicationData,
        other => TlsRecordContentType::Unknown(other),
    }
}

/// Reads one complete TLS record from an async byte stream.
pub(crate) async fn read_tls_record_from_stream<S>(stream: &mut S) -> io::Result<TlsRecord>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    stream.read_exact(&mut header).await?;

    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    let mut raw = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&payload);

    Ok(TlsRecord {
        content_type: parse_tls_record_content_type(header[0]),
        legacy_version: [header[1], header[2]],
        payload,
        raw,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn tls_record_content_type_name(content_type: TlsRecordContentType) -> String {
    match content_type {
        TlsRecordContentType::ChangeCipherSpec => "ChangeCipherSpec".to_string(),
        TlsRecordContentType::Alert => "Alert".to_string(),
        TlsRecordContentType::Handshake => "Handshake".to_string(),
        TlsRecordContentType::ApplicationData => "ApplicationData".to_string(),
        TlsRecordContentType::Unknown(byte) => format!("Unknown(0x{byte:02x})"),
    }
}

fn client_finished_read_error(kind: ErrorKind, message: impl Into<String>) -> Error {
    Error::new(
        kind,
        format!("{}: {}", stages::TLS13_CLIENT_FINISHED_READ, message.into()),
    )
}

/// Reads the encrypted client Finished record, skipping TLS 1.3 dummy ChangeCipherSpec records.
///
/// Dummy CCS records are not part of the TLS 1.3 transcript and must not affect handshake secrets.
pub(crate) async fn read_client_finished_tls_record_from_stream<S>(
    stream: &mut S,
) -> io::Result<TlsRecord>
where
    S: AsyncRead + Unpin,
{
    let mut skipped_ccs = 0usize;

    loop {
        let record = read_tls_record_from_stream(stream).await.map_err(|err| {
            if err.kind() == ErrorKind::UnexpectedEof {
                client_finished_read_error(
                    ErrorKind::UnexpectedEof,
                    format!("client closed connection before client Finished ({err})"),
                )
            } else {
                err
            }
        })?;

        match record.content_type {
            TlsRecordContentType::ChangeCipherSpec => {
                if record.payload != TLS13_DUMMY_CHANGE_CIPHER_SPEC_PAYLOAD {
                    return Err(client_finished_read_error(
                        ErrorKind::InvalidData,
                        "invalid ChangeCipherSpec payload before client Finished",
                    ));
                }

                skipped_ccs += 1;
                if skipped_ccs > MAX_DUMMY_CHANGE_CIPHER_SPEC_BEFORE_CLIENT_FINISHED {
                    return Err(client_finished_read_error(
                        ErrorKind::InvalidData,
                        "too many ChangeCipherSpec records before client Finished",
                    ));
                }

                debug!(
                    stage = stages::TLS13_CLIENT_FINISHED_READ,
                    skipped_ccs_count = skipped_ccs,
                    record_len = record.raw.len(),
                    "skipping TLS 1.3 dummy ChangeCipherSpec"
                );
            }
            TlsRecordContentType::ApplicationData => {
                info!(
                    stage = stages::TLS13_CLIENT_FINISHED_READ,
                    skipped_ccs_count = skipped_ccs,
                    encrypted_record_len = record.raw.len(),
                    "read encrypted client Finished TLS record"
                );
                return Ok(record);
            }
            TlsRecordContentType::Alert => {
                info!(
                    stage = stages::TLS13_CLIENT_FINISHED_READ,
                    skipped_ccs_count = skipped_ccs,
                    alert_record_len = record.raw.len(),
                    alert_bytes_hex = hex_encode(&record.payload),
                    "client sent TLS alert before Finished"
                );
                return Err(client_finished_read_error(
                    ErrorKind::InvalidData,
                    format!(
                        "client sent TLS alert before Finished: {}",
                        hex_encode(&record.payload)
                    ),
                ));
            }
            other => {
                return Err(client_finished_read_error(
                    ErrorKind::InvalidData,
                    format!(
                        "unexpected TLS record before client Finished: {}",
                        tls_record_content_type_name(other)
                    ),
                ));
            }
        }
    }
}

struct ApplicationStreamRelaySplitGuard(Arc<AtomicBool>);

impl ApplicationStreamRelaySplitGuard {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn mark_split(&self) -> io::Result<()> {
        if self.0.swap(true, Ordering::SeqCst) {
            warn!(
                stage = stages::TLS13_APPLICATION_STREAM_SPLIT,
                "TLS application stream relay split called more than once"
            );
            return Err(io::Error::new(
                ErrorKind::Other,
                "TLS application stream relay split called more than once",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn split_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.0)
    }
}

/// Shared flags for Vision DIRECT / raw relay on the underlying REALITY transport.
#[derive(Debug, Clone)]
pub struct ApplicationStreamDirectRelay {
    reader_direct: Arc<AtomicBool>,
    writer_direct: Arc<AtomicBool>,
}

impl ApplicationStreamDirectRelay {
    fn new_shared() -> (Arc<AtomicBool>, Arc<AtomicBool>) {
        (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn from_shared(reader_direct: Arc<AtomicBool>, writer_direct: Arc<AtomicBool>) -> Self {
        Self {
            reader_direct,
            writer_direct,
        }
    }

    pub fn is_reader_enabled(&self) -> bool {
        self.reader_direct.load(Ordering::SeqCst)
    }

    pub fn is_writer_enabled(&self) -> bool {
        self.writer_direct.load(Ordering::SeqCst)
    }

    pub fn is_enabled(&self) -> bool {
        self.is_reader_enabled() || self.is_writer_enabled()
    }

    pub fn enable_reader(&self) {
        if self.reader_direct.swap(true, Ordering::SeqCst) {
            return;
        }
        info!("switching REALITY application stream to raw direct relay");
    }

    pub fn enable_writer(&self) {
        if self.writer_direct.swap(true, Ordering::SeqCst) {
            return;
        }
        info!("switching REALITY application stream writer to raw direct relay");
    }
}

/// Reader/writer halves plus shared direct-relay control for Vision DIRECT.
pub struct RealityTls13RelaySplit<S> {
    pub reader: RealityTls13ClientReader<ReadHalf<S>>,
    pub writer: RealityTls13ClientWriter<WriteHalf<S>>,
    pub direct_relay: ApplicationStreamDirectRelay,
}

struct Tls13ClientReadState {
    read_decryptor: Tls13RecordDecryptor,
    plaintext_read_buf: BytesMut,
    ciphertext_read_buf: BytesMut,
    read_eof: bool,
    server_key_update_requested: Arc<AtomicBool>,
}

impl Tls13ClientReadState {
    fn new(
        read_decryptor: Tls13RecordDecryptor,
        server_key_update_requested: Arc<AtomicBool>,
    ) -> Self {
        Self {
            read_decryptor,
            plaintext_read_buf: BytesMut::new(),
            ciphertext_read_buf: BytesMut::new(),
            read_eof: false,
            server_key_update_requested,
        }
    }

    fn decrypt_sequence(&self) -> u64 {
        self.read_decryptor.sequence
    }

    async fn read_tls_record<S>(&mut self, inner: &mut S) -> io::Result<TlsRecord>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            if let Some(record) = try_take_tls_record(&mut self.ciphertext_read_buf)? {
                return Ok(record);
            }

            let mut chunk = [0u8; 4096];
            let read = inner.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS 1.3 application stream closed before a complete record",
                ));
            }
            self.ciphertext_read_buf.extend_from_slice(&chunk[..read]);
        }
    }

    fn fill_plaintext_read_buf<S>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            if !self.plaintext_read_buf.is_empty() {
                return Poll::Ready(Ok(()));
            }

            if self.read_eof {
                return Poll::Ready(Ok(()));
            }

            let record =
                match poll_read_tls_record(Pin::new(inner), &mut self.ciphertext_read_buf, cx)? {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(record) => record,
                };

            match self.decrypt_application_stream_record(&record)? {
                ApplicationStreamRecord::Plaintext(plaintext) => {
                    self.plaintext_read_buf.extend_from_slice(&plaintext);
                    return Poll::Ready(Ok(()));
                }
                ApplicationStreamRecord::PeerClosed => {
                    self.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                ApplicationStreamRecord::PostHandshakeConsumed => {}
            }
        }
    }

    fn decrypt_application_stream_record(
        &mut self,
        record: &TlsRecord,
    ) -> io::Result<ApplicationStreamRecord> {
        let meta = ApplicationStreamRecordMeta::from_record(record, self.read_decryptor.sequence);
        let cipher_suite = self.read_decryptor.suite.name;

        log_application_stream_record(&meta);

        if let Err(err) = validate_client_application_record(record) {
            return Err(application_stream_record_error(err, &meta, cipher_suite));
        }

        info!(
            stage = stages::TLS13_APPLICATION_STREAM_DECRYPT,
            direction = TLS13_APPLICATION_STREAM_DIRECTION,
            tls_record_content_type = %meta.content_type_name,
            legacy_version_hex = meta.legacy_version_hex(),
            record_payload_len = meta.record_payload_len,
            record_total_len = meta.record_total_len,
            decrypt_sequence_before = meta.decrypt_sequence,
            cipher_suite,
            "decrypting client application-data TLS record"
        );

        log_application_stream_decrypt_attempt(&meta, cipher_suite, &self.read_decryptor, record);

        let inner_plaintext =
            self.read_decryptor
                .decrypt_record_payload(record)
                .map_err(|err| {
                    log_application_stream_record_decrypt_failure(record, &meta);
                    application_stream_decrypt_error(err, &meta, cipher_suite)
                })?;

        let read_sequence_after = self.read_decryptor.sequence;
        log_application_stream_inner_plaintext(
            meta.decrypt_sequence,
            read_sequence_after,
            &inner_plaintext,
            cipher_suite,
        );

        let result = handle_application_stream_inner_plaintext(
            &mut self.read_decryptor,
            &inner_plaintext,
            meta.decrypt_sequence,
            &self.server_key_update_requested,
        )
        .map_err(|err| application_stream_decrypt_error(err, &meta, cipher_suite))?;

        if let ApplicationStreamRecord::Plaintext(plaintext) = &result {
            info!(
                stage = stages::TLS13_APPLICATION_STREAM_DECRYPT,
                direction = TLS13_APPLICATION_STREAM_DIRECTION,
                decrypt_sequence = meta.decrypt_sequence,
                record_payload_len = meta.record_payload_len,
                record_total_len = meta.record_total_len,
                decrypted_plaintext_len = plaintext.len(),
                cipher_suite,
                "decrypted client application-data TLS record"
            );
            if debug_vless_plaintext_enabled() {
                let (preview_hex, preview_len) = vless_plaintext_debug_preview(plaintext);
                info!(
                    stage = stages::TLS13_APPLICATION_STREAM_DECRYPT,
                    debug_plaintext_enabled = true,
                    decrypt_sequence = meta.decrypt_sequence,
                    decrypted_plaintext_preview_hex = preview_hex,
                    decrypted_plaintext_preview_len = preview_len,
                    "debug plaintext enabled"
                );
            }
        }

        Ok(result)
    }
}

struct Tls13ClientWriteState {
    write_encryptor: Tls13RecordEncryptor,
    ciphertext_write_buf: BytesMut,
    pending_write_plaintext_len: Option<usize>,
    server_key_update_requested: Arc<AtomicBool>,
}

impl Tls13ClientWriteState {
    fn new(
        write_encryptor: Tls13RecordEncryptor,
        server_key_update_requested: Arc<AtomicBool>,
    ) -> Self {
        Self {
            write_encryptor,
            ciphertext_write_buf: BytesMut::new(),
            pending_write_plaintext_len: None,
            server_key_update_requested,
        }
    }

    fn encrypt_sequence(&self) -> u64 {
        self.write_encryptor.sequence
    }

    fn poll_write_encrypted_record<S>(
        &mut self,
        mut inner: Pin<&mut S>,
        cx: &mut Context<'_>,
        plaintext_len: usize,
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin,
    {
        while !self.ciphertext_write_buf.is_empty() {
            match inner.as_mut().poll_write(cx, &self.ciphertext_write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS 1.3 application stream write returned zero",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    let _ = self.ciphertext_write_buf.split_to(written);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        self.pending_write_plaintext_len = None;
        Poll::Ready(Ok(plaintext_len))
    }

    fn poll_flush_pending_ciphertext<S>(
        &mut self,
        mut inner: Pin<&mut S>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while !self.ciphertext_write_buf.is_empty() {
            match inner.as_mut().poll_write(cx, &self.ciphertext_write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS 1.3 application stream write returned zero",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    let _ = self.ciphertext_write_buf.split_to(written);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        self.pending_write_plaintext_len = None;
        Poll::Ready(Ok(()))
    }

    fn poll_write<S>(
        &mut self,
        inner: Pin<&mut S>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin,
    {
        if !self.ciphertext_write_buf.is_empty() {
            let pending = self
                .pending_write_plaintext_len
                .expect("pending plaintext length while encrypted write buffer is non-empty");
            return self.poll_write_encrypted_record(inner, cx, pending);
        }

        if self
            .server_key_update_requested
            .swap(false, Ordering::SeqCst)
        {
            match self.write_encryptor.encrypt_server_key_update_response() {
                Ok(record) => {
                    self.ciphertext_write_buf.extend_from_slice(&record);
                    self.pending_write_plaintext_len = Some(0);
                    return self.poll_write_encrypted_record(inner, cx, 0);
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let encrypt_sequence = self.write_encryptor.sequence;
        let cipher_suite = self.write_encryptor.suite.name;
        log_application_stream_encrypt_start(encrypt_sequence, buf.len(), cipher_suite, buf);

        match self.write_encryptor.encrypt_application_data(buf) {
            Ok(record) => {
                log_application_stream_encrypt_complete(&record);
                self.ciphertext_write_buf.extend_from_slice(&record);
                self.pending_write_plaintext_len = Some(buf.len());
                self.poll_write_encrypted_record(inner, cx, buf.len())
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

fn log_application_stream_split(read_sequence: u64, write_sequence: u64) {
    debug!(
        stage = stages::TLS13_APPLICATION_STREAM_SPLIT,
        direction = TLS13_APPLICATION_STREAM_DIRECTION,
        read_sequence_preserved = read_sequence,
        write_sequence_preserved = write_sequence,
        read_sequence_current = read_sequence,
        write_sequence_current = write_sequence,
        "split TLS application stream for bidirectional relay"
    );
}

/// Client-to-server TLS 1.3 application reader with exclusive decrypt state.
pub struct RealityTls13ClientReader<S> {
    inner: S,
    read: Tls13ClientReadState,
    direct_relay: Arc<AtomicBool>,
    direct_mode_active: bool,
}

impl<S> RealityTls13ClientReader<S> {
    pub fn client_decrypt_sequence(&self) -> u64 {
        self.read.decrypt_sequence()
    }

    pub fn direct_relay_enabled(&self) -> bool {
        self.direct_relay.load(Ordering::SeqCst)
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S> AsyncRead for RealityTls13ClientReader<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        if this.direct_relay.load(Ordering::SeqCst) {
            if !this.direct_mode_active {
                if !this.read.ciphertext_read_buf.is_empty() {
                    this.read
                        .plaintext_read_buf
                        .extend_from_slice(&this.read.ciphertext_read_buf);
                    this.read.ciphertext_read_buf.clear();
                }
                this.direct_mode_active = true;
            }
            if !this.read.plaintext_read_buf.is_empty() {
                let to_copy = this.read.plaintext_read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read.plaintext_read_buf[..to_copy]);
                let _ = this.read.plaintext_read_buf.split_to(to_copy);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        if this.read.plaintext_read_buf.is_empty() {
            match this.read.fill_plaintext_read_buf(&mut this.inner, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            }
        }

        if this.read.plaintext_read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let to_copy = this.read.plaintext_read_buf.len().min(buf.remaining());
        buf.put_slice(&this.read.plaintext_read_buf[..to_copy]);
        let _ = this.read.plaintext_read_buf.split_to(to_copy);
        Poll::Ready(Ok(()))
    }
}

/// Client-to-server TLS 1.3 application writer with exclusive encrypt state.
pub struct RealityTls13ClientWriter<S> {
    inner: S,
    write: Tls13ClientWriteState,
    direct_relay: Arc<AtomicBool>,
}

impl<S> RealityTls13ClientWriter<S> {
    pub fn client_encrypt_sequence(&self) -> u64 {
        self.write.encrypt_sequence()
    }

    pub fn direct_relay_enabled(&self) -> bool {
        self.direct_relay.load(Ordering::SeqCst)
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S> AsyncWrite for RealityTls13ClientWriter<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.direct_relay.load(Ordering::SeqCst) {
            if !this.write.ciphertext_write_buf.is_empty() {
                let pending = this
                    .write
                    .pending_write_plaintext_len
                    .expect("pending plaintext length while encrypted write buffer is non-empty");
                return this.write.poll_write_encrypted_record(
                    Pin::new(&mut this.inner),
                    cx,
                    pending,
                );
            }
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.write.poll_write(Pin::new(&mut this.inner), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        log_application_stream_writer_flush();
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let pending_ciphertext_len = this.write.ciphertext_write_buf.len();
        // TODO: send encrypted TLS close_notify before transport shutdown.
        match this
            .write
            .poll_flush_pending_ciphertext(Pin::new(&mut this.inner), cx)?
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(()) => {}
        }
        match Pin::new(&mut this.inner).poll_flush(cx)? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(()) => {}
        }
        log_application_stream_writer_shutdown(pending_ciphertext_len, false);
        Poll::Ready(Ok(()))
    }
}

/// Bidirectional relay adapter: read decrypts via [`RealityTls13ClientReader`], write encrypts via [`RealityTls13ClientWriter`].
pub struct RealityTls13RelayClient<R, W> {
    reader: R,
    writer: W,
    direct_relay: ApplicationStreamDirectRelay,
}

impl<R, W> RealityTls13RelayClient<R, W> {
    pub fn new(reader: R, writer: W, direct_relay: ApplicationStreamDirectRelay) -> Self {
        Self {
            reader,
            writer,
            direct_relay,
        }
    }

    pub fn enable_reader_direct_relay(&self) {
        self.direct_relay.enable_reader();
    }

    pub fn enable_writer_direct_relay(&self) {
        self.direct_relay.enable_writer();
    }

    pub fn direct_relay_enabled(&self) -> bool {
        self.direct_relay.is_enabled()
    }
}

impl<R, W> AsyncRead for RealityTls13RelayClient<R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl<R, W> AsyncWrite for RealityTls13RelayClient<R, W>
where
    W: AsyncWrite + Unpin,
    R: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

/// REALITY TLS 1.3 application-data stream adapter.
pub struct RealityTls13ApplicationStream<S> {
    inner: S,
    read: Tls13ClientReadState,
    write: Tls13ClientWriteState,
    relay_split_guard: ApplicationStreamRelaySplitGuard,
}

impl<S> RealityTls13ApplicationStream<S> {
    pub fn new(
        inner: S,
        read_decryptor: Tls13RecordDecryptor,
        write_encryptor: Tls13RecordEncryptor,
    ) -> Self {
        let server_key_update_requested = Arc::new(AtomicBool::new(false));
        Self {
            inner,
            read: Tls13ClientReadState::new(
                read_decryptor,
                Arc::clone(&server_key_update_requested),
            ),
            write: Tls13ClientWriteState::new(write_encryptor, server_key_update_requested),
            relay_split_guard: ApplicationStreamRelaySplitGuard::new(),
        }
    }

    pub fn client_decrypt_sequence(&self) -> u64 {
        self.read.decrypt_sequence()
    }

    pub fn client_encrypt_sequence(&self) -> u64 {
        self.write.encrypt_sequence()
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Splits into exclusive reader/writer halves for bidirectional relay.
    ///
    /// Decrypt state moves into the reader; encrypt state moves into the writer.
    /// Each half owns one [`tokio::io`] socket half so only one task reads ciphertext.
    pub fn split_for_relay(self) -> io::Result<RealityTls13RelaySplit<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let read_sequence = self.read.decrypt_sequence();
        let write_sequence = self.write.encrypt_sequence();
        self.relay_split_guard.mark_split()?;
        log_application_stream_split(read_sequence, write_sequence);

        let (reader_direct, writer_direct) = ApplicationStreamDirectRelay::new_shared();
        let direct_relay = ApplicationStreamDirectRelay::from_shared(
            Arc::clone(&reader_direct),
            Arc::clone(&writer_direct),
        );

        let (read_half, write_half) = split(self.inner);
        Ok(RealityTls13RelaySplit {
            reader: RealityTls13ClientReader {
                inner: read_half,
                read: self.read,
                direct_relay: reader_direct,
                direct_mode_active: false,
            },
            writer: RealityTls13ClientWriter {
                inner: write_half,
                write: self.write,
                direct_relay: writer_direct,
            },
            direct_relay,
        })
    }

    /// Reads and decrypts one client ApplicationData record.
    pub async fn read_plaintext_chunk(&mut self) -> io::Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            if self.read.read_eof {
                return Ok(Vec::new());
            }

            let record = self.read.read_tls_record(&mut self.inner).await?;
            match self.read.decrypt_application_stream_record(&record)? {
                ApplicationStreamRecord::Plaintext(plaintext) => return Ok(plaintext),
                ApplicationStreamRecord::PeerClosed => {
                    self.read.read_eof = true;
                    return Ok(Vec::new());
                }
                ApplicationStreamRecord::PostHandshakeConsumed => {}
            }
        }
    }

    /// Encrypts and writes one server ApplicationData record.
    pub async fn write_plaintext_all(&mut self, data: &[u8]) -> io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let record = self.write.write_encryptor.encrypt_application_data(data)?;
        self.inner.write_all(&record).await?;
        Ok(())
    }
}

impl<S> AsyncRead for RealityTls13ApplicationStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        if this.read.plaintext_read_buf.is_empty() {
            match this.read.fill_plaintext_read_buf(&mut this.inner, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            }
        }

        if this.read.plaintext_read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let to_copy = this.read.plaintext_read_buf.len().min(buf.remaining());
        buf.put_slice(&this.read.plaintext_read_buf[..to_copy]);
        let _ = this.read.plaintext_read_buf.split_to(to_copy);
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for RealityTls13ApplicationStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        this.write.poll_write(Pin::new(&mut this.inner), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let pending_ciphertext_len = this.write.ciphertext_write_buf.len();
        log_application_stream_writer_shutdown(pending_ciphertext_len, true);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn try_take_tls_record(buf: &mut BytesMut) -> io::Result<Option<TlsRecord>> {
    if buf.len() < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }

    let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_len = TLS_RECORD_HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TLS record length overflow"))?;

    if buf.len() < record_len {
        return Ok(None);
    }

    let raw = buf.split_to(record_len).to_vec();
    let content_type = parse_tls_record_content_type(raw[0]);
    let legacy_version = [raw[1], raw[2]];
    let payload = raw[TLS_RECORD_HEADER_LEN..].to_vec();

    Ok(Some(TlsRecord {
        content_type,
        legacy_version,
        payload,
        raw,
    }))
}

fn poll_read_tls_record<S>(
    mut inner: Pin<&mut S>,
    ciphertext_read_buf: &mut BytesMut,
    cx: &mut Context<'_>,
) -> Poll<io::Result<TlsRecord>>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(record) = try_take_tls_record(ciphertext_read_buf)? {
            return Poll::Ready(Ok(record));
        }

        let mut chunk = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut chunk);
        match inner.as_mut().poll_read(cx, &mut read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS 1.3 application stream closed before a complete record",
                    )));
                }
                ciphertext_read_buf.extend_from_slice(read_buf.filled());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use crate::reality::tls13::{tls13_cipher_suite, Tls13TrafficKeys, TLS_AES_128_GCM_SHA256};
    use crate::tls::records::{
        build_application_data_record, build_change_cipher_spec_record, build_tls_record,
        parse_tls_records, TLS_LEGACY_VERSION_1_2, TLS_RECORD_ALERT, TLS_RECORD_APPLICATION_DATA,
        TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
    };

    use crate::reality::stages;

    use super::*;

    use crate::vless::inbound::read_vless_request;
    use crate::vless::protocol::{build_vless_domain_address, build_vless_request_wire};

    fn aes128_keys(seed: u8) -> Tls13TrafficKeys {
        Tls13TrafficKeys {
            key: (seed..seed + 16).collect(),
            iv: (0x01..0x0d).collect(),
        }
    }

    fn client_to_server_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys(0x10);
        let encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor");
        let decryptor = Tls13RecordDecryptor::new(suite, keys).expect("decryptor");
        (encryptor, decryptor)
    }

    fn server_to_client_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys(0x20);
        let encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor");
        let decryptor = Tls13RecordDecryptor::new(suite, keys).expect("decryptor");
        (encryptor, decryptor)
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    #[test]
    fn application_stream_second_record_decrypt_after_partial_async_read() {
        block_on(async {
            let (mut client_io, server_io) = duplex(8192);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let record0_plaintext = b"vless-header-and-initial-payload-bytes";
            let record1_plaintext = b"extra-client-bytes-after-vless";

            let encrypted0 = client_encryptor
                .encrypt_application_data(record0_plaintext)
                .expect("encrypted record 0");
            let encrypted1 = client_encryptor
                .encrypt_application_data(record1_plaintext)
                .expect("encrypted record 1");
            client_io
                .write_all(&encrypted0)
                .await
                .expect("write record 0");
            client_io
                .write_all(&encrypted1)
                .await
                .expect("write record 1");

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let mut first_chunk = [0u8; 24];
            let read = stream
                .read(&mut first_chunk)
                .await
                .expect("read first plaintext chunk");
            assert_eq!(read, first_chunk.len());
            assert_eq!(&first_chunk[..read], &record0_plaintext[..read]);
            assert_eq!(stream.client_decrypt_sequence(), 1);

            let mut second_chunk = [0u8; 64];
            let read = stream
                .read(&mut second_chunk)
                .await
                .expect("read second plaintext chunk");
            assert_eq!(
                &second_chunk[..read],
                &record0_plaintext[first_chunk.len()..record0_plaintext.len()]
            );
            assert_eq!(stream.client_decrypt_sequence(), 1);

            let mut third_chunk = [0u8; 64];
            let read = stream
                .read(&mut third_chunk)
                .await
                .expect("read third plaintext chunk");
            assert_eq!(&third_chunk[..read], record1_plaintext);
            assert_eq!(stream.client_decrypt_sequence(), 2);
        });
    }

    #[test]
    fn application_stream_does_not_reset_decrypt_sequence_between_reads() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let encrypted0 = client_encryptor
                .encrypt_application_data(b"record-zero")
                .expect("encrypted record 0");
            let encrypted1 = client_encryptor
                .encrypt_application_data(b"record-one")
                .expect("encrypted record 1");
            client_io.write_all(&encrypted0).await.expect("write 0");
            client_io.write_all(&encrypted1).await.expect("write 1");

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let mut buf = [0u8; 32];
            let read = stream.read(&mut buf).await.expect("first read");
            assert_eq!(&buf[..read], b"record-zero");
            assert_eq!(stream.client_decrypt_sequence(), 1);

            let read = stream.read(&mut buf).await.expect("second read");
            assert_eq!(&buf[..read], b"record-one");
            assert_eq!(stream.client_decrypt_sequence(), 2);
        });
    }

    #[test]
    fn application_stream_vless_request_parse_then_second_record_decrypt() {
        block_on(async {
            let user_id = [0x11; 16];
            let second_record_plaintext = b"second-client-record-after-vless";
            let mut vless_packet = build_vless_request_wire(
                0,
                &user_id,
                &[],
                0x01,
                443,
                &build_vless_domain_address("example.com"),
            );
            vless_packet.extend_from_slice(b"TLS-INITIAL");

            let (mut client_io, server_io) = duplex(8192);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let encrypted0 = client_encryptor
                .encrypt_application_data(&vless_packet)
                .expect("encrypted vless record");
            let encrypted1 = client_encryptor
                .encrypt_application_data(second_record_plaintext)
                .expect("encrypted second record");
            client_io.write_all(&encrypted0).await.expect("write 0");
            client_io.write_all(&encrypted1).await.expect("write 1");

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let inbound = read_vless_request(&mut stream)
                .await
                .expect("vless request parsed from application stream");
            assert_eq!(inbound.request.version, 0);
            assert_eq!(inbound.initial_payload, b"TLS-INITIAL");
            assert_eq!(stream.client_decrypt_sequence(), 1);

            let mut second = [0u8; 64];
            let read = stream.read(&mut second).await.expect("second record read");
            assert_eq!(&second[..read], second_record_plaintext);
            assert_eq!(stream.client_decrypt_sequence(), 2);
        });
    }

    #[test]
    fn read_plaintext_chunk_decrypts_one_record() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_application_data(b"vless-payload")
                .expect("encrypted record");
            client_io.write_all(&encrypted).await.expect("write");

            let plaintext = stream
                .read_plaintext_chunk()
                .await
                .expect("decrypted plaintext");

            assert_eq!(plaintext, b"vless-payload");
            assert_eq!(stream.client_decrypt_sequence(), 1);
        });
    }

    #[test]
    fn split_once_preserves_decrypt_sequence_after_initial_read() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let encrypted0 = client_encryptor
                .encrypt_application_data(b"before-split")
                .expect("encrypted record 0");
            let encrypted1 = client_encryptor
                .encrypt_application_data(b"after-split")
                .expect("encrypted record 1");
            client_io.write_all(&encrypted0).await.expect("write 0");
            client_io.write_all(&encrypted1).await.expect("write 1");

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let mut buf = [0u8; 32];
            let read = stream.read(&mut buf).await.expect("read before split");
            assert_eq!(&buf[..read], b"before-split");
            assert_eq!(stream.client_decrypt_sequence(), 1);

            let split = stream.split_for_relay().expect("split once");
            let mut reader = split.reader;
            assert_eq!(reader.client_decrypt_sequence(), 1);

            let read = reader.read(&mut buf).await.expect("read after split");
            assert_eq!(&buf[..read], b"after-split");
            assert_eq!(reader.client_decrypt_sequence(), 2);
        });
    }

    #[test]
    fn split_does_not_clone_decrypt_sequence() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let encrypted = client_encryptor
                .encrypt_application_data(b"single-record")
                .expect("encrypted record");
            client_io.write_all(&encrypted).await.expect("write");

            let stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
            assert_eq!(stream.client_decrypt_sequence(), 0);

            let split = stream.split_for_relay().expect("split");
            let mut reader = split.reader;
            assert_eq!(reader.client_decrypt_sequence(), 0);

            let mut buf = [0u8; 32];
            let read = reader.read(&mut buf).await.expect("read");
            assert_eq!(&buf[..read], b"single-record");
            assert_eq!(reader.client_decrypt_sequence(), 1);
        });
    }

    #[test]
    fn two_records_after_split_decrypt_with_sequence_zero_then_one() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let encrypted0 = client_encryptor
                .encrypt_application_data(b"split-seq-0")
                .expect("encrypted record 0");
            let encrypted1 = client_encryptor
                .encrypt_application_data(b"split-seq-1")
                .expect("encrypted record 1");
            client_io.write_all(&encrypted0).await.expect("write 0");
            client_io.write_all(&encrypted1).await.expect("write 1");

            let stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
            let split = stream.split_for_relay().expect("split");
            let mut reader = split.reader;

            assert_eq!(reader.client_decrypt_sequence(), 0);

            let mut buf = [0u8; 32];
            let read = reader.read(&mut buf).await.expect("read seq 0");
            assert_eq!(&buf[..read], b"split-seq-0");
            assert_eq!(reader.client_decrypt_sequence(), 1);

            let read = reader.read(&mut buf).await.expect("read seq 1");
            assert_eq!(&buf[..read], b"split-seq-1");
            assert_eq!(reader.client_decrypt_sequence(), 2);
        });
    }

    #[test]
    fn independent_application_streams_each_split_once_without_error() {
        block_on(async {
            let (_client_encryptor_a, server_decryptor_a) = client_to_server_keys();
            let (server_encryptor_a, _client_decryptor_a) = server_to_client_keys();
            let (_client_encryptor_b, server_decryptor_b) = client_to_server_keys();
            let (server_encryptor_b, _client_decryptor_b) = server_to_client_keys();

            let stream_a = RealityTls13ApplicationStream::new(
                duplex(4096).1,
                server_decryptor_a,
                server_encryptor_a,
            );
            let stream_b = RealityTls13ApplicationStream::new(
                duplex(4096).1,
                server_decryptor_b,
                server_encryptor_b,
            );

            stream_a.split_for_relay().expect("first stream split");
            stream_b.split_for_relay().expect("second stream split");
        });
    }

    #[test]
    fn repeated_split_on_same_stream_instance_is_rejected() {
        let (_client_encryptor, server_decryptor) = client_to_server_keys();
        let (server_encryptor, _client_decryptor) = server_to_client_keys();

        let stream =
            RealityTls13ApplicationStream::new(duplex(4096).1, server_decryptor, server_encryptor);
        let split_flag = stream.relay_split_guard.split_flag();

        stream.split_for_relay().expect("first split succeeds");
        assert!(split_flag.load(Ordering::SeqCst));

        let err = ApplicationStreamRelaySplitGuard(split_flag)
            .mark_split()
            .expect_err("second split on same stream must fail");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err
            .to_string()
            .contains("TLS application stream relay split called more than once"));
    }

    #[test]
    fn direct_relay_bypasses_tls_decrypt_on_reader() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (_client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
            let split = stream.split_for_relay().expect("split");
            split.direct_relay.enable_reader();
            let mut reader = split.reader;

            client_io
                .write_all(b"raw-after-direct")
                .await
                .expect("write raw");

            let mut buf = [0u8; 32];
            let read = reader.read(&mut buf).await.expect("read raw");
            assert_eq!(&buf[..read], b"raw-after-direct");
            assert_eq!(reader.client_decrypt_sequence(), 0);
        });
    }

    #[test]
    fn direct_relay_bypasses_tls_encrypt_on_writer() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (_client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
            let split = stream.split_for_relay().expect("split");
            split.direct_relay.enable_writer();
            let mut writer = split.writer;

            writer.write_all(b"raw-downlink").await.expect("write raw");
            writer.flush().await.expect("flush");

            let mut client_buf = [0u8; 32];
            let read = client_io.read(&mut client_buf).await.expect("client read");
            assert_eq!(&client_buf[..read], b"raw-downlink");
            assert_eq!(writer.client_encrypt_sequence(), 0);
        });
    }

    #[test]
    fn direct_relay_drains_buffered_ciphertext_before_raw_read() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (_client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);
            let split = stream.split_for_relay().expect("split");
            let mut reader = split.reader;

            reader
                .read
                .ciphertext_read_buf
                .extend_from_slice(b"buffered-raw");
            split.direct_relay.enable_reader();

            let mut buf = [0u8; 32];
            let read = reader.read(&mut buf).await.expect("read buffered raw");
            assert_eq!(&buf[..read], b"buffered-raw");

            client_io
                .write_all(b"-from-socket")
                .await
                .expect("write socket");
            let read = reader.read(&mut buf).await.expect("read socket raw");
            assert_eq!(&buf[..read], b"-from-socket");
        });
    }

    #[test]
    fn read_plaintext_chunk_then_async_read_continues_sequence() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let encrypted0 = client_encryptor
                .encrypt_application_data(b"chunk-read")
                .expect("encrypted record 0");
            let encrypted1 = client_encryptor
                .encrypt_application_data(b"async-read")
                .expect("encrypted record 1");
            client_io.write_all(&encrypted0).await.expect("write 0");
            client_io.write_all(&encrypted1).await.expect("write 1");

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let plaintext = stream
                .read_plaintext_chunk()
                .await
                .expect("decrypted plaintext");
            assert_eq!(plaintext, b"chunk-read");
            assert_eq!(stream.client_decrypt_sequence(), 1);

            let mut buf = [0u8; 32];
            let read = stream.read(&mut buf).await.expect("async read");
            assert_eq!(&buf[..read], b"async-read");
            assert_eq!(stream.client_decrypt_sequence(), 2);
        });
    }

    #[test]
    fn async_write_produces_tls_application_record() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (_client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, mut client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            stream
                .write_all(b"server response")
                .await
                .expect("write plaintext");

            let mut encrypted = vec![0u8; 4096];
            let read = client_io
                .read(&mut encrypted)
                .await
                .expect("read encrypted record");
            encrypted.truncate(read);

            let records = parse_tls_records(&encrypted).expect("parsable record");
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].content_type,
                TlsRecordContentType::ApplicationData
            );

            let plaintext = client_decryptor
                .decrypt_application_data_record(&records[0])
                .expect("decrypted application data");
            assert_eq!(plaintext, b"server response");
        });
    }

    #[test]
    fn duplex_encrypt_decrypt_roundtrip() {
        block_on(async {
            let (mut client_io, server_io) = duplex(8192);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, mut client_decryptor) = server_to_client_keys();

            let mut server_stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let client_to_server = client_encryptor
                .encrypt_application_data(b"client->server")
                .expect("encrypted");
            client_io
                .write_all(&client_to_server)
                .await
                .expect("client write");

            let mut read_buf = [0u8; 64];
            let read = server_stream
                .read(&mut read_buf)
                .await
                .expect("server read");
            assert_eq!(&read_buf[..read], b"client->server");

            server_stream
                .write_all(b"server->client")
                .await
                .expect("server write");

            let mut encrypted = vec![0u8; 4096];
            let read = client_io
                .read(&mut encrypted)
                .await
                .expect("client read encrypted");
            encrypted.truncate(read);

            let records = parse_tls_records(&encrypted).expect("parsable record");
            let plaintext = client_decryptor
                .decrypt_application_data_record(&records[0])
                .expect("decrypted");
            assert_eq!(plaintext, b"server->client");
        });
    }

    #[test]
    fn fragmented_tls_record_read_waits_for_full_record() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_application_data(b"fragmented")
                .expect("encrypted record");
            let split_at = 3;
            client_io
                .write_all(&encrypted[..split_at])
                .await
                .expect("first fragment");
            client_io
                .write_all(&encrypted[split_at..])
                .await
                .expect("second fragment");

            let plaintext = stream
                .read_plaintext_chunk()
                .await
                .expect("decrypted plaintext");
            assert_eq!(plaintext, b"fragmented");
        });
    }

    #[test]
    fn read_tls_record_from_stream_reads_one_record() {
        block_on(async {
            let record_bytes = build_tls_record(
                TLS_RECORD_APPLICATION_DATA,
                TLS_LEGACY_VERSION_1_2,
                b"payload",
            )
            .expect("valid record");
            let mut cursor = std::io::Cursor::new(record_bytes.clone());

            let record = read_tls_record_from_stream(&mut cursor)
                .await
                .expect("valid TLS record");

            assert_eq!(record.raw, record_bytes);
            assert_eq!(record.payload, b"payload");
            assert_eq!(record.content_type, TlsRecordContentType::ApplicationData);
        });
    }

    #[test]
    fn read_client_finished_tls_record_skips_one_change_cipher_spec() {
        block_on(async {
            let mut input = build_change_cipher_spec_record();
            let app_data = build_application_data_record(b"client-finished")
                .expect("valid ApplicationData record");
            input.extend_from_slice(&app_data);
            let total_len = input.len();
            let mut cursor = std::io::Cursor::new(input);

            let record = read_client_finished_tls_record_from_stream(&mut cursor)
                .await
                .expect("client Finished record");

            assert_eq!(record.content_type, TlsRecordContentType::ApplicationData);
            assert_eq!(record.payload, b"client-finished");
            assert_eq!(cursor.position() as usize, total_len);
        });
    }

    #[test]
    fn read_client_finished_tls_record_skips_two_change_cipher_spec_records() {
        block_on(async {
            let mut input = build_change_cipher_spec_record();
            input.extend_from_slice(&build_change_cipher_spec_record());
            let app_data = build_application_data_record(b"client-finished")
                .expect("valid ApplicationData record");
            input.extend_from_slice(&app_data);
            let mut cursor = std::io::Cursor::new(input);

            let record = read_client_finished_tls_record_from_stream(&mut cursor)
                .await
                .expect("client Finished record");

            assert_eq!(record.content_type, TlsRecordContentType::ApplicationData);
            assert_eq!(record.payload, b"client-finished");
        });
    }

    #[test]
    fn read_client_finished_tls_record_rejects_too_many_change_cipher_spec_records() {
        block_on(async {
            let mut input = Vec::new();
            for _ in 0..MAX_DUMMY_CHANGE_CIPHER_SPEC_BEFORE_CLIENT_FINISHED + 1 {
                input.extend_from_slice(&build_change_cipher_spec_record());
            }
            let mut cursor = std::io::Cursor::new(input);

            let err = read_client_finished_tls_record_from_stream(&mut cursor)
                .await
                .unwrap_err();

            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(err
                .to_string()
                .contains("too many ChangeCipherSpec records before client Finished"));
        });
    }

    #[test]
    fn read_client_finished_tls_record_rejects_alert_before_finished() {
        block_on(async {
            let alert = build_tls_record(TLS_RECORD_ALERT, TLS_LEGACY_VERSION_1_2, &[0x02, 0x28])
                .expect("valid alert record");
            let mut cursor = std::io::Cursor::new(alert);

            let err = read_client_finished_tls_record_from_stream(&mut cursor)
                .await
                .unwrap_err();

            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(err
                .to_string()
                .contains("client sent TLS alert before Finished"));
            assert!(err.to_string().contains("0228"));
            assert!(err.to_string().contains(stages::TLS13_CLIENT_FINISHED_READ));
        });
    }

    #[test]
    fn read_client_finished_tls_record_eof_includes_stage_phrase() {
        block_on(async {
            let mut cursor = std::io::Cursor::new(Vec::new());

            let err = read_client_finished_tls_record_from_stream(&mut cursor)
                .await
                .unwrap_err();

            assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
            assert!(err.to_string().contains(stages::TLS13_CLIENT_FINISHED_READ));
            assert!(err
                .to_string()
                .contains("client closed connection before client Finished"));
        });
    }

    #[test]
    fn read_client_finished_tls_record_errors_do_not_include_secret_field_names() {
        block_on(async {
            let alert = build_tls_record(TLS_RECORD_ALERT, TLS_LEGACY_VERSION_1_2, &[0x02, 0x28])
                .expect("valid alert record");
            let mut cursor = std::io::Cursor::new(alert);

            let err = read_client_finished_tls_record_from_stream(&mut cursor)
                .await
                .unwrap_err();
            let message = err.to_string().to_ascii_lowercase();

            assert!(!message.contains("privatekey"));
            assert!(!message.contains("auth_key"));
            assert!(!message.contains("traffic_secret"));
            assert!(!message.contains("handshake_secret"));
        });
    }

    #[test]
    fn read_client_finished_tls_record_rejects_invalid_change_cipher_spec_payload() {
        block_on(async {
            let invalid_ccs = build_tls_record(
                TLS_RECORD_CHANGE_CIPHER_SPEC,
                TLS_LEGACY_VERSION_1_2,
                &[0x02],
            )
            .expect("valid CCS record framing");
            let mut cursor = std::io::Cursor::new(invalid_ccs);

            let err = read_client_finished_tls_record_from_stream(&mut cursor)
                .await
                .unwrap_err();

            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(err
                .to_string()
                .contains("invalid ChangeCipherSpec payload before client Finished"));
        });
    }

    #[test]
    fn read_client_finished_tls_record_rejects_unexpected_handshake_record() {
        block_on(async {
            let handshake = build_tls_record(TLS_RECORD_HANDSHAKE, TLS_LEGACY_VERSION_1_2, &[0x01])
                .expect("valid handshake record");
            let mut cursor = std::io::Cursor::new(handshake);

            let err = read_client_finished_tls_record_from_stream(&mut cursor)
                .await
                .unwrap_err();

            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(err
                .to_string()
                .contains("unexpected TLS record before client Finished: Handshake"));
        });
    }

    #[test]
    fn try_take_tls_record_requires_complete_record() {
        let mut buf = BytesMut::from(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x02][..]);
        assert!(try_take_tls_record(&mut buf)
            .expect("valid parse")
            .is_none());

        buf.extend_from_slice(&[0x01, 0x02]);
        let record = try_take_tls_record(&mut buf)
            .expect("valid parse")
            .expect("complete record");
        assert_eq!(record.payload, vec![0x01, 0x02]);
        assert!(buf.is_empty());
    }

    #[test]
    fn vless_appdata_decrypt_failure_error_contains_sequence_and_len() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, mut server_decryptor) = client_to_server_keys();
            server_decryptor.keys.key[0] ^= 0x01;
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_application_data(b"secret-vless-payload")
                .expect("encrypted record");
            let records = parse_tls_records(&encrypted).expect("parsable record");
            let record_payload_len = records[0].payload.len();
            client_io.write_all(&encrypted).await.expect("write");

            let err = stream.read_plaintext_chunk().await.unwrap_err();
            let message = err.to_string();

            assert!(message.contains("decrypt_sequence=0"));
            assert!(message.contains(&format!("record_payload_len={record_payload_len}")));
            assert!(message.contains("record_content_type=ApplicationData"));
            assert!(message.contains("legacy_version_hex=0303"));
            assert!(message.contains(stages::TLS13_APPLICATION_STREAM_DECRYPT));
            assert!(message.contains("TLS_AES_128_GCM_SHA256"));
            assert!(message.contains("AES-128-GCM decrypt failed"));
        });
    }

    #[test]
    fn short_encrypted_application_record_rejected_before_aead() {
        block_on(async {
            let short_record = build_tls_record(
                TLS_RECORD_APPLICATION_DATA,
                TLS_LEGACY_VERSION_1_2,
                &[0u8; 8],
            )
            .expect("valid short record");

            let (mut client_io, server_io) = duplex(4096);
            let (_client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            client_io
                .write_all(&short_record)
                .await
                .expect("write short record");

            let err = stream.read_plaintext_chunk().await.unwrap_err();
            let message = err.to_string();

            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(message.contains("TLS application record too short for AEAD tag"));
            assert!(message.contains("decrypt_sequence=0"));
            assert!(message.contains("record_payload_len=8"));
            assert!(!message.contains("AES-128-GCM decrypt failed"));
            assert!(!message.contains("AES-256-GCM decrypt failed"));
        });
    }

    #[test]
    fn tls_record_debug_prefix_helpers_cap_at_32_bytes() {
        let payload: Vec<u8> = (0..64).collect();
        assert_eq!(
            encrypted_payload_prefix_hex(&payload).len(),
            MAX_DEBUG_TLS_RECORD_PREFIX_BYTES * 2
        );
        assert_eq!(
            encrypted_payload_suffix_hex(&payload).len(),
            MAX_DEBUG_TLS_RECORD_PREFIX_BYTES * 2
        );

        let record = build_tls_record(
            TLS_RECORD_APPLICATION_DATA,
            TLS_LEGACY_VERSION_1_2,
            &payload,
        )
        .expect("valid record");
        assert_eq!(
            tls_record_header_hex(&record).len(),
            TLS_RECORD_HEADER_LEN * 2
        );
        assert_eq!(tls_record_header_hex(&record), "1703030040");
    }

    #[test]
    fn debug_tls_record_prefix_enabled_requires_exact_one() {
        let key = "RUST_XRAY_DEBUG_TLS_RECORD_PREFIX";
        let previous = std::env::var(key).ok();

        std::env::set_var(key, "1");
        assert!(debug_tls_record_prefix_enabled());

        std::env::set_var(key, "true");
        assert!(!debug_tls_record_prefix_enabled());

        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn vless_appdata_decrypt_failure_does_not_contain_plaintext() {
        block_on(async {
            let payload = b"secret-vless-payload";
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, mut server_decryptor) = client_to_server_keys();
            server_decryptor.keys.key[0] ^= 0x01;
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_application_data(payload)
                .expect("encrypted record");
            client_io.write_all(&encrypted).await.expect("write");

            let err = stream.read_plaintext_chunk().await.unwrap_err();
            let message = err.to_string().to_ascii_lowercase();

            assert!(!message.contains("secret-vless-payload"));
            assert!(!message.contains("736563726574")); // "secret" hex
            assert!(!message.contains("traffic_secret"));
            assert!(!message.contains("auth_key"));
        });
    }

    #[test]
    fn vless_plaintext_debug_preview_caps_at_64_bytes() {
        let plaintext = vec![0xAB; 128];
        let (preview_hex, preview_len) = vless_plaintext_debug_preview(&plaintext);

        assert_eq!(preview_len, 64);
        assert_eq!(preview_hex.len(), 128);
        assert_eq!(preview_hex, "ab".repeat(64));
    }

    #[test]
    fn decrypted_close_notify_alert_maps_to_eof() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_application_record_with_inner_content_type(
                    &[TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY],
                    TLS_RECORD_ALERT,
                )
                .expect("encrypted close_notify alert");
            client_io.write_all(&encrypted).await.expect("write");

            let plaintext = stream
                .read_plaintext_chunk()
                .await
                .expect("close_notify maps to EOF");
            assert!(plaintext.is_empty());

            let mut read_buf = [0u8; 8];
            let read = stream.read(&mut read_buf).await.expect("async EOF");
            assert_eq!(read, 0);
            assert!(stream.read.read_eof);
        });
    }

    #[test]
    fn decrypted_fatal_alert_maps_to_connection_aborted_with_description() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_application_record_with_inner_content_type(
                    &[TLS_ALERT_LEVEL_FATAL, 0x28],
                    TLS_RECORD_ALERT,
                )
                .expect("encrypted fatal alert");
            client_io.write_all(&encrypted).await.expect("write");

            let err = stream.read_plaintext_chunk().await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ConnectionAborted);
            assert!(err.to_string().contains("level=fatal"));
            assert!(err.to_string().contains("description=40"));
        });
    }

    #[test]
    fn unexpected_inner_content_type_maps_to_invalid_data() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_handshake_message(&[0x01, 0x00, 0x00, 0x01, 0x00])
                .expect("encrypted handshake inner record");
            client_io.write_all(&encrypted).await.expect("write");

            let err = stream.read_plaintext_chunk().await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(err
                .to_string()
                .contains("unsupported post-handshake message type: 0x01"));
        });
    }

    fn sample_traffic_secret(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn client_to_server_keys_with_traffic_secret() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
        use crate::reality::tls13::key_schedule::derive_traffic_key;

        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let traffic_secret = sample_traffic_secret(0xAA);
        let keys = derive_traffic_key(suite, &traffic_secret).expect("traffic keys");
        let encryptor =
            Tls13RecordEncryptor::with_traffic_secret(suite, keys.clone(), traffic_secret.clone())
                .expect("encryptor");
        let decryptor = Tls13RecordDecryptor::with_traffic_secret(suite, keys, traffic_secret)
            .expect("decryptor");
        (encryptor, decryptor)
    }

    #[test]
    fn key_update_record_is_consumed_and_next_appdata_decrypts_with_updated_key() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) =
                client_to_server_keys_with_traffic_secret();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let key_update = client_encryptor
                .encrypt_key_update(crate::reality::tls13::messages::KEY_UPDATE_NOT_REQUESTED)
                .expect("encrypted key update");
            client_encryptor
                .apply_sending_traffic_key_update()
                .expect("client sending key update");
            let encrypted_app = client_encryptor
                .encrypt_application_data(b"after-key-update")
                .expect("encrypted app data after key update");

            client_io
                .write_all(&key_update)
                .await
                .expect("write key update");
            client_io
                .write_all(&encrypted_app)
                .await
                .expect("write app data");

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let mut buf = [0u8; 32];
            let read = stream.read(&mut buf).await.expect("read after key update");
            assert_eq!(&buf[..read], b"after-key-update");
            assert_eq!(stream.client_decrypt_sequence(), 1);
        });
    }

    #[test]
    fn key_update_resets_record_sequence_after_traffic_key_change() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) =
                client_to_server_keys_with_traffic_secret();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let encrypted0 = client_encryptor
                .encrypt_application_data(b"before-key-update")
                .expect("encrypted record 0");
            assert_eq!(client_encryptor.sequence, 1);

            let key_update = client_encryptor
                .encrypt_key_update(crate::reality::tls13::messages::KEY_UPDATE_NOT_REQUESTED)
                .expect("encrypted key update");
            assert_eq!(client_encryptor.sequence, 2);
            client_encryptor
                .apply_sending_traffic_key_update()
                .expect("client sending key update");

            let encrypted1 = client_encryptor
                .encrypt_application_data(b"after-key-update")
                .expect("encrypted record 1");
            assert_eq!(client_encryptor.sequence, 1);

            client_io.write_all(&encrypted0).await.expect("write 0");
            client_io
                .write_all(&key_update)
                .await
                .expect("write key update");
            client_io.write_all(&encrypted1).await.expect("write 1");

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let mut buf = [0u8; 32];
            let read = stream.read(&mut buf).await.expect("read first");
            assert_eq!(&buf[..read], b"before-key-update");
            assert_eq!(stream.client_decrypt_sequence(), 1);

            let read = stream.read(&mut buf).await.expect("read second");
            assert_eq!(&buf[..read], b"after-key-update");
            assert_eq!(stream.client_decrypt_sequence(), 1);
        });
    }

    #[test]
    fn unsupported_post_handshake_message_returns_invalid_data() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) =
                client_to_server_keys_with_traffic_secret();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_handshake_message(&[0x08, 0x00, 0x00, 0x00])
                .expect("encrypted encrypted extensions inner record");
            client_io.write_all(&encrypted).await.expect("write");

            let err = stream.read_plaintext_chunk().await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidData);
            assert!(err
                .to_string()
                .contains("unsupported post-handshake message type: 0x08"));
        });
    }

    #[test]
    fn parse_application_stream_tls_alert_rejects_short_alert_body() {
        let err = parse_application_stream_tls_alert(&[TLS_ALERT_LEVEL_FATAL], 3).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("too short"));
    }

    struct ShutdownTrackingWriter {
        written: Vec<u8>,
        shutdown_calls: u32,
        block_next_write: bool,
    }

    impl ShutdownTrackingWriter {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                shutdown_calls: 0,
                block_next_write: false,
            }
        }

        fn block_next_write(mut self) -> Self {
            self.block_next_write = true;
            self
        }
    }

    impl AsyncWrite for ShutdownTrackingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.block_next_write {
                self.block_next_write = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_calls += 1;
            Poll::Ready(Ok(()))
        }
    }

    fn noop_waker() -> Waker {
        static VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    fn client_writer_for_test(
        inner: ShutdownTrackingWriter,
    ) -> RealityTls13ClientWriter<ShutdownTrackingWriter> {
        let (write_encryptor, _) = server_to_client_keys();
        let (_reader_direct, writer_direct) = ApplicationStreamDirectRelay::new_shared();
        RealityTls13ClientWriter {
            inner,
            write: Tls13ClientWriteState::new(write_encryptor, Arc::new(AtomicBool::new(false))),
            direct_relay: writer_direct,
        }
    }

    #[test]
    fn client_writer_poll_shutdown_flushes_pending_encrypted_bytes() {
        let inner = ShutdownTrackingWriter::new().block_next_write();
        let mut writer = client_writer_for_test(inner);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut writer).poll_write(&mut cx, b"pending-shutdown-flush") {
            Poll::Pending => {}
            Poll::Ready(result) => panic!("expected pending write, got {result:?}"),
        }
        assert!(!writer.write.ciphertext_write_buf.is_empty());

        match Pin::new(&mut writer).poll_shutdown(&mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("expected shutdown ready Ok(()), got {other:?}"),
        }

        assert!(writer.write.ciphertext_write_buf.is_empty());
        assert!(!writer.inner.written.is_empty());
        assert_eq!(writer.inner.written[0], TLS_RECORD_APPLICATION_DATA);
        assert_eq!(writer.inner.shutdown_calls, 0);
    }

    #[test]
    fn client_writer_poll_shutdown_does_not_shutdown_underlying_transport() {
        let inner = ShutdownTrackingWriter::new();
        let mut writer = client_writer_for_test(inner);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut writer).poll_shutdown(&mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("expected shutdown ready Ok(()), got {other:?}"),
        }

        assert_eq!(writer.inner.shutdown_calls, 0);
    }
}
