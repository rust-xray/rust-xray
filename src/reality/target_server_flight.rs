//! Target TLS 1.3 server-flight record-shape observation for REALITY camouflage.
//!
//! Observes positional wire record lengths from the destination server flight.
//! Encrypted ApplicationData payloads are never decrypted; slot names reflect
//! upstream REALITY positional expectations, not inferred handshake plaintext types.

use std::io::ErrorKind;

use crate::tls::{
    build_change_cipher_spec_record, parse_complete_tls_records_prefix,
    parse_tls_server_hello_handshake, TlsRecord, TlsRecordContentType, TLS_MAX_RECORD_WIRE_LEN,
    TLS_RECORD_HEADER_LEN,
};

use super::handshake::{validate_observed_server_hello, TLS_RECORD_LEGACY_VERSION};

/// Total bytes read while observing the destination TLS 1.3 server flight.
pub const DEST_SERVER_FLIGHT_READ_CAP: usize = 256 * 1024;

const EXPECTED_CHANGE_CIPHER_SPEC_WIRE_LEN: usize = 6;

/// Observed wire length of a destination ChangeCipherSpec record (header + payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedChangeCipherSpec {
    pub wire_len: usize,
}

/// Positional TLS record wire lengths observed from the destination server flight.
///
/// Each length is the full on-wire TLS record size: 5-byte header + payload.
/// Slots after ServerHello are optional when the target closes or stops sending
/// before the full upstream seven-record profile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservedTargetTls13ServerFlight {
    pub server_hello_wire_len: usize,
    pub change_cipher_spec: Option<ObservedChangeCipherSpec>,
    pub encrypted_extensions_wire_len: Option<usize>,
    pub certificate_wire_len: Option<usize>,
    pub certificate_verify_wire_len: Option<usize>,
    pub finished_wire_len: Option<usize>,
    /// Positional encrypted record #6 (upstream `NewSessionTicket` slot); length only.
    pub next_encrypted_record_wire_len: Option<usize>,
}

/// Encrypted TLS 1.3 server-handshake record slots mirrored from target observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedEncryptedHandshakeSlot {
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
}

impl ObservedTargetTls13ServerFlight {
    /// Returns the observed target wire length for an encrypted server-handshake slot.
    pub fn observed_wire_len_for_encrypted_handshake_slot(
        &self,
        slot: ObservedEncryptedHandshakeSlot,
    ) -> Option<usize> {
        match slot {
            ObservedEncryptedHandshakeSlot::EncryptedExtensions => {
                self.encrypted_extensions_wire_len
            }
            ObservedEncryptedHandshakeSlot::Certificate => self.certificate_wire_len,
            ObservedEncryptedHandshakeSlot::CertificateVerify => self.certificate_verify_wire_len,
            ObservedEncryptedHandshakeSlot::Finished => self.finished_wire_len,
        }
    }

    /// Observed positional record #6 wire length for REALITY camouflage emission.
    ///
    /// Upstream uses the `NewSessionTicket` slot name for length observation only.
    /// A zero or missing length means no camouflage record is emitted.
    pub fn observed_position6_camouflage_wire_len(&self) -> Option<usize> {
        self.next_encrypted_record_wire_len.filter(|len| *len > 0)
    }
}

/// Result of feeding another TCP chunk into the incremental target-flight observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetServerFlightFeedStatus {
    /// Fewer bytes than a complete next record; caller should read more from TCP.
    NeedMoreData,
    /// Valid prefix observed; caller may stop reading (partial profile allowed).
    Progress,
    /// Seven positional records observed; observation complete.
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetServerFlightFeedOutcome {
    pub status: TargetServerFlightFeedStatus,
    pub flight: ObservedTargetTls13ServerFlight,
    pub complete_record_count: usize,
    pub buffered_len: usize,
    pub consumed_complete_prefix_len: usize,
    pub has_incomplete_trailing_record: bool,
}

/// Incremental, bounded observer for the destination TLS 1.3 server flight.
#[derive(Debug, Default)]
pub struct TargetServerFlightObserver {
    buffer: Vec<u8>,
}

impl TargetServerFlightObserver {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn buffer_as_slice(&self) -> &[u8] {
        &self.buffer
    }

    /// Re-evaluates the currently buffered bytes without consuming new TCP input.
    pub fn evaluate_buffered(&self) -> std::io::Result<TargetServerFlightFeedOutcome> {
        reject_oversized_declared_record_in_buffer(&self.buffer)?;

        let (records, consumed) = parse_complete_tls_records_prefix(&self.buffer)?;
        let has_incomplete_trailing_record = consumed < self.buffer.len();

        let flight = if records.is_empty() {
            ObservedTargetTls13ServerFlight::default()
        } else {
            build_observed_target_tls13_server_flight(&records)?
        };

        let complete_record_count = records.len();
        let status = if complete_record_count >= 7 {
            TargetServerFlightFeedStatus::Complete
        } else if has_incomplete_trailing_record {
            TargetServerFlightFeedStatus::NeedMoreData
        } else if complete_record_count > 0 {
            TargetServerFlightFeedStatus::Progress
        } else {
            TargetServerFlightFeedStatus::NeedMoreData
        };

        Ok(TargetServerFlightFeedOutcome {
            status,
            flight,
            complete_record_count,
            buffered_len: self.buffer.len(),
            consumed_complete_prefix_len: consumed,
            has_incomplete_trailing_record,
        })
    }

    /// Appends `chunk` and parses every complete TLS record prefix currently available.
    pub fn feed(&mut self, chunk: &[u8]) -> std::io::Result<TargetServerFlightFeedOutcome> {
        if self.buffer.len().saturating_add(chunk.len()) > DEST_SERVER_FLIGHT_READ_CAP {
            return Err(flight_error(
                ErrorKind::InvalidData,
                format!(
                    "destination server flight read cap exceeded (max {DEST_SERVER_FLIGHT_READ_CAP} bytes)"
                ),
            ));
        }

        self.buffer.extend_from_slice(chunk);
        self.evaluate_buffered()
    }
}

fn flight_error(kind: ErrorKind, message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(kind, message.into())
}

/// Returns the declared on-wire TLS record length from a 5-byte record header.
pub fn tls_record_wire_len_from_header(header: &[u8]) -> std::io::Result<usize> {
    if header.len() < TLS_RECORD_HEADER_LEN {
        return Err(flight_error(
            ErrorKind::UnexpectedEof,
            "TLS record header incomplete",
        ));
    }

    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    payload_len
        .checked_add(TLS_RECORD_HEADER_LEN)
        .ok_or_else(|| flight_error(ErrorKind::InvalidData, "TLS record length overflow"))
}

/// Rejects declared record sizes that exceed the TLS wire maximum before payload allocation.
pub fn reject_oversized_declared_record_in_buffer(buffer: &[u8]) -> std::io::Result<()> {
    if buffer.len() < TLS_RECORD_HEADER_LEN {
        return Ok(());
    }

    let mut offset = 0;
    while offset + TLS_RECORD_HEADER_LEN <= buffer.len() {
        let header = &buffer[offset..offset + TLS_RECORD_HEADER_LEN];
        let wire_len = tls_record_wire_len_from_header(header)?;

        if wire_len > TLS_MAX_RECORD_WIRE_LEN {
            return Err(flight_error(
                ErrorKind::InvalidData,
                format!("TLS record declared wire length {wire_len} exceeds protocol maximum"),
            ));
        }

        if wire_len > DEST_SERVER_FLIGHT_READ_CAP {
            return Err(flight_error(
                ErrorKind::InvalidData,
                format!(
                    "destination server flight record declared wire length {wire_len} exceeds observation cap"
                ),
            ));
        }

        if offset + wire_len > buffer.len() {
            // Incomplete record; declared length itself is acceptable so far.
            return Ok(());
        }

        offset += wire_len;
    }

    Ok(())
}

/// Builds the positional server-flight profile from sequentially validated TLS records.
pub fn build_observed_target_tls13_server_flight(
    records: &[TlsRecord],
) -> std::io::Result<ObservedTargetTls13ServerFlight> {
    if records.is_empty() {
        return Err(flight_error(
            ErrorKind::InvalidData,
            "destination server flight has no TLS records",
        ));
    }

    if records.len() > 7 {
        return Err(flight_error(
            ErrorKind::InvalidData,
            format!(
                "destination server flight has {} TLS records (expected at most 7 positional records)",
                records.len()
            ),
        ));
    }

    validate_server_hello_position_record(&records[0])?;
    let mut flight = ObservedTargetTls13ServerFlight {
        server_hello_wire_len: records[0].raw.len(),
        ..ObservedTargetTls13ServerFlight::default()
    };

    let mut index = 1;

    if index < records.len() {
        match records[index].content_type {
            TlsRecordContentType::ChangeCipherSpec => {
                validate_change_cipher_spec_record(&records[index])?;
                flight.change_cipher_spec = Some(ObservedChangeCipherSpec {
                    wire_len: records[index].raw.len(),
                });
                index += 1;
            }
            TlsRecordContentType::ApplicationData => {
                return Err(flight_error(
                    ErrorKind::InvalidData,
                    "destination server flight position 1 must be ChangeCipherSpec, got ApplicationData",
                ));
            }
            other => {
                return Err(flight_error(
                    ErrorKind::InvalidData,
                    format!(
                        "destination server flight position 1 must be ChangeCipherSpec, got {}",
                        content_type_name(other)
                    ),
                ));
            }
        }
    }

    let mut slot = 0usize;
    while index < records.len() {
        validate_encrypted_position_record(&records[index], index)?;
        assign_encrypted_slot(&mut flight, slot, records[index].raw.len())?;
        index += 1;
        slot += 1;
    }

    Ok(flight)
}

fn assign_encrypted_slot(
    flight: &mut ObservedTargetTls13ServerFlight,
    slot: usize,
    wire_len: usize,
) -> std::io::Result<()> {
    match slot {
        0 => flight.encrypted_extensions_wire_len = Some(wire_len),
        1 => flight.certificate_wire_len = Some(wire_len),
        2 => flight.certificate_verify_wire_len = Some(wire_len),
        3 => flight.finished_wire_len = Some(wire_len),
        4 => flight.next_encrypted_record_wire_len = Some(wire_len),
        _ => {
            return Err(flight_error(
                ErrorKind::InvalidData,
                "destination server flight encrypted slot index out of range",
            ));
        }
    }
    Ok(())
}

fn validate_server_hello_position_record(record: &TlsRecord) -> std::io::Result<()> {
    if record.content_type != TlsRecordContentType::Handshake {
        return Err(flight_error(
            ErrorKind::InvalidData,
            "destination server flight position 0 must be Handshake (ServerHello)",
        ));
    }

    validate_legacy_record_version(&record.legacy_version, 0)?;

    if record.payload.first() != Some(&0x02) {
        return Err(flight_error(
            ErrorKind::InvalidData,
            "destination server flight position 0 handshake payload must begin with ServerHello",
        ));
    }

    let server_hello = parse_tls_server_hello_handshake(&record.payload)?;
    validate_observed_server_hello(&server_hello)?;

    Ok(())
}

fn validate_change_cipher_spec_record(record: &TlsRecord) -> std::io::Result<()> {
    validate_legacy_record_version(&record.legacy_version, 1)?;

    if record.raw.len() != EXPECTED_CHANGE_CIPHER_SPEC_WIRE_LEN {
        return Err(flight_error(
            ErrorKind::InvalidData,
            format!(
                "destination ChangeCipherSpec wire length must be {EXPECTED_CHANGE_CIPHER_SPEC_WIRE_LEN}, got {}",
                record.raw.len()
            ),
        ));
    }

    let expected = build_change_cipher_spec_record();
    if record.raw != expected {
        return Err(flight_error(
            ErrorKind::InvalidData,
            "destination ChangeCipherSpec record must be 14 03 03 00 01 01",
        ));
    }

    Ok(())
}

fn validate_encrypted_position_record(record: &TlsRecord, position: usize) -> std::io::Result<()> {
    if record.content_type != TlsRecordContentType::ApplicationData {
        return Err(flight_error(
            ErrorKind::InvalidData,
            format!(
                "destination server flight position {position} must be ApplicationData, got {}",
                content_type_name(record.content_type)
            ),
        ));
    }

    validate_legacy_record_version(&record.legacy_version, position)
}

fn validate_legacy_record_version(version: &[u8; 2], position: usize) -> std::io::Result<()> {
    if *version != TLS_RECORD_LEGACY_VERSION {
        return Err(flight_error(
            ErrorKind::InvalidData,
            format!(
                "destination server flight position {position} legacy record version must be 0x0303, got 0x{:02x}{:02x}",
                version[0], version[1]
            ),
        ));
    }
    Ok(())
}

fn content_type_name(content_type: TlsRecordContentType) -> &'static str {
    match content_type {
        TlsRecordContentType::ChangeCipherSpec => "ChangeCipherSpec",
        TlsRecordContentType::Alert => "Alert",
        TlsRecordContentType::Handshake => "Handshake",
        TlsRecordContentType::ApplicationData => "ApplicationData",
        TlsRecordContentType::Unknown(_) => "Unknown",
    }
}

/// Returns true when destination observation can stop after an idle read.
pub fn target_server_flight_observation_satisfied(outcome: &TargetServerFlightFeedOutcome) -> bool {
    match outcome.status {
        TargetServerFlightFeedStatus::Complete => true,
        TargetServerFlightFeedStatus::NeedMoreData => false,
        TargetServerFlightFeedStatus::Progress => {
            outcome.complete_record_count > 0 && !outcome.has_incomplete_trailing_record
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/reality/target_server_flight.rs"]
mod tests;
