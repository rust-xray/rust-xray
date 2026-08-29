//! Consecutive useless/non-advancing TLS record tolerance (Stage 5C runtime policy).
//!
//! Mirrors upstream REALITY/TLS `retryReadRecord` / `MaxUselessRecords` semantics on the
//! accepted REALITY server read path.

use std::fmt;
use std::io::{Error, ErrorKind};

use crate::reality::post_handshake::UselessRecordTolerance;
use crate::tls::records::{
    TlsRecord, TlsRecordContentType, TLS13_COMPATIBILITY_CCS_RECORD, TLS_LEGACY_VERSION_1_2,
};

const TLS_ALERT_LEVEL_WARNING: u8 = 1;
const TLS_ALERT_LEVEL_FATAL: u8 = 2;
const TLS_ALERT_USER_CANCELED: u8 = 0x5a;

/// Typed signal that consecutive useless-record tolerance was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UselessRecordOverflow {
    pub limit: usize,
}

impl fmt::Display for UselessRecordOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS 1.3 too many ignored records (limit={})", self.limit)
    }
}

impl std::error::Error for UselessRecordOverflow {}

/// Tracks consecutive ignored/non-advancing TLS records against an effective tolerance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UselessRecordCounter {
    tolerance: UselessRecordTolerance,
    consecutive: usize,
}

impl UselessRecordCounter {
    pub fn new(tolerance: UselessRecordTolerance) -> Self {
        Self {
            tolerance,
            consecutive: 0,
        }
    }

    pub fn tolerance(&self) -> UselessRecordTolerance {
        self.tolerance
    }

    pub fn consecutive(&self) -> usize {
        self.consecutive
    }

    pub fn observe_advancing(&mut self) {
        self.consecutive = 0;
    }

    pub fn observe_useless(&mut self) -> Result<(), UselessRecordOverflow> {
        self.consecutive += 1;
        if let Some(limit) = self.tolerance.effective_limit() {
            if self.consecutive > limit {
                return Err(UselessRecordOverflow { limit });
            }
        }
        Ok(())
    }
}

pub fn too_many_ignored_records_error(limit: usize) -> Error {
    Error::new(ErrorKind::InvalidData, UselessRecordOverflow { limit })
}

pub fn useless_record_overflow_limit(err: &Error) -> Option<usize> {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<UselessRecordOverflow>())
        .map(|overflow| overflow.limit)
}

pub fn is_useless_record_overflow(err: &Error) -> bool {
    useless_record_overflow_limit(err).is_some()
}

pub fn is_valid_tls13_compatibility_ccs_record(record: &TlsRecord) -> bool {
    record.raw.as_slice() == TLS13_COMPATIBILITY_CCS_RECORD.as_slice()
}

/// Classifies an outer TLS record received before the encrypted client Finished.
///
/// Returns `Ok(true)` when the record is a permitted ignored/non-advancing record (compatibility
/// CCS, warning alert, TLS 1.3 user_canceled, empty ApplicationData).
/// Returns `Ok(false)` when the record advances handshake state (non-empty ApplicationData).
/// Returns `Err` for malformed CCS or fatal/unexpected records.
pub fn classify_record_before_client_finished(record: &TlsRecord) -> Result<bool, Error> {
    match record.content_type {
        TlsRecordContentType::ChangeCipherSpec => {
            if !is_valid_tls13_compatibility_ccs_record(record) {
                if record.legacy_version != TLS_LEGACY_VERSION_1_2 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "invalid ChangeCipherSpec legacy version before client Finished",
                    ));
                }
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid ChangeCipherSpec payload before client Finished",
                ));
            }
            Ok(true)
        }
        TlsRecordContentType::Alert => classify_handshake_phase_alert(record),
        TlsRecordContentType::ApplicationData => Ok(record.payload.is_empty()),
        other => Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "unexpected TLS record before client Finished: {}",
                content_type_name(other)
            ),
        )),
    }
}

/// Classifies an outer TLS record on the post-handshake application stream.
///
/// Only compatibility CCS and permitted alerts are ignored; outer ApplicationData is always
/// handed to the decryptor (useful records reset the counter after successful delivery).
pub fn classify_record_on_application_stream(record: &TlsRecord) -> Result<bool, Error> {
    match record.content_type {
        TlsRecordContentType::ChangeCipherSpec => {
            if !is_valid_tls13_compatibility_ccs_record(record) {
                if record.legacy_version != TLS_LEGACY_VERSION_1_2 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "invalid ChangeCipherSpec legacy version on application stream",
                    ));
                }
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid ChangeCipherSpec payload on application stream",
                ));
            }
            Ok(true)
        }
        TlsRecordContentType::Alert => classify_handshake_phase_alert(record),
        TlsRecordContentType::ApplicationData => Ok(false),
        other => Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "unexpected TLS record on application stream: {}",
                content_type_name(other)
            ),
        )),
    }
}

fn classify_handshake_phase_alert(record: &TlsRecord) -> Result<bool, Error> {
    if record.legacy_version != TLS_LEGACY_VERSION_1_2 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid TLS alert legacy version before client Finished",
        ));
    }

    match record.payload.as_slice() {
        [TLS_ALERT_LEVEL_WARNING, _] => Ok(true),
        [TLS_ALERT_LEVEL_FATAL, TLS_ALERT_USER_CANCELED] => Ok(true),
        [TLS_ALERT_LEVEL_FATAL, description] => Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "client sent TLS alert before Finished: {:02x}{:02x}",
                TLS_ALERT_LEVEL_FATAL, description
            ),
        )),
        [] | [_] => Err(Error::new(
            ErrorKind::InvalidData,
            "client sent TLS alert before Finished: truncated alert payload",
        )),
        bytes => Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "client sent TLS alert before Finished: {}",
                hex_encode(bytes)
            ),
        )),
    }
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/useless_records.rs"]
mod tests;
