//! TLS record framing and alert observation for REALITY dest probes (Stage 5B/5C).
//!
//! Outgoing: incremental record assembly so a single `write_tls` chunk may contain
//! multiple records (e.g. rustls coalesces compatibility CCS + encrypted Finished).
//!
//! Incoming: single-buffer owner feeds rustls and a framing-safe alert observer.

use std::io::{Error as IoError, ErrorKind};

use crate::tls::records::{
    parse_complete_tls_records_prefix, TLS13_COMPATIBILITY_CCS_RECORD, TLS_LEGACY_VERSION_1_2,
    TLS_RECORD_ALERT, TLS_RECORD_HEADER_LEN,
};

/// Returns true when `record` is a TLS 1.3 middlebox compatibility CCS (`14 03 03 00 01 01`).
pub fn is_tls13_compatibility_ccs_record(record: &[u8]) -> bool {
    record == TLS13_COMPATIBILITY_CCS_RECORD.as_slice()
}

/// Incremental outgoing TLS record buffer (preserves record order, no reordering).
#[derive(Debug, Default)]
pub struct OutgoingTlsRecordBuffer {
    pending: Vec<u8>,
}

impl OutgoingTlsRecordBuffer {
    pub fn push_chunk(&mut self, chunk: &[u8]) {
        self.pending.extend_from_slice(chunk);
    }

    /// Drains and returns the next complete TLS record when available.
    pub fn pop_complete_record(&mut self) -> Option<Vec<u8>> {
        if self.pending.len() < TLS_RECORD_HEADER_LEN {
            return None;
        }

        let record_len = u16::from_be_bytes([self.pending[3], self.pending[4]]) as usize;
        let total_len = TLS_RECORD_HEADER_LEN
            .checked_add(record_len)
            .expect("TLS record length fits in usize");
        if self.pending.len() < total_len {
            return None;
        }

        Some(self.pending.drain(..total_len).collect())
    }
}

/// Plaintext TLS alert record acceptable during pre-application probe observation.
fn is_handshake_phase_plaintext_alert(record: &[u8]) -> bool {
    if record.len() < TLS_RECORD_HEADER_LEN + 2 {
        return false;
    }
    if record[0] != TLS_RECORD_ALERT {
        return false;
    }
    if record[1..3] != TLS_LEGACY_VERSION_1_2 {
        return false;
    }
    let payload_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    record.len() == TLS_RECORD_HEADER_LEN + payload_len
}

/// Framing-safe inbound alert observer (does not scan arbitrary byte offsets).
#[derive(Debug, Default)]
pub struct InboundAlertObserver {
    buffer: Vec<u8>,
    alert_seen: bool,
    /// Incremented when a new batch observation starts; stale alerts are ignored.
    observation_epoch: u64,
    current_epoch: u64,
}

impl InboundAlertObserver {
    pub fn begin_observation(&mut self) {
        self.observation_epoch = self.observation_epoch.wrapping_add(1);
        self.current_epoch = self.observation_epoch;
        self.alert_seen = false;
        self.buffer.clear();
    }

    pub fn ingest(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
        self.scan_complete_records();
    }

    fn scan_complete_records(&mut self) {
        while let Ok((records, consumed)) = parse_complete_tls_records_prefix(&self.buffer) {
            if consumed == 0 {
                break;
            }

            for record in records {
                if is_handshake_phase_plaintext_alert(&record.raw) {
                    self.alert_seen = true;
                }
            }

            self.buffer.drain(..consumed);
        }
    }

    /// Returns true when a valid alert record was seen during the current observation epoch.
    pub fn alert_seen_in_current_observation(&self) -> bool {
        self.alert_seen && self.current_epoch == self.observation_epoch
    }

    /// After `observe_no_alert`, late alerts from the previous batch must not affect the next tier.
    ///
    /// Strategy: each batch wait calls `begin_observation()` (fresh epoch + cleared flag). When the
    /// wait ends without alert we call `end_observation()` which bumps `observation_epoch` so any
    /// alert record parsed afterward is attributed to a stale epoch and ignored by
    /// `alert_seen_in_current_observation()`. This mirrors upstream's cumulative `hasAlert` flag
    /// without attributing post-deadline reads to the next tier.
    pub fn end_observation(&mut self) {
        self.observation_epoch = self.observation_epoch.wrapping_add(1);
        self.alert_seen = false;
        self.buffer.clear();
    }
}

/// Fatal unexpected_message alert (`level=fatal`, `description=unexpected_message`).
pub fn build_fatal_unexpected_message_alert_record() -> [u8; 7] {
    [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x0a]
}

pub fn rustls_error_to_io(err: rustls::Error) -> IoError {
    IoError::new(
        ErrorKind::InvalidData,
        format!("REALITY probe TLS error: {err}"),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/probe_io.rs"]
mod tests;
