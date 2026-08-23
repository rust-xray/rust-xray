//! Pure cumulative extra-CCS tolerance probe state machine (Stage 5C).
//!
//! Network I/O is injected by the caller; this module only tracks probe progression.

use crate::tls::records::TLS13_COMPATIBILITY_CCS_RECORD;

use super::tolerance::UselessRecordTolerance;

/// Incremental extra-CCS batch sizes sent on a single probe connection (upstream order).
pub const CCS_PROBE_INCREMENTAL_BATCHES: [usize; 3] = [2, 15, 16];

/// Cumulative extra CCS sent after each batch completes (2, 2+15, 2+15+16).
pub const CCS_PROBE_CUMULATIVE_SENT: [usize; 3] = [2, 17, 33];

/// Detected tolerance when target alerts after the corresponding cumulative batch.
pub const CCS_PROBE_RESULTS_ON_ALERT: [UselessRecordTolerance; 3] = [
    UselessRecordTolerance::PROBE_FINITE_ONE,
    UselessRecordTolerance::PROBE_FINITE_SIXTEEN,
    UselessRecordTolerance::PROBE_FINITE_THIRTY_TWO,
];

/// High-level probe stage (mirrors upstream tier boundaries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcsProbeStage {
    ProbeBeyondOne,
    ProbeBeyondSixteen,
    ProbeBeyondThirtyTwo,
    Complete,
}

/// Next action after observing no alert at the current tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcsProbeStep {
    SendBatch(usize),
    Complete(UselessRecordTolerance),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbePhase {
    NeedSend,
    WaitingAlert,
    Complete,
}

/// Cumulative extra-CCS probe driver (unit-testable without sockets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcsToleranceProbe {
    batch_index: usize,
    phase: ProbePhase,
    cumulative_sent: usize,
    result: Option<UselessRecordTolerance>,
}

impl Default for CcsToleranceProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl CcsToleranceProbe {
    pub fn new() -> Self {
        Self {
            batch_index: 0,
            phase: ProbePhase::NeedSend,
            cumulative_sent: 0,
            result: None,
        }
    }

    pub fn stage(&self) -> CcsProbeStage {
        if self.phase == ProbePhase::Complete {
            return CcsProbeStage::Complete;
        }
        match self.batch_index {
            0 => CcsProbeStage::ProbeBeyondOne,
            1 => CcsProbeStage::ProbeBeyondSixteen,
            _ => CcsProbeStage::ProbeBeyondThirtyTwo,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.phase == ProbePhase::Complete
    }

    pub fn result(&self) -> Option<UselessRecordTolerance> {
        self.result
    }

    pub fn cumulative_sent(&self) -> usize {
        self.cumulative_sent
    }

    /// Incremental extra-CCS count to send for the current stage, if any.
    pub fn pending_batch_count(&self) -> Option<usize> {
        if self.phase == ProbePhase::NeedSend
            && self.batch_index < CCS_PROBE_INCREMENTAL_BATCHES.len()
        {
            Some(extra_ccs_count_for_stage(self.stage()))
        } else {
            None
        }
    }

    /// Records that the pending batch was written to the wire.
    pub fn record_batch_sent(&mut self) {
        debug_assert_eq!(self.phase, ProbePhase::NeedSend);
        let count = CCS_PROBE_INCREMENTAL_BATCHES[self.batch_index];
        self.cumulative_sent += count;
        self.phase = ProbePhase::WaitingAlert;
    }

    /// Target returned a TLS alert after the most recent batch.
    pub fn observe_alert(&mut self) -> UselessRecordTolerance {
        debug_assert_eq!(self.phase, ProbePhase::WaitingAlert);
        let tolerance = CCS_PROBE_RESULTS_ON_ALERT[self.batch_index];
        self.result = Some(tolerance);
        self.phase = ProbePhase::Complete;
        tolerance
    }

    /// Target did not alert within the observation window after the most recent batch.
    pub fn observe_no_alert(&mut self) -> CcsProbeStep {
        debug_assert_eq!(self.phase, ProbePhase::WaitingAlert);
        if self.batch_index + 1 >= CCS_PROBE_INCREMENTAL_BATCHES.len() {
            self.result = Some(UselessRecordTolerance::Unlimited);
            self.phase = ProbePhase::Complete;
            CcsProbeStep::Complete(UselessRecordTolerance::Unlimited)
        } else {
            self.batch_index += 1;
            self.phase = ProbePhase::NeedSend;
            CcsProbeStep::SendBatch(extra_ccs_count_for_stage(self.stage()))
        }
    }
}

/// Incremental batch size for an active (non-complete) probe stage.
pub fn extra_ccs_count_for_stage(stage: CcsProbeStage) -> usize {
    match stage {
        CcsProbeStage::ProbeBeyondOne => CCS_PROBE_INCREMENTAL_BATCHES[0],
        CcsProbeStage::ProbeBeyondSixteen => CCS_PROBE_INCREMENTAL_BATCHES[1],
        CcsProbeStage::ProbeBeyondThirtyTwo => CCS_PROBE_INCREMENTAL_BATCHES[2],
        CcsProbeStage::Complete => 0,
    }
}

/// Builds wire bytes for `count` consecutive compatibility CCS records.
pub fn build_extra_ccs_probe_payload(count: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(TLS13_COMPATIBILITY_CCS_RECORD.len() * count);
    for _ in 0..count {
        payload.extend_from_slice(&TLS13_COMPATIBILITY_CCS_RECORD);
    }
    payload
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/ccs_probe.rs"]
mod tests;
