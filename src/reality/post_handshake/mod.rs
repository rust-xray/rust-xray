//! REALITY post-handshake record-length detection infrastructure.

pub mod alpn;
pub mod cache;
pub mod ccs_cache;
pub mod ccs_probe;
pub mod ccs_probe_exec;
pub mod emission;
pub mod parser;
pub mod probe;
pub mod probe_io;
mod tls_client;
pub mod tolerance;
mod validation;

pub use alpn::RealityAlpnProfile;
pub use cache::{PostHandshakeProbeCache, PostHandshakeProbeKey, PostHandshakeProbeState};
pub use ccs_cache::{
    CcsToleranceProbeCache, CcsToleranceProbeCompletionGuard, CcsToleranceProbeState,
};
pub use ccs_probe::{
    build_extra_ccs_probe_payload, extra_ccs_count_for_stage, CcsProbeStage, CcsProbeStep,
    CcsToleranceProbe, CCS_PROBE_CUMULATIVE_SENT, CCS_PROBE_INCREMENTAL_BATCHES,
    CCS_PROBE_RESULTS_ON_ALERT,
};
pub use ccs_probe_exec::{
    execute_ccs_tolerance_probe, CCS_PROBE_BATCH_WAIT, CCS_PROBE_TOTAL_TIMEOUT,
};
pub use emission::{
    emit_post_handshake_camouflage_records, post_handshake_probe_key, resolve_ccs_tolerance,
    resolve_post_handshake_wire_lengths, POST_HANDSHAKE_CACHE_WAIT_TIMEOUT,
};
pub use parser::{
    parse_post_handshake_application_record_lengths, post_handshake_parse_error,
    PostHandshakeParseError,
};
pub use tolerance::UselessRecordTolerance;
pub use validation::{is_valid_post_handshake_wire_length, sanitize_post_handshake_wire_lengths};

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/parser.rs"]
mod parser_tests;
