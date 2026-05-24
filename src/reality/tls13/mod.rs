//! TLS 1.3 server handshake skeleton for the REALITY accepted path.
//!
//! Cryptography and message generation are intentionally **not** implemented here
//! yet. This module defines the structure for porting upstream XTLS/REALITY in
//! smaller steps.

mod key_schedule;
mod messages;
mod state;
mod transcript;

pub use key_schedule::Tls13KeySchedule;
pub use messages::{
    RealityCertificatePlan, RealityEncryptedExtensionsPlan, RealityFinishedPlan,
    RealityServerHelloPlan,
};
pub use state::RealityTls13ServerState;
pub use transcript::TranscriptHash;
