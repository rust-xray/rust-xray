//! VLESS inbound policy hooks (handshake timeout from Xray `policy.levels`).

use std::time::Duration;

use crate::config::{PolicyConfig, XrayConfig};

/// Effective inbound policy for VLESS header read (upstream uses level 0 before auth).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlessInboundPolicy {
    pub handshake_timeout: Duration,
}

impl Default for VlessInboundPolicy {
    fn default() -> Self {
        Self {
            // Xray-core default level-0 handshake timeout.
            handshake_timeout: Duration::from_secs(4),
        }
    }
}

impl VlessInboundPolicy {
    /// Resolve handshake timeout from config policy level `"0"` (matches upstream pre-auth read).
    pub fn from_xray_config(config: &XrayConfig) -> Self {
        config
            .policy
            .as_ref()
            .map(Self::from_policy_config_level_zero)
            .unwrap_or_default()
    }

    pub fn from_policy_config_level_zero(policy: &PolicyConfig) -> Self {
        let mut out = Self::default();
        if let Some(level) = policy.levels.get("0") {
            if let Some(secs) = level.handshake_secs() {
                out.handshake_timeout = Duration::from_secs(u64::from(secs));
            }
        }
        out
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vless/policy.rs"]
mod tests;
