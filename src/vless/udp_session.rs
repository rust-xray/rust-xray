use std::time::Duration;

/// Grace period after VLESS uplink EOF before ending downlink relay.
///
/// Mirrors Xray policy `downlinkOnly`: when the client closes the uplink, the inbound
/// waits this long for remaining UDP responses before terminating the association.
pub const ENV_VLESS_UDP_DOWNLINK_GRACE_MS: &str = "RUST_XRAY_VLESS_UDP_DOWNLINK_GRACE_MS";
const DEFAULT_VLESS_UDP_DOWNLINK_GRACE_MS: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlessUdpRelayOptions {
    pub downlink_grace_after_uplink_eof: Duration,
}

impl VlessUdpRelayOptions {
    pub fn from_env() -> Self {
        Self {
            downlink_grace_after_uplink_eof: parse_duration_ms_env(
                ENV_VLESS_UDP_DOWNLINK_GRACE_MS,
                DEFAULT_VLESS_UDP_DOWNLINK_GRACE_MS,
            ),
        }
    }

    /// Stable values for unit tests (ignores process env).
    pub fn for_test(downlink_grace_after_uplink_eof: Duration) -> Self {
        Self {
            downlink_grace_after_uplink_eof,
        }
    }
}

impl Default for VlessUdpRelayOptions {
    fn default() -> Self {
        Self::from_env()
    }
}

fn parse_duration_ms_env(var: &str, default_ms: u64) -> Duration {
    std::env::var(var)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(default_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_do_not_read_dns_timeout_env() {
        std::env::set_var("RUST_XRAY_DNS_TIMEOUT_MS", "999999");
        std::env::remove_var(ENV_VLESS_UDP_DOWNLINK_GRACE_MS);
        let opts = VlessUdpRelayOptions::from_env();
        assert_eq!(
            opts.downlink_grace_after_uplink_eof,
            Duration::from_millis(DEFAULT_VLESS_UDP_DOWNLINK_GRACE_MS)
        );
    }
}
