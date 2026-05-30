use std::time::Duration;

use tracing::{debug, warn};

pub const ENV_DNS_TIMEOUT_MS: &str = "RUST_XRAY_DNS_TIMEOUT_MS";
pub const ENV_MUX_DNS_TIMEOUT_MS: &str = "RUST_XRAY_MUX_DNS_TIMEOUT_MS";
pub const ENV_MUX_DNS_TOTAL_TIMEOUT_MS: &str = "RUST_XRAY_MUX_DNS_TOTAL_TIMEOUT_MS";
pub const ENV_DNS_MAX_RETRIES: &str = "RUST_XRAY_DNS_MAX_RETRIES";
pub const ENV_MUX_DNS_MAX_RETRIES: &str = "RUST_XRAY_MUX_DNS_MAX_RETRIES";
pub const ENV_MUX_DNS_UPSTREAM_MODE: &str = "RUST_XRAY_MUX_DNS_UPSTREAM_MODE";
pub const ENV_MUX_DNS_LEGACY_DIRECT: &str = "RUST_XRAY_DNS_LEGACY_MUX_DIRECT";

const DEFAULT_DNS_TIMEOUT_MS: u64 = 5000;
const DEFAULT_MUX_DNS_TIMEOUT_MS: u64 = 750;
const DEFAULT_MUX_DNS_TOTAL_TIMEOUT_MS: u64 = 1000;
const DEFAULT_DNS_MAX_RETRIES: usize = 1;
const DEFAULT_MUX_DNS_MAX_RETRIES: usize = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxDnsUpstreamMode {
    DestinationOnly,
    DestinationThenConfigFallback,
    RaceDestinationAndConfig,
}

impl MuxDnsUpstreamMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DestinationOnly => "destination_only",
            Self::DestinationThenConfigFallback => "fallback",
            Self::RaceDestinationAndConfig => "race",
        }
    }
}

impl Default for MuxDnsUpstreamMode {
    fn default() -> Self {
        Self::RaceDestinationAndConfig
    }
}

#[derive(Debug, Clone)]
pub struct DnsEngineOptions {
    pub default_timeout: Duration,
    pub mux_udp_dns_timeout: Duration,
    pub mux_udp_dns_total_timeout: Duration,
    pub max_retries: usize,
    pub mux_udp_dns_max_retries: usize,
    pub mux_dns_upstream_mode: MuxDnsUpstreamMode,
    pub cache_enabled: bool,
    pub cache_max_entries: usize,
    pub cache_min_ttl: Duration,
    pub cache_max_ttl: Duration,
}

impl Default for DnsEngineOptions {
    fn default() -> Self {
        Self::from_env()
    }
}

pub fn mux_dns_legacy_direct_enabled() -> bool {
    std::env::var(ENV_MUX_DNS_LEGACY_DIRECT)
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

pub fn log_mux_dns_startup_options() {
    let opts = DnsEngineOptions::from_env();
    debug!(
        mux_dns_upstream_mode = opts.mux_dns_upstream_mode.as_str(),
        mux_udp_dns_timeout_ms = opts.mux_udp_dns_timeout.as_millis(),
        mux_udp_dns_total_timeout_ms = opts.mux_udp_dns_total_timeout.as_millis(),
        mux_dns_legacy_direct = mux_dns_legacy_direct_enabled(),
        env_mux_dns_legacy_direct = ENV_MUX_DNS_LEGACY_DIRECT,
        "mux dns startup options"
    );
    if mux_dns_legacy_direct_enabled() {
        warn!("legacy mux direct DNS path enabled; DNS engine bypassed");
    }
}

impl DnsEngineOptions {
    /// Stable defaults for unit tests (ignores process env).
    pub fn for_test() -> Self {
        Self {
            default_timeout: Duration::from_millis(DEFAULT_DNS_TIMEOUT_MS),
            mux_udp_dns_timeout: Duration::from_millis(DEFAULT_MUX_DNS_TIMEOUT_MS),
            mux_udp_dns_total_timeout: Duration::from_millis(DEFAULT_MUX_DNS_TOTAL_TIMEOUT_MS),
            max_retries: DEFAULT_DNS_MAX_RETRIES,
            mux_udp_dns_max_retries: DEFAULT_MUX_DNS_MAX_RETRIES,
            mux_dns_upstream_mode: MuxDnsUpstreamMode::default(),
            cache_enabled: true,
            cache_max_entries: 4096,
            cache_min_ttl: Duration::from_secs(30),
            cache_max_ttl: Duration::from_secs(3600),
        }
    }

    pub fn from_env() -> Self {
        Self {
            default_timeout: parse_duration_ms_env(ENV_DNS_TIMEOUT_MS, DEFAULT_DNS_TIMEOUT_MS),
            mux_udp_dns_timeout: parse_duration_ms_env(
                ENV_MUX_DNS_TIMEOUT_MS,
                DEFAULT_MUX_DNS_TIMEOUT_MS,
            ),
            mux_udp_dns_total_timeout: parse_duration_ms_env(
                ENV_MUX_DNS_TOTAL_TIMEOUT_MS,
                DEFAULT_MUX_DNS_TOTAL_TIMEOUT_MS,
            ),
            max_retries: parse_usize_env(ENV_DNS_MAX_RETRIES, DEFAULT_DNS_MAX_RETRIES),
            mux_udp_dns_max_retries: parse_usize_env(
                ENV_MUX_DNS_MAX_RETRIES,
                DEFAULT_MUX_DNS_MAX_RETRIES,
            ),
            mux_dns_upstream_mode: parse_mux_dns_upstream_mode_env(ENV_MUX_DNS_UPSTREAM_MODE),
            cache_enabled: true,
            cache_max_entries: 4096,
            cache_min_ttl: Duration::from_secs(30),
            cache_max_ttl: Duration::from_secs(3600),
        }
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

fn parse_mux_dns_upstream_mode_env(var: &str) -> MuxDnsUpstreamMode {
    match std::env::var(var)
        .ok()
        .map(|raw| raw.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("destination_only") => MuxDnsUpstreamMode::DestinationOnly,
        Some("fallback") => MuxDnsUpstreamMode::DestinationThenConfigFallback,
        Some("race") => MuxDnsUpstreamMode::RaceDestinationAndConfig,
        _ => MuxDnsUpstreamMode::default(),
    }
}

fn parse_usize_env(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env test lock")
    }

    fn with_env_vars<F>(vars: &[(&str, Option<&str>)], f: F)
    where
        F: FnOnce(),
    {
        let _guard = env_lock();
        let keys: Vec<&str> = vars.iter().map(|(key, _)| *key).collect();
        let previous: Vec<(String, Option<String>)> = keys
            .iter()
            .map(|key| ((*key).to_string(), std::env::var(key).ok()))
            .collect();
        for (key, value) in vars {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        f();
        for (key, value) in previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn default_mux_upstream_mode_is_race() {
        assert_eq!(
            MuxDnsUpstreamMode::default(),
            MuxDnsUpstreamMode::RaceDestinationAndConfig
        );
        with_env_vars(&[(ENV_MUX_DNS_UPSTREAM_MODE, None)], || {
            let opts = DnsEngineOptions::from_env();
            assert_eq!(
                opts.mux_dns_upstream_mode,
                MuxDnsUpstreamMode::RaceDestinationAndConfig
            );
        });
    }

    #[test]
    fn default_mux_timeout_is_750ms() {
        with_env_vars(
            &[
                (ENV_DNS_TIMEOUT_MS, None),
                (ENV_MUX_DNS_TIMEOUT_MS, None),
                (ENV_MUX_DNS_TOTAL_TIMEOUT_MS, None),
                (ENV_DNS_MAX_RETRIES, None),
                (ENV_MUX_DNS_MAX_RETRIES, None),
                (ENV_MUX_DNS_UPSTREAM_MODE, None),
            ],
            || {
                let opts = DnsEngineOptions::from_env();
                assert_eq!(opts.default_timeout, Duration::from_millis(5000));
                assert_eq!(opts.mux_udp_dns_timeout, Duration::from_millis(750));
                assert_eq!(opts.mux_udp_dns_total_timeout, Duration::from_millis(1000));
                assert_eq!(opts.max_retries, 1);
                assert_eq!(opts.mux_udp_dns_max_retries, 0);
            },
        );
    }

    #[test]
    fn parse_mux_dns_timeout_env() {
        with_env_vars(&[(ENV_MUX_DNS_TIMEOUT_MS, Some("250"))], || {
            let opts = DnsEngineOptions::from_env();
            assert_eq!(opts.mux_udp_dns_timeout, Duration::from_millis(250));
        });
    }

    #[test]
    fn parse_mux_dns_total_timeout_env() {
        with_env_vars(&[(ENV_MUX_DNS_TOTAL_TIMEOUT_MS, Some("750"))], || {
            let opts = DnsEngineOptions::from_env();
            assert_eq!(opts.mux_udp_dns_total_timeout, Duration::from_millis(750));
        });
    }

    #[test]
    fn invalid_mux_dns_timeout_env_falls_back_to_default() {
        with_env_vars(&[(ENV_MUX_DNS_TIMEOUT_MS, Some("not-a-number"))], || {
            let opts = DnsEngineOptions::from_env();
            assert_eq!(opts.mux_udp_dns_timeout, Duration::from_millis(750));
        });
    }

    #[test]
    fn parse_dns_max_retries_env() {
        with_env_vars(&[(ENV_MUX_DNS_MAX_RETRIES, Some("2"))], || {
            let opts = DnsEngineOptions::from_env();
            assert_eq!(opts.mux_udp_dns_max_retries, 2);
        });
    }

    #[test]
    fn parse_mux_dns_upstream_mode_env() {
        with_env_vars(&[(ENV_MUX_DNS_UPSTREAM_MODE, Some("race"))], || {
            let opts = DnsEngineOptions::from_env();
            assert_eq!(
                opts.mux_dns_upstream_mode,
                MuxDnsUpstreamMode::RaceDestinationAndConfig
            );
        });
    }

    #[test]
    fn invalid_mux_dns_upstream_mode_env_falls_back_to_default() {
        with_env_vars(&[(ENV_MUX_DNS_UPSTREAM_MODE, Some("invalid"))], || {
            let opts = DnsEngineOptions::from_env();
            assert_eq!(
                opts.mux_dns_upstream_mode,
                MuxDnsUpstreamMode::RaceDestinationAndConfig
            );
        });
    }

    #[test]
    fn mux_dns_legacy_direct_false_by_default() {
        with_env_vars(&[(ENV_MUX_DNS_LEGACY_DIRECT, None)], || {
            assert!(!mux_dns_legacy_direct_enabled());
        });
    }

    #[test]
    fn mux_dns_legacy_direct_true_for_enabled_values() {
        for value in ["1", "true", "TRUE", "yes", "YES"] {
            with_env_vars(&[(ENV_MUX_DNS_LEGACY_DIRECT, Some(value))], || {
                assert!(mux_dns_legacy_direct_enabled(), "value={value}");
            });
        }
    }
}
