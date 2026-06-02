
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
