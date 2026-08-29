use std::time::Duration;

use crate::config::xray::raw::ObservatoryConfig;

pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_PROBE_URL: &str = "https://www.google.com/generate_204";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryRuntimeConfig {
    pub subject_selector: Vec<String>,
    pub probe_url: String,
    pub probe_interval: Duration,
    pub enable_concurrency: bool,
}

impl ObservatoryRuntimeConfig {
    pub fn from_raw(raw: &ObservatoryConfig) -> Self {
        Self {
            subject_selector: raw.subject_selector.clone(),
            probe_url: raw
                .probe_url
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(DEFAULT_PROBE_URL)
                .to_string(),
            probe_interval: raw
                .probe_interval
                .as_deref()
                .map(parse_probe_interval)
                .unwrap_or(DEFAULT_PROBE_INTERVAL),
            enable_concurrency: raw.enable_concurrency,
        }
    }

    pub fn for_test(
        subject_selector: Vec<String>,
        probe_url: impl Into<String>,
        probe_interval: Duration,
        enable_concurrency: bool,
    ) -> Self {
        Self {
            subject_selector,
            probe_url: probe_url.into(),
            probe_interval,
            enable_concurrency,
        }
    }
}

/// Parse Xray JSON duration strings (`time.ParseDuration` compatible).
pub fn parse_xray_duration(raw: &str) -> Duration {
    humantime_parse(raw).unwrap_or(Duration::ZERO)
}

/// Parse Xray JSON `probeInterval` strings (`time.ParseDuration` compatible).
pub fn parse_probe_interval(raw: &str) -> Duration {
    humantime_parse(raw).unwrap_or(DEFAULT_PROBE_INTERVAL)
}

type DurationUnit = fn(u64) -> Duration;

fn humantime_parse(raw: &str) -> Option<Duration> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }

    const UNITS: [(&str, DurationUnit); 10] = [
        ("ms", Duration::from_millis),
        ("us", Duration::from_micros),
        ("µs", Duration::from_micros),
        ("ns", Duration::from_nanos),
        ("s", Duration::from_secs),
        ("S", Duration::from_secs),
        ("m", |n| Duration::from_secs(n.saturating_mul(60))),
        ("M", |n| Duration::from_secs(n.saturating_mul(60))),
        ("h", |n| Duration::from_secs(n.saturating_mul(3600))),
        ("H", |n| Duration::from_secs(n.saturating_mul(3600))),
    ];
    for (suffix, to_duration) in UNITS {
        if let Some(number) = value.strip_suffix(suffix) {
            let number: u64 = number.trim().parse().ok()?;
            return Some(to_duration(number));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_probe_interval_accepts_xray_duration_strings() {
        assert_eq!(parse_probe_interval("500ms"), Duration::from_millis(500));
        assert_eq!(parse_probe_interval("10s"), Duration::from_secs(10));
    }
}
