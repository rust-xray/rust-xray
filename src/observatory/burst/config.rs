use std::time::Duration;

use crate::config::xray::raw::{BurstObservatoryConfig, HealthPingJsonConfig};
use crate::observatory::parse_xray_duration;

use super::health_ping::{
    sample_validity, sampling_period, DEFAULT_BURST_DESTINATION, DEFAULT_BURST_HTTP_METHOD,
    DEFAULT_BURST_INTERVAL, DEFAULT_BURST_SAMPLING, DEFAULT_BURST_TIMEOUT, MIN_BURST_INTERVAL,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstObservatoryRuntimeConfig {
    pub subject_selector: Vec<String>,
    pub ping: HealthPingRuntimeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPingRuntimeConfig {
    pub destination: String,
    pub connectivity: String,
    pub interval: Duration,
    pub sampling_count: u32,
    pub timeout: Duration,
    pub http_method: String,
    pub validity: Duration,
    pub scheduler_period: Duration,
}

impl BurstObservatoryRuntimeConfig {
    pub fn from_raw(raw: &BurstObservatoryConfig) -> Result<Self, std::io::Error> {
        let ping_raw = raw.ping_config.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "BurstObservatory requires a valid pingConfig",
            )
        })?;
        Ok(Self {
            subject_selector: raw.subject_selector.clone(),
            ping: HealthPingRuntimeConfig::from_raw(ping_raw)?,
        })
    }

    pub fn for_test(subject_selector: Vec<String>, ping: HealthPingRuntimeConfig) -> Self {
        Self {
            subject_selector,
            ping,
        }
    }
}

impl HealthPingRuntimeConfig {
    pub fn from_raw(raw: &HealthPingJsonConfig) -> Result<Self, std::io::Error> {
        let http_method = raw
            .http_method
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_BURST_HTTP_METHOD)
            .to_string();
        let destination = raw
            .destination
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_BURST_DESTINATION)
            .to_string();
        let connectivity = raw
            .connectivity
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();

        let mut interval = raw
            .interval
            .as_deref()
            .map(parse_xray_duration)
            .filter(|value| !value.is_zero())
            .unwrap_or(DEFAULT_BURST_INTERVAL);
        if interval < MIN_BURST_INTERVAL {
            interval = MIN_BURST_INTERVAL;
        }

        let sampling_raw = raw.sampling.or(raw.sampling_count).unwrap_or(0);
        let sampling_count = normalize_sampling_count(sampling_raw);

        let timeout = raw
            .timeout
            .as_deref()
            .map(parse_xray_duration)
            .filter(|value| !value.is_zero())
            .unwrap_or(DEFAULT_BURST_TIMEOUT);

        let scheduler_period = sampling_period(interval, sampling_count)
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
        let validity = sample_validity(interval, sampling_count)
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;

        Ok(Self {
            destination,
            connectivity,
            interval,
            sampling_count,
            timeout,
            http_method,
            validity,
            scheduler_period,
        })
    }

    pub fn for_test(
        destination: impl Into<String>,
        connectivity: impl Into<String>,
        interval: Duration,
        sampling_count: u32,
        timeout: Duration,
        http_method: impl Into<String>,
    ) -> Self {
        let interval = if interval.is_zero() {
            DEFAULT_BURST_INTERVAL
        } else if interval < MIN_BURST_INTERVAL {
            MIN_BURST_INTERVAL
        } else {
            interval
        };
        let sampling_count = normalize_sampling_count(sampling_count as i32);
        let scheduler_period =
            sampling_period(interval, sampling_count).expect("test sampling period");
        let validity = sample_validity(interval, sampling_count).expect("test validity");
        Self {
            destination: destination.into(),
            connectivity: connectivity.into(),
            interval,
            sampling_count,
            timeout,
            http_method: http_method.into(),
            validity,
            scheduler_period,
        }
    }
}

fn normalize_sampling_count(raw: i32) -> u32 {
    if raw <= 0 {
        DEFAULT_BURST_SAMPLING
    } else {
        raw as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_requires_ping_config() {
        let err = BurstObservatoryRuntimeConfig::from_raw(&BurstObservatoryConfig {
            subject_selector: vec!["proxy-".to_string()],
            ping_config: None,
        })
        .expect_err("missing ping config");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn burst_default_settings() {
        let config = HealthPingRuntimeConfig::from_raw(&HealthPingJsonConfig {
            destination: None,
            connectivity: None,
            interval: None,
            sampling: None,
            sampling_count: None,
            timeout: None,
            http_method: None,
        })
        .expect("defaults");
        assert_eq!(config.destination, DEFAULT_BURST_DESTINATION);
        assert_eq!(config.http_method, DEFAULT_BURST_HTTP_METHOD);
        assert_eq!(config.interval, DEFAULT_BURST_INTERVAL);
        assert_eq!(config.sampling_count, DEFAULT_BURST_SAMPLING);
        assert_eq!(config.timeout, DEFAULT_BURST_TIMEOUT);
    }

    #[test]
    fn burst_interval_is_clamped_to_10s() {
        let config = HealthPingRuntimeConfig::from_raw(&HealthPingJsonConfig {
            destination: None,
            connectivity: None,
            interval: Some("1s".to_string()),
            sampling: Some(1),
            sampling_count: None,
            timeout: None,
            http_method: None,
        })
        .expect("clamp");
        assert_eq!(config.interval, MIN_BURST_INTERVAL);
    }

    #[test]
    fn burst_duration_units() {
        let config = HealthPingRuntimeConfig::from_raw(&HealthPingJsonConfig {
            destination: None,
            connectivity: None,
            interval: Some("30s".to_string()),
            sampling: Some(3),
            sampling_count: None,
            timeout: Some("5s".to_string()),
            http_method: None,
        })
        .expect("duration parse");
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.scheduler_period, Duration::from_secs(90));
        assert_eq!(config.validity, Duration::from_secs(180));
    }
}
