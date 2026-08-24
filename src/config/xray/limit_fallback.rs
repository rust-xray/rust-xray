use serde::Deserialize;

/// Xray-compatible REALITY fallback rate limit (`limitFallbackUpload` / `limitFallbackDownload`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
pub struct LimitFallback {
    #[serde(rename = "afterBytes", default)]
    pub after_bytes: u64,

    #[serde(rename = "bytesPerSec", default)]
    pub bytes_per_sec: u64,

    #[serde(rename = "burstBytesPerSec", default)]
    pub burst_bytes_per_sec: u64,
}

impl LimitFallback {
    /// Upstream REALITY disables the limiter when `bytesPerSec == 0`.
    pub(crate) fn is_disabled(self) -> bool {
        self.bytes_per_sec == 0
    }

    /// Effective bucket capacity: `max(burstBytesPerSec, bytesPerSec)`.
    pub(crate) fn effective_burst_capacity(self) -> u64 {
        self.burst_bytes_per_sec.max(self.bytes_per_sec)
    }

    /// Upstream `int64(limit.AfterBytes)` conversion (Go uint64→int64 bit pattern).
    pub(crate) fn after_counter(self) -> i64 {
        self.after_bytes as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        let limit = LimitFallback::default();
        assert!(limit.is_disabled());
        assert_eq!(limit.after_bytes, 0);
    }

    #[test]
    fn parses_partial_object() {
        let limit: LimitFallback = serde_json::from_value(serde_json::json!({
            "bytesPerSec": 100_000
        }))
        .expect("parse partial limit");
        assert_eq!(limit.bytes_per_sec, 100_000);
        assert_eq!(limit.after_bytes, 0);
        assert_eq!(limit.burst_bytes_per_sec, 0);
        assert_eq!(limit.effective_burst_capacity(), 100_000);
    }

    #[test]
    fn rejects_negative_bytes_per_sec() {
        let err = serde_json::from_value::<LimitFallback>(serde_json::json!({
            "bytesPerSec": -1
        }))
        .unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn after_bytes_overflow_matches_go_int64_cast() {
        let limit = LimitFallback {
            after_bytes: (i64::MAX as u64) + 1,
            bytes_per_sec: 1,
            burst_bytes_per_sec: 1,
        };
        assert!(limit.after_counter() <= 0);
    }
}
