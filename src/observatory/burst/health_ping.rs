use std::time::{Duration, Instant};

pub const DEFAULT_BURST_DESTINATION: &str = "https://connectivitycheck.gstatic.com/generate_204";
pub const DEFAULT_BURST_HTTP_METHOD: &str = "HEAD";
pub const DEFAULT_BURST_INTERVAL: Duration = Duration::from_secs(60);
pub const MIN_BURST_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_BURST_SAMPLING: u32 = 10;
pub const DEFAULT_BURST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingSample {
    Untested,
    Failed,
    Success(Duration),
}

#[derive(Debug, Clone)]
struct PingSampleSlot {
    taken_at: Instant,
    sample: PingSample,
}

#[derive(Debug, Clone)]
pub struct HealthPingRing {
    capacity: usize,
    validity: Duration,
    idx: i32,
    slots: Vec<PingSampleSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPingStats {
    pub all: i64,
    pub fail: i64,
    pub average: Duration,
    pub deviation: Duration,
    pub max: Duration,
    pub min: Duration,
    pub alive: bool,
}

impl HealthPingRing {
    pub fn new(capacity: u32, validity: Duration) -> Self {
        let capacity = capacity.max(1) as usize;
        Self {
            capacity,
            validity,
            idx: -1,
            slots: Vec::new(),
        }
    }

    pub fn put_failed(&mut self, now: Instant) {
        self.put_sample(now, PingSample::Failed);
    }

    pub fn put_success(&mut self, now: Instant, rtt: Duration) {
        self.put_sample(now, PingSample::Success(rtt));
    }

    fn put_sample(&mut self, now: Instant, sample: PingSample) {
        if self.slots.is_empty() {
            self.slots = (0..self.capacity)
                .map(|_| PingSampleSlot {
                    taken_at: now,
                    sample: PingSample::Untested,
                })
                .collect();
            self.idx = -1;
        }
        self.idx = self.calc_index(1);
        self.slots[self.idx as usize].taken_at = now;
        self.slots[self.idx as usize].sample = sample;
    }

    pub fn statistics(&self, now: Instant) -> HealthPingStats {
        self.statistics_inner(now)
    }

    fn calc_index(&self, step: i32) -> i32 {
        let mut idx = self.idx + step;
        if idx >= self.capacity as i32 {
            idx %= self.capacity as i32;
        }
        idx
    }

    fn statistics_inner(&self, now: Instant) -> HealthPingStats {
        let mut stats = HealthPingStats {
            all: 0,
            fail: 0,
            average: Duration::ZERO,
            deviation: Duration::ZERO,
            max: Duration::ZERO,
            min: Duration::ZERO,
            alive: false,
        };
        if self.slots.is_empty() {
            return stats;
        }

        let mut sum = Duration::ZERO;
        let mut cnt = 0u32;
        let mut valid_rtts = Vec::new();
        for slot in &self.slots {
            match slot.sample {
                PingSample::Untested => continue,
                PingSample::Failed if now.duration_since(slot.taken_at) > self.validity => {
                    continue;
                }
                PingSample::Success(_) if now.duration_since(slot.taken_at) > self.validity => {
                    continue;
                }
                PingSample::Failed => {
                    stats.fail += 1;
                }
                PingSample::Success(rtt) => {
                    cnt += 1;
                    sum += rtt;
                    valid_rtts.push(rtt);
                    if stats.max < rtt {
                        stats.max = rtt;
                    }
                    if stats.min == Duration::ZERO || stats.min > rtt {
                        stats.min = rtt;
                    }
                }
            }
        }

        stats.all = i64::from(cnt) + stats.fail;
        if cnt == 0 {
            stats.min = Duration::ZERO;
            stats.alive = stats.all != stats.fail;
            return stats;
        }

        stats.average = sum / cnt;
        if cnt < 2 {
            stats.deviation = stats.average / 2;
        } else {
            let avg = stats.average.as_nanos() as f64;
            let mut variance = 0.0;
            for rtt in &valid_rtts {
                let diff = rtt.as_nanos() as f64 - avg;
                variance += diff * diff;
            }
            let std = (variance / f64::from(cnt)).sqrt();
            stats.deviation = Duration::from_nanos(std as u64);
        }
        stats.alive = stats.all != stats.fail;
        stats
    }
}

pub fn sampling_period(interval: Duration, sampling_count: u32) -> Result<Duration, String> {
    interval
        .checked_mul(sampling_count)
        .ok_or_else(|| "burst observatory interval * samplingCount overflow".to_string())
}

pub fn sample_validity(interval: Duration, sampling_count: u32) -> Result<Duration, String> {
    sampling_period(interval, sampling_count).map(|period| period.saturating_mul(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(capacity: u32) -> HealthPingRing {
        HealthPingRing::new(capacity, Duration::from_secs(3600))
    }

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn health_ping_ring_overwrites_oldest() {
        let mut ring = ring(3);
        let base = now();
        ring.put_success(base, Duration::from_millis(10));
        ring.put_success(base, Duration::from_millis(20));
        ring.put_success(base, Duration::from_millis(30));
        ring.put_success(base, Duration::from_millis(40));
        let stats = ring.statistics(base);
        assert_eq!(stats.all, 3);
        assert_eq!(stats.average, Duration::from_millis(30));
        assert_eq!(stats.min, Duration::from_millis(20));
        assert_eq!(stats.max, Duration::from_millis(40));
    }

    #[test]
    fn health_ping_counts_all_and_fail() {
        let mut ring = ring(4);
        let base = now();
        ring.put_success(base, Duration::from_millis(10));
        ring.put_failed(base);
        ring.put_success(base, Duration::from_millis(30));
        let stats = ring.statistics(base);
        assert_eq!(stats.all, 3);
        assert_eq!(stats.fail, 1);
        assert!(stats.alive);
    }

    #[test]
    fn health_ping_average_ignores_failures() {
        let mut ring = ring(3);
        let base = now();
        ring.put_success(base, Duration::from_millis(10));
        ring.put_failed(base);
        ring.put_success(base, Duration::from_millis(30));
        let stats = ring.statistics(base);
        assert_eq!(stats.all, 3);
        assert_eq!(stats.fail, 1);
        assert_eq!(stats.average, Duration::from_millis(20));
    }

    #[test]
    fn health_ping_single_sample_deviation_half_average() {
        let mut ring = ring(1);
        let base = now();
        ring.put_success(base, Duration::from_millis(20));
        let stats = ring.statistics(base);
        assert_eq!(stats.deviation, Duration::from_millis(10));
    }

    #[test]
    fn health_ping_population_deviation() {
        let mut ring = ring(4);
        let base = now();
        ring.put_success(base, Duration::from_millis(10));
        ring.put_success(base, Duration::from_millis(20));
        ring.put_failed(base);
        ring.put_success(base, Duration::from_millis(30));
        let stats = ring.statistics(base);
        assert_eq!(stats.all, 4);
        assert_eq!(stats.fail, 1);
        assert_eq!(stats.average, Duration::from_millis(20));
        let variance =
            ((10.0 - 20.0f64).powi(2) + (20.0 - 20.0f64).powi(2) + (30.0 - 20.0f64).powi(2)) / 3.0;
        let expected = Duration::from_nanos((variance.sqrt() * 1_000_000.0) as u64);
        assert!(
            (stats.deviation.as_nanos() as i64 - expected.as_nanos() as i64).abs() <= 1_000_000
        );
    }

    #[test]
    fn health_ping_expired_samples_ignored() {
        let mut ring = HealthPingRing::new(3, Duration::from_millis(50));
        let base = Instant::now();
        ring.put_success(base - Duration::from_millis(100), Duration::from_millis(10));
        ring.put_failed(base);
        let stats = ring.statistics(base);
        assert_eq!(stats.all, 1);
        assert_eq!(stats.fail, 1);
        assert_eq!(stats.average, Duration::ZERO);
    }

    #[test]
    fn health_ping_zero_success_samples() {
        let mut ring = ring(2);
        let base = now();
        ring.put_failed(base);
        ring.put_failed(base);
        let stats = ring.statistics(base);
        assert_eq!(stats.all, 2);
        assert_eq!(stats.fail, 2);
        assert_eq!(stats.average, Duration::ZERO);
        assert_eq!(stats.deviation, Duration::ZERO);
        assert!(!stats.alive);
    }
}
