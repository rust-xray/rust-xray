use std::cell::Cell;
use std::num::{NonZeroI64, NonZeroU64};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::config::LimitFallback;
use crate::proxy::rate_limit::{
    juju_rate_parameters, DirectionalLimiter, JujuBucket, RateLimitClock, RATE_MARGIN,
};

#[derive(Debug, Clone)]
struct FakeClock {
    now: Rc<Cell<Instant>>,
}

impl FakeClock {
    fn new() -> Self {
        Self {
            now: Rc::new(Cell::new(Instant::now())),
        }
    }

    fn advance(&self, duration: Duration) {
        self.now.set(self.now.get() + duration);
    }
}

impl RateLimitClock for FakeClock {
    fn now(&self) -> Instant {
        self.now.get()
    }
}

fn bucket(rate: u64, capacity: i64, clock: FakeClock) -> JujuBucket<FakeClock> {
    JujuBucket::new_with_rate(
        NonZeroU64::new(rate).expect("test rate is positive"),
        NonZeroI64::new(capacity).expect("test capacity is positive"),
        clock,
    )
}

fn limit(after_bytes: u64, bytes_per_sec: u64, burst_bytes_per_sec: u64) -> LimitFallback {
    LimitFallback {
        after_bytes,
        bytes_per_sec,
        burst_bytes_per_sec,
    }
}

fn limiter(config: LimitFallback) -> DirectionalLimiter<FakeClock> {
    DirectionalLimiter::new_with_clock(config, FakeClock::new())
}

#[test]
fn disabled_limiter_has_no_bucket_or_wait() {
    let mut limiter = limiter(limit(999, 0, 999));
    assert!(limiter.is_disabled());
    assert_eq!(limiter.wait_after_read(1024), Duration::ZERO);
}

#[test]
fn effective_burst_clamps_to_rate_and_bucket_starts_full() {
    let config = limit(0, 100, 10);
    assert_eq!(config.effective_burst_capacity(), 100);

    let mut bucket = bucket(100, 100, FakeClock::new());
    assert_eq!(bucket.capacity(), 100);
    assert_eq!(bucket.take(100), Duration::ZERO);
    assert_eq!(bucket.take(1), Duration::from_millis(10));
}

#[test]
fn after_zero_first_read_uses_initial_full_bucket() {
    let mut limiter = limiter(limit(0, 100, 100));
    assert_eq!(limiter.wait_after_read(100), Duration::ZERO);
    assert!(limiter.wait_after_read(1) > Duration::ZERO);
}

#[test]
fn positive_after_reads_are_free_until_next_read() {
    let mut limiter = limiter(limit(100, 100, 100));
    assert_eq!(limiter.wait_after_read(40), Duration::ZERO);
    assert_eq!(limiter.wait_after_read(40), Duration::ZERO);
    assert_eq!(limiter.wait_after_read(20), Duration::ZERO);
    assert_eq!(limiter.wait_after_read(100), Duration::ZERO);
    assert!(limiter.wait_after_read(1) > Duration::ZERO);
}

#[test]
fn crossing_read_is_entirely_unthrottled() {
    let mut limiter = limiter(limit(10, 100, 100));
    assert_eq!(limiter.wait_after_read(16), Duration::ZERO);
    assert_eq!(limiter.wait_after_read(100), Duration::ZERO);
    assert!(limiter.wait_after_read(1) > Duration::ZERO);
}

#[test]
fn large_read_creates_and_refills_token_debt() {
    let clock = FakeClock::new();
    let mut bucket = bucket(1000, 10, clock.clone());

    assert_eq!(bucket.take(25), Duration::from_millis(15));
    assert_eq!(bucket.available(), -15);
    clock.advance(Duration::from_millis(15));
    assert_eq!(bucket.available(), 0);
    assert_eq!(bucket.take(1), Duration::from_millis(1));
}

#[test]
fn idle_time_refills_only_to_capacity() {
    let clock = FakeClock::new();
    let mut bucket = bucket(1000, 10, clock.clone());

    assert_eq!(bucket.take(10), Duration::ZERO);
    clock.advance(Duration::from_millis(5));
    assert_eq!(bucket.available(), 5);
    clock.advance(Duration::from_secs(10));
    assert_eq!(bucket.available(), 10);
}

#[test]
fn upload_and_download_limiter_state_is_independent() {
    let mut upload = limiter(limit(0, 100, 100));
    let mut download = limiter(limit(0, 200, 200));

    assert_eq!(upload.wait_after_read(100), Duration::ZERO);
    assert!(upload.wait_after_read(1) > Duration::ZERO);
    assert_eq!(download.wait_after_read(200), Duration::ZERO);
}

#[test]
fn after_bytes_overflow_matches_go_int64_cast() {
    let mut limiter = limiter(limit((i64::MAX as u64) + 1, 100, 100));
    assert_eq!(limiter.wait_after_read(100), Duration::ZERO);
    assert!(limiter.wait_after_read(1) > Duration::ZERO);
}

#[test]
fn configured_after_bytes_is_not_reduced_by_initial_forward() {
    let mut limiter = limiter(limit(10_000, 100, 100));

    assert_eq!(limiter.wait_after_read(1_500), Duration::ZERO);
    assert_eq!(limiter.wait_after_read(8_500), Duration::ZERO);
    assert_eq!(limiter.wait_after_read(100), Duration::ZERO);
    assert!(limiter.wait_after_read(1) > Duration::ZERO);
}

#[test]
fn absolute_tick_above_u32_does_not_truncate_wait() {
    let clock = FakeClock::new();
    let mut bucket = bucket(1_000_000_000, 1, clock.clone());

    assert_eq!(bucket.take(1), Duration::ZERO);
    clock.advance(Duration::from_secs(5));
    assert_eq!(bucket.take(1), Duration::ZERO);
    assert_eq!(bucket.take(1), Duration::from_nanos(1));
}

#[test]
fn extreme_u64_rate_and_i64_sized_read_do_not_overflow() {
    let clock = FakeClock::new();
    let mut bucket = bucket(u64::MAX, i64::MAX, clock);

    assert_eq!(bucket.take(i64::MAX), Duration::ZERO);
    assert!(bucket.take(1) > Duration::ZERO);
}

#[test]
fn quantum_selection_stays_within_juju_rate_margin() {
    for rate in [1_u64, 100, 1_000_000_000, u64::MAX] {
        let (interval, quantum) =
            juju_rate_parameters(NonZeroU64::new(rate).expect("rate is positive"));
        assert!(!interval.is_zero());
        let actual = 1e9_f64 * quantum as f64 / interval.as_nanos() as f64;
        assert!((actual - rate as f64).abs() / rate as f64 <= RATE_MARGIN);
    }
}
