use std::num::{NonZeroI64, NonZeroU64};
use std::time::{Duration, Instant};

use tokio::time::sleep;

use crate::config::LimitFallback;

const RATE_MARGIN: f64 = 0.01;
const MAX_QUANTUM: i64 = 1_i64 << 50;
const NANOS_PER_SEC: u128 = 1_000_000_000;

pub(super) trait RateLimitClock {
    fn now(&self) -> Instant;
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SystemClock;

impl RateLimitClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Per-direction REALITY fallback limiter state (upstream `RatelimitedConn` semantics).
#[derive(Debug)]
pub(super) struct DirectionalLimiter<C: RateLimitClock = SystemClock> {
    after: i64,
    bucket: Option<JujuBucket<C>>,
}

impl DirectionalLimiter<SystemClock> {
    pub(super) fn new(limit: LimitFallback) -> Self {
        Self::new_with_clock(limit, SystemClock)
    }

    /// Applies the post-read wait. Reads crossing `afterBytes` remain entirely free.
    pub(super) async fn after_read(&mut self, n: usize) {
        let wait = self.wait_after_read(n);
        if !wait.is_zero() {
            sleep(wait).await;
        }
    }
}

impl<C: RateLimitClock> DirectionalLimiter<C> {
    fn new_with_clock(limit: LimitFallback, clock: C) -> Self {
        let Some(rate) = NonZeroU64::new(limit.bytes_per_sec) else {
            return Self {
                after: 0,
                bucket: None,
            };
        };

        // Upstream converts the uint64 capacity to int64. Clamping avoids a production panic for
        // extreme JSON values while preserving the full positive int64 range and normal behavior.
        let capacity = limit.effective_burst_capacity().min(i64::MAX as u64) as i64;
        let Some(capacity) = NonZeroI64::new(capacity) else {
            return Self {
                after: 0,
                bucket: None,
            };
        };

        Self {
            after: limit.after_counter(),
            bucket: Some(JujuBucket::new_with_rate(rate, capacity, clock)),
        }
    }

    fn wait_after_read(&mut self, n: usize) -> Duration {
        let Some(bucket) = self.bucket.as_mut() else {
            return Duration::ZERO;
        };
        if n == 0 {
            return Duration::ZERO;
        }

        let n = i64::try_from(n).unwrap_or(i64::MAX);
        if self.after > 0 {
            // `after` starts positive and `n` is at most i64::MAX, so this cannot overflow.
            self.after -= n;
            Duration::ZERO
        } else {
            bucket.take(n)
        }
    }

    #[cfg(test)]
    fn is_disabled(&self) -> bool {
        self.bucket.is_none()
    }
}

/// Single-owner subset of juju/ratelimit v1.0.2 used by one relay direction.
#[derive(Debug)]
struct JujuBucket<C: RateLimitClock> {
    clock: C,
    start_time: Instant,
    capacity: i128,
    quantum: i128,
    fill_interval: Duration,
    available_tokens: i128,
    latest_tick: u128,
}

impl<C: RateLimitClock> JujuBucket<C> {
    fn new_with_rate(rate: NonZeroU64, capacity: NonZeroI64, clock: C) -> Self {
        let (fill_interval, quantum) = juju_rate_parameters(rate);
        let capacity = i128::from(capacity.get());
        Self {
            start_time: clock.now(),
            clock,
            capacity,
            quantum: i128::from(quantum),
            fill_interval,
            available_tokens: capacity,
            latest_tick: 0,
        }
    }

    /// Non-blocking take; returns the juju-compatible wait for an irrevocable request.
    fn take(&mut self, count: i64) -> Duration {
        if count <= 0 {
            return Duration::ZERO;
        }

        let now = self.clock.now();
        let elapsed = now.saturating_duration_since(self.start_time);
        let tick = duration_nanos(elapsed) / duration_nanos(self.fill_interval);
        self.adjust_available_tokens(tick);

        let available = self.available_tokens.saturating_sub(i128::from(count));
        if available >= 0 {
            self.available_tokens = available;
            return Duration::ZERO;
        }

        let missing = available.unsigned_abs();
        let quantum = self.quantum as u128;
        let ticks_needed = missing.div_ceil(quantum);
        let end_tick = tick.saturating_add(ticks_needed);
        let end_nanos = end_tick.saturating_mul(duration_nanos(self.fill_interval));
        let wait_nanos = end_nanos.saturating_sub(duration_nanos(elapsed));

        self.available_tokens = available;
        duration_from_nanos_saturating(wait_nanos)
    }

    fn adjust_available_tokens(&mut self, tick: u128) {
        let elapsed_ticks = tick.saturating_sub(self.latest_tick);
        self.latest_tick = tick;
        if self.available_tokens >= self.capacity || elapsed_ticks == 0 {
            return;
        }

        let refill = elapsed_ticks.saturating_mul(self.quantum as u128);
        let refill = i128::try_from(refill).unwrap_or(i128::MAX);
        self.available_tokens = self
            .available_tokens
            .saturating_add(refill)
            .min(self.capacity);
    }

    #[cfg(test)]
    fn capacity(&self) -> i64 {
        self.capacity as i64
    }

    #[cfg(test)]
    fn available(&mut self) -> i128 {
        let elapsed = self.clock.now().saturating_duration_since(self.start_time);
        let tick = duration_nanos(elapsed) / duration_nanos(self.fill_interval);
        self.adjust_available_tokens(tick);
        self.available_tokens
    }
}

fn juju_rate_parameters(rate: NonZeroU64) -> (Duration, i64) {
    let requested_rate = rate.get() as f64;
    let mut quantum = 1_i64;

    while quantum < MAX_QUANTUM {
        // This is the same truncating float calculation as juju/ratelimit v1.0.2.
        let fill_nanos = (1e9_f64 * quantum as f64 / requested_rate) as u64;
        if fill_nanos != 0 {
            let fill_interval = Duration::from_nanos(fill_nanos);
            let actual_rate = 1e9_f64 * quantum as f64 / fill_nanos as f64;
            if (actual_rate - requested_rate).abs() / requested_rate <= RATE_MARGIN {
                return (fill_interval, quantum);
            }
        }
        quantum = next_quantum(quantum);
    }

    // Every positive u64 rate has a representable solution below MAX_QUANTUM. Keep a safe
    // non-panicking fallback in case future numeric behavior violates that invariant.
    (Duration::from_nanos(1), MAX_QUANTUM - 1)
}

fn next_quantum(quantum: i64) -> i64 {
    let mut next = quantum * 11 / 10;
    if next == quantum {
        next += 1;
    }
    next
}

fn duration_nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

fn duration_from_nanos_saturating(nanos: u128) -> Duration {
    let seconds = nanos / NANOS_PER_SEC;
    if seconds > u128::from(u64::MAX) {
        return Duration::MAX;
    }
    Duration::new(seconds as u64, (nanos % NANOS_PER_SEC) as u32)
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/rate_limit.rs"]
mod tests;
