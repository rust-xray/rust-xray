use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// One traffic counter (Xray `stats.Counter`).
#[derive(Debug)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn add(&self, delta: u64) {
        if delta > 0 {
            self.value.fetch_add(delta, Ordering::Relaxed);
        }
    }

    pub fn value(&self) -> i64 {
        self.value.load(Ordering::Relaxed) as i64
    }

    /// Returns the previous value and resets the counter to zero.
    pub fn reset(&self) -> i64 {
        self.value.swap(0, Ordering::Relaxed) as i64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatEntry {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetStatError {
    NotFound,
}

/// Thread-safe Xray-compatible stats registry.
#[derive(Debug, Default)]
pub struct StatsRegistry {
    counters: RwLock<BTreeMap<String, Arc<Counter>>>,
}

impl StatsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn counter(&self, name: &str) -> Arc<Counter> {
        let mut guard = self.counters.write().expect("stats registry lock");
        guard
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Counter::new()))
            .clone()
    }

    pub fn add(&self, name: &str, delta: u64) {
        if delta == 0 {
            return;
        }
        self.counter(name).add(delta);
    }

    pub fn get(&self, name: &str, reset: bool) -> Result<i64, GetStatError> {
        let guard = self.counters.read().expect("stats registry lock");
        let counter = guard.get(name).ok_or(GetStatError::NotFound)?;
        let value = if reset {
            counter.reset()
        } else {
            counter.value()
        };
        Ok(value)
    }

    pub fn query(&self, pattern: &str, reset: bool) -> Vec<StatEntry> {
        let guard = self.counters.read().expect("stats registry lock");
        let mut out = Vec::new();
        for (name, counter) in guard.iter() {
            if !name.contains(pattern) {
                continue;
            }
            let value = if reset {
                counter.reset()
            } else {
                counter.value()
            };
            out.push(StatEntry {
                name: name.clone(),
                value,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_and_reset_returns_previous_value() {
        let registry = StatsRegistry::new();
        registry.add("inbound>>>in>>>traffic>>>uplink", 42);
        assert_eq!(
            registry
                .get("inbound>>>in>>>traffic>>>uplink", false)
                .unwrap(),
            42
        );
        assert_eq!(
            registry
                .get("inbound>>>in>>>traffic>>>uplink", true)
                .unwrap(),
            42
        );
        assert_eq!(
            registry
                .get("inbound>>>in>>>traffic>>>uplink", false)
                .unwrap(),
            0
        );
    }

    #[test]
    fn get_missing_counter_is_not_found() {
        let registry = StatsRegistry::new();
        assert_eq!(registry.get("missing", false), Err(GetStatError::NotFound));
    }

    #[test]
    fn query_filters_by_substring_pattern() {
        let registry = StatsRegistry::new();
        registry.add("inbound>>>a>>>traffic>>>uplink", 1);
        registry.add("outbound>>>b>>>traffic>>>downlink", 2);
        let stats = registry.query("inbound>>>", false);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].name, "inbound>>>a>>>traffic>>>uplink");
        assert_eq!(stats[0].value, 1);
    }

    #[test]
    fn query_empty_pattern_matches_all() {
        let registry = StatsRegistry::new();
        registry.add("user>>>u@example.com>>>traffic>>>uplink", 3);
        registry.add("user>>>u@example.com>>>traffic>>>downlink", 4);
        assert_eq!(registry.query("", false).len(), 2);
    }

    #[test]
    fn query_reset_clears_matched_counters() {
        let registry = StatsRegistry::new();
        registry.add("inbound>>>in>>>traffic>>>uplink", 10);
        registry.add("inbound>>>in>>>traffic>>>downlink", 20);
        let stats = registry.query("inbound>>>in", true);
        assert_eq!(stats.len(), 2);
        assert_eq!(
            registry
                .get("inbound>>>in>>>traffic>>>uplink", false)
                .unwrap(),
            0
        );
    }
}
