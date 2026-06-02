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

    /// Ensure a counter exists so QueryStats can discover it before traffic is recorded.
    pub fn ensure(&self, name: &str) {
        let _ = self.counter(name);
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
#[path = "../../tests/unit/stats/registry.rs"]
mod tests;
