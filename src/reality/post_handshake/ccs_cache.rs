//! Cache for proactive REALITY extra-CCS tolerance probes (Stage 5C).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;

use super::cache::PostHandshakeProbeKey;
use super::tolerance::UselessRecordTolerance;

/// Cache entry state for a CCS tolerance probe key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcsToleranceProbeState {
    Detecting,
    Ready(UselessRecordTolerance),
}

impl CcsToleranceProbeState {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    pub fn ready_tolerance(&self) -> Option<UselessRecordTolerance> {
        match self {
            Self::Ready(tolerance) => Some(*tolerance),
            Self::Detecting => None,
        }
    }
}

#[derive(Debug, Default)]
struct CacheInner {
    entries: HashMap<PostHandshakeProbeKey, CcsToleranceProbeState>,
    waiters: HashMap<PostHandshakeProbeKey, Arc<Notify>>,
    started_probe_count: usize,
}

/// Process-wide cache for extra-CCS tolerance probe results.
#[derive(Debug, Clone, Default)]
pub struct CcsToleranceProbeCache {
    inner: Arc<Mutex<CacheInner>>,
}

impl CcsToleranceProbeCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_inner(&self) -> MutexGuard<'_, CacheInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn get(&self, key: &PostHandshakeProbeKey) -> Option<CcsToleranceProbeState> {
        self.lock_inner().entries.get(key).cloned()
    }

    /// Effective tolerance for runtime lookup: default `Finite(32)` when absent or still detecting.
    pub fn effective_tolerance(&self, key: &PostHandshakeProbeKey) -> UselessRecordTolerance {
        match self.get(key) {
            Some(CcsToleranceProbeState::Ready(tolerance)) => tolerance,
            Some(CcsToleranceProbeState::Detecting) | None => UselessRecordTolerance::DEFAULT,
        }
    }

    /// Atomically begins detection for `key`.
    ///
    /// Returns `true` only for the caller that should spawn the probe task.
    pub fn try_begin_detection(&self, key: PostHandshakeProbeKey) -> bool {
        let mut inner = self.lock_inner();
        use std::collections::hash_map::Entry;
        match inner.entries.entry(key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(CcsToleranceProbeState::Detecting);
                inner.started_probe_count += 1;
                true
            }
        }
    }

    pub fn complete_detection(
        &self,
        key: &PostHandshakeProbeKey,
        tolerance: UselessRecordTolerance,
    ) {
        let mut inner = self.lock_inner();
        inner
            .entries
            .insert(key.clone(), CcsToleranceProbeState::Ready(tolerance));
        Self::notify_waiters(&mut inner, key);
    }

    /// Marks probe failure using upstream-compatible fallback (`Finite(32)`).
    pub fn complete_detection_failed(&self, key: &PostHandshakeProbeKey) {
        self.complete_detection(key, UselessRecordTolerance::DEFAULT);
    }

    fn notify_waiters(inner: &mut CacheInner, key: &PostHandshakeProbeKey) {
        if let Some(notify) = inner.waiters.remove(key) {
            notify.notify_waiters();
        }
    }

    fn waiter_notify(inner: &mut CacheInner, key: &PostHandshakeProbeKey) -> Arc<Notify> {
        inner
            .waiters
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Waits until `key` is `Ready`, the timeout elapses, or the key was never started.
    pub async fn wait_for_ready_tolerance(
        &self,
        key: &PostHandshakeProbeKey,
        timeout: Duration,
    ) -> UselessRecordTolerance {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.get(key) {
                Some(CcsToleranceProbeState::Ready(tolerance)) => return tolerance,
                Some(CcsToleranceProbeState::Detecting) => {}
                None => return UselessRecordTolerance::DEFAULT,
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return UselessRecordTolerance::DEFAULT;
            }

            let notify = {
                let mut inner = self.lock_inner();
                Self::waiter_notify(&mut inner, key)
            };

            tokio::select! {
                () = tokio::time::sleep(remaining) => return UselessRecordTolerance::DEFAULT,
                () = notify.notified() => {}
            }
        }
    }

    pub fn started_probe_count(&self) -> usize {
        self.lock_inner().started_probe_count
    }
}

/// Ensures a started CCS tolerance probe always completes the cache (failure → `Finite(32)`).
pub struct CcsToleranceProbeCompletionGuard {
    cache: CcsToleranceProbeCache,
    key: PostHandshakeProbeKey,
    completed: bool,
}

impl CcsToleranceProbeCompletionGuard {
    pub fn new(cache: CcsToleranceProbeCache, key: PostHandshakeProbeKey) -> Self {
        Self {
            cache,
            key,
            completed: false,
        }
    }

    pub fn key(&self) -> &PostHandshakeProbeKey {
        &self.key
    }

    pub fn complete_with(&mut self, tolerance: UselessRecordTolerance) {
        self.cache.complete_detection(&self.key, tolerance);
        self.completed = true;
    }

    pub fn complete_failed(&mut self) {
        self.cache.complete_detection_failed(&self.key);
        self.completed = true;
    }
}

impl Drop for CcsToleranceProbeCompletionGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.cache.complete_detection_failed(&self.key);
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/ccs_cache.rs"]
mod tests;
