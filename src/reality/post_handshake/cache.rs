//! Shared cache for proactive REALITY post-handshake record-length detection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;

use super::alpn::RealityAlpnProfile;
use super::validation::sanitize_post_handshake_wire_lengths;

/// Typed cache key for post-handshake record-length probes.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PostHandshakeProbeKey {
    pub dest_addr: String,
    pub server_name: String,
    pub alpn_profile: RealityAlpnProfile,
}

/// Cache entry state for a probe key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostHandshakeProbeState {
    Detecting,
    /// Completed detection. An empty vector means the probe finished and found no records.
    Ready(Vec<usize>),
}

impl PostHandshakeProbeState {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    pub fn ready_lengths(&self) -> Option<&[usize]> {
        match self {
            Self::Ready(lengths) => Some(lengths.as_slice()),
            Self::Detecting => None,
        }
    }
}

#[derive(Debug, Default)]
struct CacheInner {
    entries: HashMap<PostHandshakeProbeKey, PostHandshakeProbeState>,
    waiters: HashMap<PostHandshakeProbeKey, Arc<Notify>>,
    started_probe_count: usize,
}

/// Process-wide cache for post-handshake probe results.
#[derive(Debug, Clone, Default)]
pub struct PostHandshakeProbeCache {
    inner: Arc<Mutex<CacheInner>>,
}

impl PostHandshakeProbeCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_inner(&self) -> MutexGuard<'_, CacheInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns the current state for `key`, if any.
    pub fn get(&self, key: &PostHandshakeProbeKey) -> Option<PostHandshakeProbeState> {
        self.lock_inner().entries.get(key).cloned()
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
                entry.insert(PostHandshakeProbeState::Detecting);
                inner.started_probe_count += 1;
                true
            }
        }
    }

    /// Marks `key` complete with observed wire record lengths (empty vector is valid).
    pub fn complete_detection(&self, key: &PostHandshakeProbeKey, wire_lengths: Vec<usize>) {
        let sanitized = sanitize_post_handshake_wire_lengths(wire_lengths);
        let mut inner = self.lock_inner();
        inner
            .entries
            .insert(key.clone(), PostHandshakeProbeState::Ready(sanitized));
        Self::notify_waiters(&mut inner, key);
    }

    /// Marks `key` complete with an empty result after probe failure.
    pub fn complete_detection_empty(&self, key: &PostHandshakeProbeKey) {
        self.complete_detection(key, Vec::new());
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
    pub async fn wait_for_ready_wire_lengths(
        &self,
        key: &PostHandshakeProbeKey,
        timeout: Duration,
    ) -> Vec<usize> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.get(key) {
                Some(PostHandshakeProbeState::Ready(lengths)) => return lengths,
                Some(PostHandshakeProbeState::Detecting) => {}
                None => return Vec::new(),
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Vec::new();
            }

            let notify = {
                let mut inner = self.lock_inner();
                Self::waiter_notify(&mut inner, key)
            };

            tokio::select! {
                () = tokio::time::sleep(remaining) => return Vec::new(),
                () = notify.notified() => {}
            }
        }
    }

    /// Returns how many probe tasks were actually started (for tests/diagnostics).
    pub fn started_probe_count(&self) -> usize {
        self.lock_inner().started_probe_count
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/cache.rs"]
mod tests;
