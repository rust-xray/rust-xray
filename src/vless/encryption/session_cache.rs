use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::config::TicketLifetimeRange;
use super::hybrid::PfsKey;

/// Upper bound on cached 0-RTT resume entries (upstream ticket slice initial capacity).
pub(crate) const MAX_STORED_SESSIONS: usize = 1024;

/// Invalid-ticket noise length bounds (upstream `crypto.RandBetween(1279, 2279)`).
pub(crate) const INVALID_TICKET_NOISE_MIN: usize = 1279;
pub(crate) const INVALID_TICKET_NOISE_MAX: usize = 2279;

/// Replay detection key: NFS relay shared secret from the current 0-RTT hello.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct ReplayKey([u8; 32]);

impl ReplayKey {
    pub(crate) fn from_nfs_key(nfs_key: &[u8; 32]) -> Self {
        Self(*nfs_key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionLookupError {
    UnknownSession,
    ExpiredSession,
    ReplayDetected,
    ResumeNotAllowed,
}

struct StoredSession {
    pfs_key: PfsKey,
    /// Strict expiry: resume allowed while `now < expires_at` (equality rejects).
    expires_at: Instant,
    replay_keys: HashSet<ReplayKey>,
}

struct SessionCacheInner {
    sessions: HashMap<[u8; 16], StoredSession>,
    tickets: Vec<[u8; 16]>,
    /// Minute bucket -> last ticket scheduled for expiry in that bucket.
    lasts: HashMap<i64, [u8; 16]>,
    last_prune_minute: Option<i64>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct MockCacheTime {
    pub instant: Instant,
    pub unix_secs: i64,
}

struct CacheTimeSource {
    #[cfg(test)]
    mock: Option<Arc<RwLock<MockCacheTime>>>,
}

impl CacheTimeSource {
    fn production() -> Self {
        Self {
            #[cfg(test)]
            mock: None,
        }
    }

    #[cfg(test)]
    fn mock(mock: Arc<RwLock<MockCacheTime>>) -> Self {
        Self { mock: Some(mock) }
    }

    fn instant(&self) -> Instant {
        #[cfg(test)]
        if let Some(mock) = &self.mock {
            return mock.read().expect("mock time lock").instant;
        }
        Instant::now()
    }

    fn unix_secs(&self) -> i64 {
        #[cfg(test)]
        if let Some(mock) = &self.mock {
            return mock.read().expect("mock time lock").unix_secs;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// Bounded inbound 0-RTT session store (upstream `ServerInstance.Sessions` + replay guard).
pub(crate) struct SessionCache {
    inner: Mutex<SessionCacheInner>,
    ticket_lifetime: TicketLifetimeRange,
    time: CacheTimeSource,
}

impl SessionCache {
    pub(crate) fn new(ticket_lifetime: TicketLifetimeRange) -> Self {
        Self {
            inner: Mutex::new(SessionCacheInner {
                sessions: HashMap::new(),
                tickets: Vec::new(),
                lasts: HashMap::new(),
                last_prune_minute: None,
            }),
            ticket_lifetime,
            time: CacheTimeSource::production(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_mock_time(
        ticket_lifetime: TicketLifetimeRange,
        mock: Arc<RwLock<MockCacheTime>>,
    ) -> Self {
        Self {
            inner: Mutex::new(SessionCacheInner {
                sessions: HashMap::new(),
                tickets: Vec::new(),
                lasts: HashMap::new(),
                last_prune_minute: None,
            }),
            ticket_lifetime,
            time: CacheTimeSource::mock(mock),
        }
    }

    pub(crate) fn allows_zero_rtt(&self) -> bool {
        self.ticket_lifetime.allows_zero_rtt()
    }

    /// Store resumable session material after successful 1-RTT when lifetime > 0.
    pub(crate) fn insert(&self, ticket: [u8; 16], pfs_key: PfsKey, ticket_lifetime_secs: u64) {
        if ticket_lifetime_secs == 0 || !self.allows_zero_rtt() {
            return;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let now_instant = self.time.instant();
        let now_unix = self.time.unix_secs();
        Self::prune_expired_locked(&mut guard, now_instant);
        Self::maybe_prune_minute_buckets_locked(&mut guard, now_unix);
        if guard.sessions.len() >= MAX_STORED_SESSIONS {
            Self::clear_locked(&mut guard);
        }
        let max_lifetime = self
            .ticket_lifetime
            .max_secs
            .max(self.ticket_lifetime.min_secs) as i64;
        let expire_minute = now_unix.saturating_add(max_lifetime) / 60 + 2;
        guard.lasts.insert(expire_minute, ticket);
        guard.tickets.push(ticket);
        guard.sessions.insert(
            ticket,
            StoredSession {
                pfs_key,
                expires_at: now_instant + Duration::from_secs(ticket_lifetime_secs.max(1)),
                replay_keys: HashSet::new(),
            },
        );
    }

    /// Lookup cached PFS material and atomically mark `(ticket, nfs_key)` as consumed.
    pub(crate) fn lookup_for_resume(
        &self,
        ticket: &[u8; 16],
        nfs_key: &[u8; 32],
    ) -> Result<PfsKey, SessionLookupError> {
        if !self.allows_zero_rtt() {
            return Err(SessionLookupError::ResumeNotAllowed);
        }
        let now_instant = self.time.instant();
        let now_unix = self.time.unix_secs();
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SessionLookupError::UnknownSession)?;
        Self::prune_expired_locked(&mut guard, now_instant);
        Self::maybe_prune_minute_buckets_locked(&mut guard, now_unix);
        let Some(session) = guard.sessions.get_mut(ticket) else {
            return Err(SessionLookupError::UnknownSession);
        };
        if session.expires_at <= now_instant {
            guard.sessions.remove(ticket);
            return Err(SessionLookupError::ExpiredSession);
        }
        let replay_key = ReplayKey::from_nfs_key(nfs_key);
        if !session.replay_keys.insert(replay_key) {
            return Err(SessionLookupError::ReplayDetected);
        }
        Ok(session.pfs_key.clone())
    }

    pub(crate) fn prune_expired(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            Self::prune_expired_locked(&mut guard, self.time.instant());
            Self::maybe_prune_minute_buckets_locked(&mut guard, self.time.unix_secs());
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|guard| guard.sessions.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn replay_key_count(&self, ticket: &[u8; 16]) -> usize {
        self.inner
            .lock()
            .ok()
            .and_then(|guard| guard.sessions.get(ticket).map(|s| s.replay_keys.len()))
            .unwrap_or(0)
    }

    fn prune_expired_locked(inner: &mut SessionCacheInner, now: Instant) {
        inner.sessions.retain(|_, entry| entry.expires_at > now);
    }

    fn maybe_prune_minute_buckets_locked(inner: &mut SessionCacheInner, now_unix: i64) {
        let minute = now_unix / 60;
        if inner.last_prune_minute == Some(minute) {
            return;
        }
        for bucket in [minute, minute - 1] {
            if let Some(last_ticket) = inner.lasts.remove(&bucket) {
                if last_ticket != [0u8; 16] {
                    Self::remove_tickets_up_to_locked(inner, &last_ticket);
                }
            }
        }
        inner.last_prune_minute = Some(minute);
    }

    fn remove_tickets_up_to_locked(inner: &mut SessionCacheInner, last_ticket: &[u8; 16]) {
        if let Some(index) = inner.tickets.iter().position(|t| t == last_ticket) {
            for ticket in inner.tickets.drain(0..=index) {
                inner.sessions.remove(&ticket);
            }
        }
    }

    fn clear_locked(inner: &mut SessionCacheInner) {
        inner.sessions.clear();
        inner.tickets.clear();
        inner.lasts.clear();
    }
}
