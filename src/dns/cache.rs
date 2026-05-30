use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::dns::packet::DnsQuestionKey;

#[derive(Debug, Clone)]
pub struct CachedDnsResponse {
    pub raw_response: Vec<u8>,
    pub expires_at: Instant,
    pub original_ttl: Duration,
}

impl CachedDnsResponse {
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

#[derive(Debug)]
pub struct DnsCache {
    entries: Mutex<HashMap<DnsQuestionKey, CachedDnsResponse>>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn get(&self, key: &DnsQuestionKey) -> Option<CachedDnsResponse> {
        let mut guard = self.entries.lock().expect("dns cache lock");
        let entry = guard.get(key)?.clone();
        if entry.is_expired() {
            guard.remove(key);
            return None;
        }
        Some(entry)
    }

    pub fn insert(
        &self,
        key: DnsQuestionKey,
        raw_response: Vec<u8>,
        ttl: Duration,
    ) -> CachedDnsResponse {
        let entry = CachedDnsResponse {
            raw_response,
            expires_at: Instant::now() + ttl,
            original_ttl: ttl,
        };
        let mut guard = self.entries.lock().expect("dns cache lock");
        if guard.len() >= self.max_entries {
            guard.retain(|_, value| !value.is_expired());
            if guard.len() >= self.max_entries {
                guard.clear();
            }
        }
        guard.insert(key, entry.clone());
        entry
    }
}
