use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

/// Refcount-based online IP map (Xray `stats.OnlineMap`).
#[derive(Debug)]
pub struct OnlineMap {
    entries: Mutex<HashMap<String, IpEntry>>,
    count: AtomicI64,
}

#[derive(Debug, Clone, Copy)]
struct IpEntry {
    ref_count: u32,
    last_seen: i64,
}

impl OnlineMap {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            count: AtomicI64::new(0),
        }
    }

    fn should_track_ip(ip: &str) -> bool {
        !ip.is_empty() && ip != "127.0.0.1" && ip != "[::1]" && ip != "::1"
    }

    pub fn add_ip(&self, ip: &str, now_unix: i64) {
        if !Self::should_track_ip(ip) {
            return;
        }
        let mut guard = self.entries.lock().expect("online map lock");
        if let Some(entry) = guard.get_mut(ip) {
            entry.ref_count = entry.ref_count.saturating_add(1);
            entry.last_seen = now_unix;
        } else {
            guard.insert(
                ip.to_string(),
                IpEntry {
                    ref_count: 1,
                    last_seen: now_unix,
                },
            );
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn remove_ip(&self, ip: &str) {
        if ip.is_empty() {
            return;
        }
        let mut guard = self.entries.lock().expect("online map lock");
        let Some(entry) = guard.get_mut(ip) else {
            return;
        };
        if entry.ref_count > 1 {
            entry.ref_count -= 1;
            return;
        }
        guard.remove(ip);
        self.count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn count(&self) -> i64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn for_each<F>(&self, mut visitor: F)
    where
        F: FnMut(&str, i64) -> bool,
    {
        let guard = self.entries.lock().expect("online map lock");
        for (ip, entry) in guard.iter() {
            if !visitor(ip, entry.last_seen) {
                break;
            }
        }
    }
}

impl Default for OnlineMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/stats/online_map.rs"]
mod tests;
