use std::sync::Arc;
use std::sync::Barrier;

use crate::reality::{
    CcsToleranceProbeCache, CcsToleranceProbeCompletionGuard, CcsToleranceProbeState,
    PostHandshakeProbeKey, RealityAlpnProfile, UselessRecordTolerance,
};

fn sample_key(dest: &str, server_name: &str, alpn: RealityAlpnProfile) -> PostHandshakeProbeKey {
    PostHandshakeProbeKey {
        dest_addr: dest.to_string(),
        server_name: server_name.to_string(),
        alpn_profile: alpn,
    }
}

#[test]
fn empty_cache_effective_tolerance_is_default_thirty_two() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::None);
    assert_eq!(
        cache.effective_tolerance(&key),
        UselessRecordTolerance::Finite(32)
    );
}

#[test]
fn not_started_effective_tolerance_is_default_thirty_two() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::Http11);
    assert!(cache.get(&key).is_none());
    assert_eq!(
        cache.effective_tolerance(&key),
        UselessRecordTolerance::Finite(32)
    );
}

#[test]
fn detecting_effective_tolerance_is_default_thirty_two() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::H2);
    assert!(cache.try_begin_detection(key.clone()));
    assert_eq!(
        cache.effective_tolerance(&key),
        UselessRecordTolerance::Finite(32)
    );
}

#[test]
fn probe_failure_completes_to_finite_thirty_two() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "a.example", RealityAlpnProfile::None);

    assert!(cache.try_begin_detection(key.clone()));
    cache.complete_detection_failed(&key);

    assert_eq!(
        cache.get(&key),
        Some(CcsToleranceProbeState::Ready(
            UselessRecordTolerance::Finite(32)
        ))
    );
    assert_eq!(
        cache.effective_tolerance(&key),
        UselessRecordTolerance::Finite(32)
    );
}

#[test]
fn concurrent_begin_starts_one_detection() {
    let cache = Arc::new(CcsToleranceProbeCache::new());
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::Http11);
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let cache = Arc::clone(&cache);
        let key = key.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            cache.try_begin_detection(key)
        }));
    }

    let winners = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread join"))
        .filter(|started| *started)
        .count();

    assert_eq!(winners, 1);
    assert_eq!(cache.started_probe_count(), 1);
}

#[test]
fn drop_guard_completes_detecting_to_finite_thirty_two() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::None);
    assert!(cache.try_begin_detection(key.clone()));

    {
        let _guard = CcsToleranceProbeCompletionGuard::new(cache.clone(), key.clone());
        assert_eq!(cache.get(&key), Some(CcsToleranceProbeState::Detecting));
    }

    assert_eq!(
        cache.get(&key),
        Some(CcsToleranceProbeState::Ready(
            UselessRecordTolerance::Finite(32)
        ))
    );
}

#[test]
fn drop_guard_does_not_override_explicit_success() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::H2);
    assert!(cache.try_begin_detection(key.clone()));

    {
        let mut guard = CcsToleranceProbeCompletionGuard::new(cache.clone(), key.clone());
        guard.complete_with(UselessRecordTolerance::Unlimited);
    }

    assert_eq!(
        cache.get(&key),
        Some(CcsToleranceProbeState::Ready(
            UselessRecordTolerance::Unlimited
        ))
    );
}

#[test]
fn success_stores_probe_tier_result() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::Http11);
    assert!(cache.try_begin_detection(key.clone()));
    cache.complete_detection(&key, UselessRecordTolerance::Finite(16));

    assert_eq!(
        cache.effective_tolerance(&key),
        UselessRecordTolerance::Finite(16)
    );
}

#[tokio::test]
async fn wait_for_ready_returns_default_on_timeout_while_detecting() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::None);
    assert!(cache.try_begin_detection(key.clone()));

    let tolerance = cache
        .wait_for_ready_tolerance(&key, std::time::Duration::from_millis(50))
        .await;
    assert_eq!(tolerance, UselessRecordTolerance::Finite(32));
}

#[tokio::test]
async fn wait_for_ready_wakes_with_stored_tolerance() {
    let cache = CcsToleranceProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::H2);
    assert!(cache.try_begin_detection(key.clone()));

    let cache_clone = cache.clone();
    let key_clone = key.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cache_clone.complete_detection(&key_clone, UselessRecordTolerance::Finite(1));
    });

    let tolerance = cache
        .wait_for_ready_tolerance(&key, std::time::Duration::from_secs(2))
        .await;
    assert_eq!(tolerance, UselessRecordTolerance::Finite(1));
}
