use std::sync::Arc;
use std::sync::Barrier;

use crate::reality::{
    PostHandshakeProbeCache, PostHandshakeProbeKey, PostHandshakeProbeState, RealityAlpnProfile,
};

fn sample_key(dest: &str, server_name: &str, alpn: RealityAlpnProfile) -> PostHandshakeProbeKey {
    PostHandshakeProbeKey {
        dest_addr: dest.to_string(),
        server_name: server_name.to_string(),
        alpn_profile: alpn,
    }
}

#[test]
fn one_key_starts_one_probe() {
    let cache = PostHandshakeProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::None);

    assert!(cache.try_begin_detection(key.clone()));
    assert!(!cache.try_begin_detection(key.clone()));
    assert_eq!(cache.started_probe_count(), 1);
    assert_eq!(cache.get(&key), Some(PostHandshakeProbeState::Detecting));
}

#[test]
fn concurrent_start_same_key_starts_one_probe() {
    let cache = Arc::new(PostHandshakeProbeCache::new());
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
fn success_empty_result_is_ready_not_absent() {
    let cache = PostHandshakeProbeCache::new();
    let key = sample_key("example.com:443", "a.example", RealityAlpnProfile::H2);

    assert!(cache.get(&key).is_none());
    assert!(cache.try_begin_detection(key.clone()));
    cache.complete_detection(&key, Vec::new());

    match cache.get(&key) {
        Some(PostHandshakeProbeState::Ready(lengths)) => assert!(lengths.is_empty()),
        other => panic!("expected Ready([]), got {other:?}"),
    }
}

#[test]
fn success_records_are_stored() {
    let cache = PostHandshakeProbeCache::new();
    let key = sample_key("example.com:443", "a.example", RealityAlpnProfile::None);

    assert!(cache.try_begin_detection(key.clone()));
    cache.complete_detection(&key, vec![100, 200, 300]);

    assert_eq!(
        cache.get(&key),
        Some(PostHandshakeProbeState::Ready(vec![100, 200, 300]))
    );
}

#[test]
fn failure_completes_to_empty_ready_state() {
    let cache = PostHandshakeProbeCache::new();
    let key = sample_key("example.com:443", "a.example", RealityAlpnProfile::Http11);

    assert!(cache.try_begin_detection(key.clone()));
    cache.complete_detection_empty(&key);

    match cache.get(&key) {
        Some(PostHandshakeProbeState::Ready(lengths)) => assert!(lengths.is_empty()),
        other => panic!("expected Ready([]), got {other:?}"),
    }
}

#[test]
fn different_alpn_profiles_are_distinct_keys() {
    let cache = PostHandshakeProbeCache::new();
    let dest = "example.com:443";
    let sni = "example.com";

    assert!(cache.try_begin_detection(sample_key(dest, sni, RealityAlpnProfile::None)));
    assert!(cache.try_begin_detection(sample_key(dest, sni, RealityAlpnProfile::Http11)));
    assert!(cache.try_begin_detection(sample_key(dest, sni, RealityAlpnProfile::H2)));
    assert_eq!(cache.started_probe_count(), 3);
}

#[test]
fn different_sni_are_distinct_keys() {
    let cache = PostHandshakeProbeCache::new();
    let dest = "example.com:443";

    assert!(cache.try_begin_detection(sample_key(dest, "a.example", RealityAlpnProfile::None)));
    assert!(cache.try_begin_detection(sample_key(dest, "b.example", RealityAlpnProfile::None)));
    assert_eq!(cache.started_probe_count(), 2);
}

#[test]
fn different_dest_are_distinct_keys() {
    let cache = PostHandshakeProbeCache::new();
    let sni = "example.com";

    assert!(cache.try_begin_detection(sample_key("a.example:443", sni, RealityAlpnProfile::None)));
    assert!(cache.try_begin_detection(sample_key("b.example:443", sni, RealityAlpnProfile::None)));
    assert_eq!(cache.started_probe_count(), 2);
}

#[tokio::test]
async fn wait_for_ready_returns_immediately_when_cache_ready() {
    let cache = PostHandshakeProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::Http11);
    cache.try_begin_detection(key.clone());
    cache.complete_detection(&key, vec![100, 200]);

    let lengths = cache
        .wait_for_ready_wire_lengths(&key, std::time::Duration::from_secs(1))
        .await;
    assert_eq!(lengths, vec![100, 200]);
}

#[tokio::test]
async fn wait_for_ready_wakes_when_detection_completes() {
    let cache = PostHandshakeProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::H2);
    assert!(cache.try_begin_detection(key.clone()));

    let cache_clone = cache.clone();
    let key_clone = key.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cache_clone.complete_detection(&key_clone, vec![128]);
    });

    let lengths = cache
        .wait_for_ready_wire_lengths(&key, std::time::Duration::from_secs(2))
        .await;
    assert_eq!(lengths, vec![128]);
}

#[tokio::test]
async fn wait_for_ready_times_out_to_empty_when_still_detecting() {
    let cache = PostHandshakeProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::None);
    assert!(cache.try_begin_detection(key.clone()));

    let lengths = cache
        .wait_for_ready_wire_lengths(&key, std::time::Duration::from_millis(100))
        .await;
    assert!(lengths.is_empty());
}

#[test]
fn complete_detection_sanitizes_invalid_lengths() {
    let cache = PostHandshakeProbeCache::new();
    let key = sample_key("example.com:443", "example.com", RealityAlpnProfile::None);
    cache.try_begin_detection(key.clone());
    cache.complete_detection(&key, vec![100, 5, 200]);

    match cache.get(&key) {
        Some(PostHandshakeProbeState::Ready(lengths)) => assert_eq!(lengths, vec![100, 200]),
        other => panic!("expected Ready, got {other:?}"),
    }
}
