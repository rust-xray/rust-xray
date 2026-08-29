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

#[test]
fn concurrent_add_and_reset_preserves_bytes_after_reset() {
    use std::sync::Arc;
    use std::thread;

    let registry = Arc::new(StatsRegistry::new());
    let name = "user>>>u@example.com>>>traffic>>>uplink";
    registry.ensure(name);

    let adders: Vec<_> = (0..4)
        .map(|_| {
            let registry = Arc::clone(&registry);
            thread::spawn(move || {
                for _ in 0..1_000 {
                    registry.add(name, 1);
                }
            })
        })
        .collect();

    let reset_value = registry.get(name, true).unwrap_or(0);
    for handle in adders {
        handle.join().expect("join adder");
    }
    let after = registry.get(name, false).unwrap();
    assert!(after >= 0);
    assert!(reset_value >= 0);
    assert_eq!(registry.get(name, false).unwrap(), after);
}
