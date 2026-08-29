use std::sync::{Arc, RwLock};

use crate::config::xray::raw::OutboundObject;
use crate::routing::health::{
    HealthPingObservation, OutboundHealthObservation, OutboundHealthProvider,
};

use super::*;

struct MockHealth {
    observations: RwLock<Result<Vec<OutboundHealthObservation>, String>>,
}

impl MockHealth {
    fn new(observations: Vec<OutboundHealthObservation>) -> Arc<Self> {
        Arc::new(Self {
            observations: RwLock::new(Ok(observations)),
        })
    }
}

impl OutboundHealthProvider for MockHealth {
    fn observations(&self) -> Result<Vec<OutboundHealthObservation>, String> {
        self.observations.read().expect("observations").clone()
    }
}

fn manager(tags: &[&str]) -> Arc<RuntimeOutboundManager> {
    let manager = RuntimeOutboundManager::new();
    for tag in tags {
        manager
            .register_startup_outbound(&OutboundObject {
                tag: Some((*tag).to_string()),
                protocol: Some("freedom".to_string()),
                extra: Default::default(),
            })
            .expect("outbound");
    }
    manager
}

fn observation(tag: &str, alive: bool, delay_ms: i64) -> OutboundHealthObservation {
    OutboundHealthObservation {
        outbound_tag: tag.to_string(),
        alive,
        delay_ms,
        health_ping: None,
    }
}

fn config(strategy: BalancerStrategy) -> BalancerConfig {
    BalancerConfig {
        tag: "balance".to_string(),
        selectors: vec!["proxy-".to_string()],
        strategy,
        fallback_tag: String::new(),
        least_load: None,
    }
}

#[test]
fn least_ping_selects_lowest_alive_observed_candidate_and_honors_override() {
    let health = MockHealth::new(vec![
        observation("proxy-dead", false, 1),
        observation("other", true, 2),
        observation("proxy-slow", true, 80),
        observation("proxy-fast", true, 12),
    ]);
    let balancer = Balancer::new(
        config(BalancerStrategy::LeastPing),
        manager(&["proxy-dead", "proxy-fast", "proxy-slow"]),
        Some(health),
    );
    assert_eq!(balancer.pick_outbound().expect("least ping"), "proxy-fast");
    assert_eq!(
        balancer.principle_targets().expect("principle"),
        vec!["proxy-fast"]
    );
    balancer.set_override_target("manual".to_string());
    assert_eq!(balancer.pick_outbound().expect("override"), "manual");
    balancer.set_override_target(String::new());
    assert_eq!(balancer.pick_outbound().expect("resumed"), "proxy-fast");
}

#[test]
fn least_ping_without_health_fails_safely_or_uses_configured_fallback() {
    let mut no_fallback = config(BalancerStrategy::LeastPing);
    let balancer = Balancer::new(no_fallback.clone(), manager(&["proxy-a"]), None);
    assert!(balancer.pick_outbound().is_err());

    no_fallback.fallback_tag = "fallback".to_string();
    let balancer = Balancer::new(no_fallback, manager(&["proxy-a", "fallback"]), None);
    assert_eq!(balancer.pick_outbound().expect("fallback"), "fallback");

    let health = MockHealth::new(vec![observation("proxy-a", false, 10)]);
    let mut with_fallback = config(BalancerStrategy::LeastPing);
    with_fallback.fallback_tag = "fallback".to_string();
    let balancer = Balancer::new(
        with_fallback,
        manager(&["proxy-a", "fallback"]),
        Some(health),
    );
    assert_eq!(balancer.pick_outbound().expect("fallback"), "fallback");
}

#[test]
fn least_load_applies_cost_max_rtt_tolerance_baseline_and_expected() {
    let health = MockHealth::new(vec![
        OutboundHealthObservation {
            outbound_tag: "proxy-cheap".to_string(),
            alive: true,
            delay_ms: 20,
            health_ping: Some(HealthPingObservation {
                average: 20_000_000,
                deviation: 10_000_000,
                all: 20,
                fail: 1,
            }),
        },
        OutboundHealthObservation {
            outbound_tag: "proxy-costly".to_string(),
            alive: true,
            delay_ms: 10,
            health_ping: Some(HealthPingObservation {
                average: 10_000_000,
                deviation: 6_000_000,
                all: 20,
                fail: 1,
            }),
        },
        OutboundHealthObservation {
            outbound_tag: "proxy-failing".to_string(),
            alive: true,
            delay_ms: 5,
            health_ping: Some(HealthPingObservation {
                average: 5_000_000,
                deviation: 1_000_000,
                all: 10,
                fail: 8,
            }),
        },
        observation("proxy-high-rtt", true, 500),
        observation("proxy-dead", false, 1),
    ]);
    let mut cfg = config(BalancerStrategy::LeastLoad);
    cfg.least_load = Some(LeastLoadConfig {
        costs: vec![StrategyWeight {
            matcher: "costly".to_string(),
            value: 9.0,
            compiled: None,
        }],
        baselines: vec![15_000_000],
        expected: 1,
        max_rtt: 100_000_000,
        tolerance: 0.5,
    });
    let balancer = Balancer::new(
        cfg,
        manager(&[
            "proxy-cheap",
            "proxy-costly",
            "proxy-failing",
            "proxy-high-rtt",
            "proxy-dead",
        ]),
        Some(health),
    );
    assert_eq!(
        balancer.principle_targets().expect("least load"),
        vec!["proxy-cheap"]
    );
    assert_eq!(balancer.pick_outbound().expect("pick"), "proxy-cheap");
}

#[test]
fn random_and_round_robin_use_sorted_live_dynamic_candidates() {
    let manager = manager(&["proxy-b", "proxy-a"]);
    let round_robin = Balancer::new(
        config(BalancerStrategy::RoundRobin),
        Arc::clone(&manager),
        None,
    );
    assert_eq!(round_robin.pick_outbound().expect("a"), "proxy-a");
    assert_eq!(round_robin.pick_outbound().expect("b"), "proxy-b");
    assert_eq!(round_robin.pick_outbound().expect("a"), "proxy-a");
    assert_eq!(round_robin.pick_outbound().expect("b"), "proxy-b");

    manager
        .register_startup_outbound(&OutboundObject {
            tag: Some("proxy-c".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("dynamic add");
    let random = Balancer::new(config(BalancerStrategy::Random), manager, None);
    for _ in 0..64 {
        assert!(["proxy-a", "proxy-b", "proxy-c"]
            .contains(&random.pick_outbound().expect("random").as_str()));
    }
}

#[test]
fn selector_prefix_matches_upstream_starts_with_semantics() {
    let manager = manager(&["proxy-a", "proxy-b", "proxy2-a", "direct"]);
    assert_eq!(
        manager.select_outbounds(&["proxy-".to_string()]),
        vec!["proxy-a", "proxy-b"]
    );
    assert_eq!(
        manager.select_outbounds(&["proxy2-".to_string()]),
        vec!["proxy2-a"]
    );
}

#[test]
fn random_principle_targets_return_all_candidates() {
    let manager = manager(&["proxy-b", "proxy-a"]);
    let random = Balancer::new(config(BalancerStrategy::Random), manager, None);
    assert_eq!(
        random.principle_targets().expect("principle"),
        vec!["proxy-a", "proxy-b"]
    );
}

#[test]
fn random_filters_dead_candidates_when_fallback_tag_is_set() {
    let health = MockHealth::new(vec![
        observation("candidate-a", false, 1),
        observation("candidate-b", true, 1),
    ]);
    let mut cfg = config(BalancerStrategy::Random);
    cfg.selectors = vec!["candidate-".to_string()];
    cfg.fallback_tag = "fallback".to_string();
    let balancer = Balancer::new(
        cfg,
        manager(&["candidate-a", "candidate-b", "candidate-c", "fallback"]),
        Some(health),
    );
    for _ in 0..32 {
        let picked = balancer.pick_outbound().expect("pick");
        assert!(picked == "candidate-b" || picked == "candidate-c");
    }
}

#[test]
fn random_returns_fallback_when_all_observed_candidates_are_dead() {
    let health = MockHealth::new(vec![
        observation("candidate-a", false, 1),
        observation("candidate-b", false, 1),
    ]);
    let mut cfg = config(BalancerStrategy::Random);
    cfg.selectors = vec!["candidate-".to_string()];
    cfg.fallback_tag = "fallback".to_string();
    let balancer = Balancer::new(
        cfg,
        manager(&["candidate-a", "candidate-b", "fallback"]),
        Some(health),
    );
    assert_eq!(balancer.pick_outbound().expect("fallback"), "fallback");
}

#[test]
fn round_robin_index_survives_dynamic_candidate_changes() {
    let manager = manager(&["proxy-a", "proxy-b"]);
    let round_robin = Balancer::new(
        config(BalancerStrategy::RoundRobin),
        Arc::clone(&manager),
        None,
    );
    assert_eq!(round_robin.pick_outbound().expect("a"), "proxy-a");
    manager
        .register_startup_outbound(&OutboundObject {
            tag: Some("proxy-c".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("add c");
    assert_eq!(round_robin.pick_outbound().expect("b"), "proxy-b");
    assert_eq!(round_robin.pick_outbound().expect("c"), "proxy-c");
}

#[test]
fn least_load_pick_is_member_of_principle_shortlist() {
    let health = MockHealth::new(vec![
        OutboundHealthObservation {
            outbound_tag: "proxy-a".to_string(),
            alive: true,
            delay_ms: 10,
            health_ping: Some(HealthPingObservation {
                average: 10_000_000,
                deviation: 10_000_000,
                all: 10,
                fail: 1,
            }),
        },
        OutboundHealthObservation {
            outbound_tag: "proxy-b".to_string(),
            alive: true,
            delay_ms: 12,
            health_ping: Some(HealthPingObservation {
                average: 12_000_000,
                deviation: 10_000_000,
                all: 10,
                fail: 1,
            }),
        },
    ]);
    let mut cfg = config(BalancerStrategy::LeastLoad);
    cfg.least_load = Some(LeastLoadConfig {
        costs: vec![],
        baselines: vec![],
        expected: 2,
        max_rtt: 0,
        tolerance: 0.0,
    });
    let balancer = Balancer::new(cfg, manager(&["proxy-a", "proxy-b"]), Some(health));
    let shortlist = balancer.principle_targets().expect("shortlist");
    assert_eq!(shortlist.len(), 2);
    for _ in 0..16 {
        let picked = balancer.pick_outbound().expect("pick");
        assert!(shortlist.contains(&picked));
    }
}
