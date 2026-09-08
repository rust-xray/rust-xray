use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::config::xray::raw::{RoutingConfig, RoutingRuleObject};
use crate::dns::engine::DnsEngine;
use crate::routing::conditions::{
    AttributeMatcher, ConditionChain, DomainMatcher, RouteMatchState,
};
use crate::routing::{RouteContext, RuntimeRouter};
use crate::runtime::RuntimeOutboundManager;

fn freedom(tag: &str) -> crate::config::xray::raw::OutboundObject {
    crate::config::xray::raw::OutboundObject {
        tag: Some(tag.to_string()),
        protocol: Some("freedom".to_string()),
        extra: Default::default(),
    }
}

#[test]
fn normalized_domain_cached_across_repeated_access() {
    let mut ctx = RouteContext {
        target_domain: "Example.COM".to_string(),
        ..Default::default()
    };
    let mut state = RouteMatchState::new(&mut ctx, false);
    let first_ptr = {
        let first = state.normalized_target_domain();
        assert_eq!(first, "example.com");
        state.normalized_domain_ptr().expect("normalized domain")
    };
    for _ in 0..100 {
        assert_eq!(state.normalized_target_domain(), "example.com");
        assert_eq!(state.normalized_domain_ptr(), Some(first_ptr));
    }
}

#[test]
fn attribute_matcher_reuses_lowered_attributes_cache() {
    let mut ctx = RouteContext {
        attributes: HashMap::from([
            ("Protocol".to_string(), "tls".to_string()),
            ("Host".to_string(), "example.com".to_string()),
        ]),
        ..Default::default()
    };
    let matcher = AttributeMatcher::new(vec![
        ("protocol".to_string(), "tls".to_string()),
        ("host".to_string(), "example.com".to_string()),
    ])
    .expect("attribute matcher");
    let chain = ConditionChain::new(vec![Box::new(matcher)]);
    let mut state = RouteMatchState::new(&mut ctx, false);
    assert!(matches!(
        chain.evaluate(&mut state),
        crate::routing::conditions::ConditionResult::Match
    ));
    assert!(state.lowered_attributes_cached());
    for _ in 0..50 {
        assert!(matches!(
            chain.evaluate(&mut state),
            crate::routing::conditions::ConditionResult::Match
        ));
    }
    assert!(state.lowered_attributes_cached());
}

#[tokio::test]
async fn domain_normalization_once_across_many_nonmatching_rules() {
    let rules = (0..100)
        .map(|index| RoutingRuleObject {
            rule_type: Some("field".to_string()),
            outbound_tag: Some(format!("out-{index}")),
            extra: BTreeMap::from([(
                "domain".to_string(),
                serde_json::json!([format!("full:miss-{index}.example")]),
            )]),
            ..Default::default()
        })
        .chain([RoutingRuleObject {
            rule_type: Some("field".to_string()),
            outbound_tag: Some("hit".to_string()),
            extra: BTreeMap::from([(
                "domain".to_string(),
                serde_json::json!(["full:target.example"]),
            )]),
            ..Default::default()
        }])
        .collect();
    let outbound = RuntimeOutboundManager::new();
    for index in 0..100 {
        let tag = format!("out-{index}");
        outbound
            .register_startup_outbound(&freedom(&tag))
            .expect("outbound");
    }
    outbound
        .register_startup_outbound(&freedom("hit"))
        .expect("outbound");
    let router = RuntimeRouter::new(
        Some(&RoutingConfig {
            domain_strategy: None,
            rules,
            ..Default::default()
        }),
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router");
    let decision = router
        .pick_route(RouteContext {
            target_domain: "Target.Example".to_string(),
            ..Default::default()
        })
        .await
        .expect("decision");
    assert_eq!(decision.outbound_tag, "hit");
}

#[test]
fn domain_matcher_uses_shared_normalized_domain() {
    let matcher = DomainMatcher::new(
        vec!["target.example".to_string()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let chain = ConditionChain::new(vec![Box::new(matcher)]);
    let mut ctx = RouteContext {
        target_domain: "Target.Example".to_string(),
        ..Default::default()
    };
    let mut state = RouteMatchState::new(&mut ctx, false);
    assert!(matches!(
        chain.evaluate(&mut state),
        crate::routing::conditions::ConditionResult::Match
    ));
    assert!(state.normalized_domain_ptr().is_some());
}

#[cfg(not(debug_assertions))]
#[test]
#[ignore = "release-only routing benchmark; run with --ignored --release"]
fn routing_pick_route_benchmark_100_rules() {
    use std::hint::black_box;
    use std::time::Instant;

    let rules = (0..100)
        .map(|index| RoutingRuleObject {
            rule_type: Some("field".to_string()),
            outbound_tag: Some(format!("out-{index}")),
            extra: BTreeMap::from([(
                "domain".to_string(),
                serde_json::json!([format!("full:miss-{index}.example")]),
            )]),
            ..Default::default()
        })
        .chain([RoutingRuleObject {
            rule_type: Some("field".to_string()),
            outbound_tag: Some("hit".to_string()),
            extra: BTreeMap::from([(
                "domain".to_string(),
                serde_json::json!(["full:target.example"]),
            )]),
            ..Default::default()
        }])
        .collect();
    let outbound = RuntimeOutboundManager::new();
    for index in 0..100 {
        let tag = format!("out-{index}");
        outbound
            .register_startup_outbound(&freedom(&tag))
            .expect("outbound");
    }
    outbound
        .register_startup_outbound(&freedom("hit"))
        .expect("outbound");
    let router = RuntimeRouter::new(
        Some(&RoutingConfig {
            domain_strategy: None,
            rules,
            ..Default::default()
        }),
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router");
    let ctx = RouteContext {
        target_domain: "target.example".to_string(),
        ..Default::default()
    };
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let started = Instant::now();
    for _ in 0..1000 {
        let decision = rt
            .block_on(router.pick_route(ctx.clone()))
            .expect("decision");
        black_box(decision.outbound_tag);
    }
    eprintln!(
        "routing_pick_route_100_rules x1000: {:?}",
        started.elapsed()
    );
}
