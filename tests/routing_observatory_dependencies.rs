//! Stage 8E4-C1: Observatory feature dependency parity for health-aware balancers.

#[path = "routing_e2e_harness.rs"]
mod harness;

use std::sync::Arc;

use harness::{connect_routing_clients, spawn_routing_server};
use prost::Message;
use rust_xray::api::proto::app::router::{BalancingRule, Config as RouterConfig, RoutingRule};
use rust_xray::api::proto::common::geodata::{domain, domain_rule, Domain, DomainRule};
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::config::xray::raw::{
    BurstObservatoryConfig, HealthPingJsonConfig, ObservatoryConfig, OutboundObject, RoutingConfig,
    XrayConfig,
};
use rust_xray::outbound::runtime::OutboundConnectRuntime;
use rust_xray::routing::{
    balancer_requires_observatory, parse_strategy, BalancerStrategy, RouteContext, RouteError,
    ROUTER_CONFIG_TYPE,
};
use rust_xray::runtime::{encode_freedom_outbound, HandlerRuntime};
use rust_xray::stats::StatsRegistry;
use serde_json::json;

fn unresolved_dependencies(err: RouteError) -> bool {
    matches!(err, RouteError::UnresolvedDependencies(_))
        || err
            .to_string()
            .contains("not all dependencies are resolved")
}

fn balancer_json(strategy: &str, fallback_tag: &str) -> serde_json::Value {
    let mut strategy_value = json!({ "type": strategy });
    if strategy == "leastLoad" {
        strategy_value["settings"] = json!({});
    }
    let mut value = json!({
        "tag": "health-balancer",
        "selector": ["direct-"],
        "strategy": strategy_value,
    });
    if !fallback_tag.is_empty() {
        value["fallbackTag"] = json!(fallback_tag);
    }
    value
}

fn base_xray(balancers: Vec<serde_json::Value>) -> XrayConfig {
    XrayConfig {
        log: None,
        api: None,
        dns: None,
        stats: None,
        policy: None,
        routing: Some(RoutingConfig {
            balancers,
            ..Default::default()
        }),
        observatory: None,
        burst_observatory: None,
        outbounds: vec![OutboundObject {
            tag: Some("direct-a".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        }],
        inbounds: vec![],
        extra: Default::default(),
    }
}

fn try_handler_runtime(mut xray: XrayConfig) -> Result<HandlerRuntime, RouteError> {
    OutboundConnectRuntime::init_shared(&xray);
    let registry = Arc::new(StatsRegistry::new());
    let outbound = rust_xray::runtime::RuntimeOutboundManager::new();
    for ob in &xray.outbounds {
        let _ = outbound.register_startup_outbound(ob);
    }
    HandlerRuntime::new(Arc::new(xray), registry, None, false)
}

fn with_standard_observatory(mut xray: XrayConfig) -> XrayConfig {
    xray.observatory = Some(ObservatoryConfig {
        subject_selector: vec!["direct-".to_string()],
        probe_url: Some("http://127.0.0.1:1/probe".to_string()),
        probe_interval: Some("10s".to_string()),
        enable_concurrency: false,
    });
    xray
}

fn with_burst_observatory(mut xray: XrayConfig) -> XrayConfig {
    xray.burst_observatory = Some(BurstObservatoryConfig {
        subject_selector: vec!["direct-".to_string()],
        ping_config: Some(HealthPingJsonConfig {
            destination: Some("http://127.0.0.1:1/probe".to_string()),
            sampling_count: Some(1),
            ..Default::default()
        }),
    });
    xray
}

fn random_rule_message() -> TypedMessage {
    TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: RouterConfig {
            balancing_rule: vec![BalancingRule {
                tag: "plain-balancer".to_string(),
                outbound_selector: vec!["direct-".to_string()],
                strategy: "random".to_string(),
                ..Default::default()
            }],
            rule: vec![RoutingRule {
                target_tag: Some(
                    rust_xray::api::proto::app::router::routing_rule::TargetTag::BalancingTag(
                        "plain-balancer".to_string(),
                    ),
                ),
                rule_tag: "plain-rule".to_string(),
                domain: vec![DomainRule {
                    value: Some(domain_rule::Value::Custom(Domain {
                        r#type: domain::Type::Full as i32,
                        value: "localhost".to_string(),
                        attribute: vec![],
                    })),
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec(),
    }
}

fn least_ping_rule_message() -> TypedMessage {
    TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: RouterConfig {
            balancing_rule: vec![BalancingRule {
                tag: "health-balancer".to_string(),
                outbound_selector: vec!["direct-".to_string()],
                strategy: "leastPing".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec(),
    }
}

#[test]
fn balancer_requires_observatory_helper_matrix() {
    assert!(balancer_requires_observatory(
        BalancerStrategy::LeastPing,
        ""
    ));
    assert!(balancer_requires_observatory(
        BalancerStrategy::LeastLoad,
        ""
    ));
    assert!(balancer_requires_observatory(
        BalancerStrategy::Random,
        "fallback"
    ));
    assert!(balancer_requires_observatory(
        BalancerStrategy::RoundRobin,
        "fallback"
    ));
    assert!(!balancer_requires_observatory(BalancerStrategy::Random, ""));
    assert!(!balancer_requires_observatory(
        BalancerStrategy::RoundRobin,
        ""
    ));

    let least_ping = parse_strategy("leastPing").expect("strategy");
    assert!(balancer_requires_observatory(least_ping, ""));
}

#[test]
fn static_least_ping_requires_observatory() {
    match try_handler_runtime(base_xray(vec![balancer_json("leastPing", "")])) {
        Err(err) => assert!(unresolved_dependencies(err)),
        Ok(_) => panic!("startup must fail"),
    }
}

#[test]
fn static_least_load_requires_observatory() {
    match try_handler_runtime(base_xray(vec![balancer_json("leastLoad", "")])) {
        Err(err) => assert!(unresolved_dependencies(err)),
        Ok(_) => panic!("startup must fail"),
    }
}

#[test]
fn static_random_with_fallback_requires_observatory() {
    match try_handler_runtime(base_xray(vec![balancer_json("random", "fallback")])) {
        Err(err) => assert!(unresolved_dependencies(err)),
        Ok(_) => panic!("startup must fail"),
    }
}

#[test]
fn static_round_robin_with_fallback_requires_observatory() {
    match try_handler_runtime(base_xray(vec![balancer_json("roundRobin", "fallback")])) {
        Err(err) => assert!(unresolved_dependencies(err)),
        Ok(_) => panic!("startup must fail"),
    }
}

#[test]
fn static_random_without_fallback_does_not_require_observatory() {
    try_handler_runtime(base_xray(vec![balancer_json("random", "")])).expect("startup ok");
}

#[test]
fn static_round_robin_without_fallback_does_not_require_observatory() {
    try_handler_runtime(base_xray(vec![balancer_json("roundRobin", "")])).expect("startup ok");
}

#[test]
fn static_health_dependent_balancers_start_with_standard_observatory() {
    for strategy in ["leastPing", "leastLoad", "random", "roundRobin"] {
        try_handler_runtime(with_standard_observatory(base_xray(vec![balancer_json(
            strategy, "fallback",
        )])))
        .unwrap_or_else(|err| panic!("standard observatory must satisfy {strategy}: {err}"));
    }
}

#[test]
fn static_health_dependent_balancers_start_with_burst_only_observatory() {
    try_handler_runtime(with_burst_observatory(base_xray(vec![balancer_json(
        "leastLoad",
        "",
    )])))
    .expect("burst-only observatory satisfies dependency");
}

#[tokio::test]
async fn replace_table_rejects_missing_observatory_and_keeps_existing_rules() {
    let runtime = Arc::new(HandlerRuntime::for_routing_tests(Arc::new(
        StatsRegistry::new(),
    )));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-a"))
        .expect("direct-a");
    runtime
        .router
        .add_rule(&random_rule_message(), true)
        .expect("seed random balancer");

    let before = runtime.router.list_rules();
    assert_eq!(before.len(), 1);

    let err = runtime
        .router
        .add_rule(&least_ping_rule_message(), false)
        .expect_err("replace must fail without observatory");
    assert!(unresolved_dependencies(err));

    let after = runtime.router.list_rules();
    assert_eq!(after, before);
    assert!(
        runtime
            .router
            .pick_route(RouteContext {
                target_domain: "localhost".to_string(),
                ..Default::default()
            })
            .await
            .is_ok(),
        "existing table must remain routable"
    );
}

#[tokio::test]
async fn dynamic_add_rule_rejects_health_dependent_without_observatory() {
    let runtime = Arc::new(HandlerRuntime::for_routing_tests(Arc::new(
        StatsRegistry::new(),
    )));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-a"))
        .expect("direct-a");

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_handler, mut routing) = connect_routing_clients(grpc_addr).await;

    let err = routing
        .add_rule(
            rust_xray::api::proto::app::router::command::AddRuleRequest {
                config: Some(least_ping_rule_message()),
                should_append: true,
            },
        )
        .await
        .expect_err("append must fail");
    assert!(err.message().contains("not all dependencies are resolved"));
}

#[test]
fn observatory_present_empty_samples_does_not_fail_startup() {
    let xray = with_standard_observatory(base_xray(vec![balancer_json("leastPing", "fallback")]));
    try_handler_runtime(xray).expect("empty observation state is runtime-time, not startup");
}
