use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use uuid::Uuid;

use crate::config::xray::raw::{OutboundObject, RoutingConfig, RoutingRuleObject};
use crate::dns::engine::DnsEngine;
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::dispatch::{
    connect_routed_outbound, route_context_from_vless, RouteSocketMeta,
};
use crate::routing::{NetworkKind, RouteContext, RouteError, RoutedOutbound, RuntimeRouter};
use crate::runtime::RuntimeOutboundManager;
use crate::vless::protocol::VlessDestination;
use crate::vless::user_manager::VlessAuthenticatedClient;

fn freedom_outbound(tag: &str) -> OutboundObject {
    OutboundObject {
        tag: Some(tag.to_string()),
        protocol: Some("freedom".to_string()),
        extra: Default::default(),
    }
}

fn blackhole_outbound(tag: &str) -> OutboundObject {
    OutboundObject {
        tag: Some(tag.to_string()),
        protocol: Some("blackhole".to_string()),
        extra: Default::default(),
    }
}

fn test_router(tags: &[&str], routing: Option<RoutingConfig>) -> Arc<RuntimeRouter> {
    let outbound = RuntimeOutboundManager::new();
    for tag in tags {
        outbound
            .register_startup_outbound(&freedom_outbound(tag))
            .expect("outbound");
    }
    RuntimeRouter::new(
        routing.as_ref(),
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router")
}

fn test_router_mixed(
    outbounds: &[OutboundObject],
    routing: Option<RoutingConfig>,
) -> Arc<RuntimeRouter> {
    let manager = RuntimeOutboundManager::new();
    for outbound in outbounds {
        manager
            .register_startup_outbound(outbound)
            .expect("outbound");
    }
    RuntimeRouter::new(
        routing.as_ref(),
        Arc::clone(&manager),
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router")
}

fn sample_auth() -> VlessAuthenticatedClient {
    VlessAuthenticatedClient {
        id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("uuid"),
        email: Some("fixture@example.test".to_string()),
        flow: None,
        level: None,
        inbound_tag: "vless-reality-in".to_string(),
    }
}

#[tokio::test]
async fn default_outbound_used_when_no_rule_matches() {
    let router = test_router(&["direct-a", "direct-b"], None);
    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "nomatch.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("decision");
    assert_eq!(decision.outbound_tag, "direct-a");
}

#[tokio::test]
async fn routing_section_absent_matches_empty_rules() {
    let router_none = test_router(&["direct"], None);
    let router_empty = test_router(
        &["direct"],
        Some(RoutingConfig {
            domain_strategy: None,
            rules: vec![],
            balancers: vec![],
            ..Default::default()
        }),
    );
    let ctx = RouteContext {
        target_domain: "example.com".to_string(),
        network: NetworkKind::Tcp,
        ..Default::default()
    };
    let a = router_none
        .pick_route_with_default(ctx.clone())
        .await
        .expect("none routing");
    let b = router_empty
        .pick_route_with_default(ctx)
        .await
        .expect("empty routing");
    assert_eq!(a.outbound_tag, "direct");
    assert_eq!(b.outbound_tag, "direct");
}

#[tokio::test]
async fn first_registered_outbound_is_default_for_multiple() {
    let router = test_router_mixed(
        &[freedom_outbound("direct"), blackhole_outbound("block")],
        Some(RoutingConfig {
            domain_strategy: None,
            rules: vec![],
            balancers: vec![],
            ..Default::default()
        }),
    );
    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "example.com".to_string(),
            ..Default::default()
        })
        .await
        .expect("decision");
    assert_eq!(decision.outbound_tag, "direct");
}

#[tokio::test]
async fn explicit_rule_outbound_selected() {
    let routing = RoutingConfig {
        domain_strategy: None,
        rules: vec![RoutingRuleObject {
            rule_type: Some("field".to_string()),
            outbound_tag: Some("block".to_string()),
            extra: BTreeMap::from([(
                "domain".to_string(),
                serde_json::json!(["full:example.com"]),
            )]),
            ..Default::default()
        }],
        ..Default::default()
    };
    let router = test_router_mixed(
        &[freedom_outbound("direct"), blackhole_outbound("block")],
        Some(routing),
    );
    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "example.com".to_string(),
            network: NetworkKind::Tcp,
            ..Default::default()
        })
        .await
        .expect("decision");
    assert_eq!(decision.outbound_tag, "block");
}

#[tokio::test]
async fn zero_outbounds_returns_no_clue() {
    let outbound = RuntimeOutboundManager::new();
    let router = RuntimeRouter::new(
        None,
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router");
    let err = router
        .pick_route_with_default(RouteContext {
            target_domain: "example.com".to_string(),
            ..Default::default()
        })
        .await
        .expect_err("no clue");
    assert_eq!(err, RouteError::NoClue);
}

#[tokio::test]
async fn missing_rule_outbound_tag_fails_at_connect_not_route_pick() {
    let routing = RoutingConfig {
        domain_strategy: None,
        rules: vec![RoutingRuleObject {
            rule_type: Some("field".to_string()),
            outbound_tag: Some("missing".to_string()),
            extra: BTreeMap::from([(
                "domain".to_string(),
                serde_json::json!(["full:example.com"]),
            )]),
            ..Default::default()
        }],
        ..Default::default()
    };
    let router = test_router(&["direct"], Some(routing));
    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "example.com".to_string(),
            network: NetworkKind::Tcp,
            ..Default::default()
        })
        .await
        .expect("rule selects missing tag");
    assert_eq!(decision.outbound_tag, "missing");
    let connect_result = connect_routed_outbound(
        &decision.outbound_tag,
        &VlessDestination::Domain("example.com".to_string(), 443),
        router.outbound_manager(),
        OutboundConnectRuntime::shared(),
        NetworkKind::Tcp,
    )
    .await;
    let err = connect_result
        .err()
        .expect("connect should fail for missing outbound tag");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    let message = err.to_string();
    assert!(message.contains("requested_outbound_tag=missing"));
    assert!(message.contains("default_outbound_tag=Some(\"direct\")"));
    assert!(message.contains("registered_outbound_count=1"));
}

#[tokio::test]
async fn default_outbound_advances_deterministically_after_removal() {
    let manager = RuntimeOutboundManager::new();
    for tag in ["A", "B", "C"] {
        manager
            .register_startup_outbound(&freedom_outbound(tag))
            .expect("register");
    }
    let router = RuntimeRouter::new(
        None,
        Arc::clone(&manager),
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router");

    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "nomatch.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("default A");
    assert_eq!(decision.outbound_tag, "A");

    manager.remove_outbound("A").expect("remove A");
    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "nomatch.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("default B");
    assert_eq!(decision.outbound_tag, "B");

    manager.remove_outbound("B").expect("remove B");
    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "nomatch.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("default C");
    assert_eq!(decision.outbound_tag, "C");
}

#[test]
fn tcp_and_udp_route_context_share_destination_metadata() {
    let auth = sample_auth();
    let destination = VlessDestination::Ip(Ipv4Addr::LOCALHOST.into(), 443);
    let meta = RouteSocketMeta::default();
    let tcp = route_context_from_vless(
        "vless-reality-in",
        &auth,
        &destination,
        b"GET /",
        &meta,
        true,
        NetworkKind::Tcp,
    );
    let udp = route_context_from_vless(
        "vless-reality-in",
        &auth,
        &destination,
        b"",
        &meta,
        false,
        NetworkKind::Udp,
    );
    assert_eq!(tcp.inbound_tag, udp.inbound_tag);
    assert_eq!(tcp.target_ips, udp.target_ips);
    assert_eq!(tcp.target_port, udp.target_port);
    assert_eq!(tcp.user, udp.user);
    assert_eq!(tcp.vless_route, udp.vless_route);
    assert_eq!(tcp.network, NetworkKind::Tcp);
    assert_eq!(udp.network, NetworkKind::Udp);
    assert_eq!(tcp.protocol, "http");
    assert!(udp.protocol.is_empty());
}

#[tokio::test]
async fn blackhole_outbound_selected_without_direct_fallback() {
    let routing = RoutingConfig {
        domain_strategy: None,
        rules: vec![RoutingRuleObject {
            rule_type: Some("field".to_string()),
            outbound_tag: Some("block".to_string()),
            extra: BTreeMap::from([(
                "domain".to_string(),
                serde_json::json!(["full:blocked.example"]),
            )]),
            ..Default::default()
        }],
        ..Default::default()
    };
    let router = test_router_mixed(
        &[freedom_outbound("direct"), blackhole_outbound("block")],
        Some(routing),
    );
    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "blocked.example".to_string(),
            network: NetworkKind::Tcp,
            ..Default::default()
        })
        .await
        .expect("decision");
    assert_eq!(decision.outbound_tag, "block");
    match connect_routed_outbound(
        &decision.outbound_tag,
        &VlessDestination::Domain("blocked.example".to_string(), 443),
        router.outbound_manager(),
        OutboundConnectRuntime::shared(),
        NetworkKind::Tcp,
    )
    .await
    .expect("blackhole connect")
    {
        RoutedOutbound::Blackhole => {}
        _ => panic!("expected blackhole outbound"),
    }
}

/// Informational routing throughput benchmark (not run in normal CI).
#[ignore]
#[tokio::test]
async fn routing_decision_benchmark() {
    use std::collections::BTreeMap;
    use std::time::Instant;

    const ITERATIONS: usize = 10_000;

    fn build_rules(count: usize) -> RoutingConfig {
        let mut rules = Vec::with_capacity(count);
        for index in 0..count {
            rules.push(RoutingRuleObject {
                rule_type: Some("field".to_string()),
                outbound_tag: Some(format!("out-{index}")),
                extra: BTreeMap::from([(
                    "domain".to_string(),
                    serde_json::json!([format!("nomatch-{index}.example")]),
                )]),
                ..Default::default()
            });
        }
        rules.push(RoutingRuleObject {
            rule_type: Some("field".to_string()),
            outbound_tag: Some("match-out".to_string()),
            extra: BTreeMap::from([(
                "domain".to_string(),
                serde_json::json!(["full:bench-target.example"]),
            )]),
            ..Default::default()
        });
        RoutingConfig {
            domain_strategy: None,
            rules,
            balancers: vec![],
            ..Default::default()
        }
    }

    async fn bench(label: &str, rule_count: usize, ctx: RouteContext) {
        let mut tags = vec!["default-out".to_string()];
        for index in 0..rule_count {
            tags.push(format!("out-{index}"));
        }
        tags.push("match-out".to_string());
        let outbounds: Vec<_> = tags.iter().map(|tag| freedom_outbound(tag)).collect();
        let router = test_router_mixed(&outbounds, Some(build_rules(rule_count)));
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let decision = router
                .pick_route_with_default(ctx.clone())
                .await
                .expect("route");
            let expected = if label.starts_with("domain-match") {
                "match-out"
            } else {
                "default-out"
            };
            assert_eq!(decision.outbound_tag, expected);
        }
        let elapsed = start.elapsed();
        eprintln!(
            "MEASURED routing bench {label} rules={rule_count} iters={ITERATIONS} total={elapsed:?} per_decision={:?}",
            elapsed / ITERATIONS as u32
        );
    }

    bench(
        "domain-match-1",
        1,
        RouteContext {
            target_domain: "bench-target.example".to_string(),
            ..Default::default()
        },
    )
    .await;
    bench(
        "domain-match-10",
        10,
        RouteContext {
            target_domain: "bench-target.example".to_string(),
            ..Default::default()
        },
    )
    .await;
    bench(
        "domain-match-100",
        100,
        RouteContext {
            target_domain: "bench-target.example".to_string(),
            ..Default::default()
        },
    )
    .await;
    bench(
        "default-no-match-100",
        100,
        RouteContext {
            target_domain: "absent.example".to_string(),
            ..Default::default()
        },
    )
    .await;
}
