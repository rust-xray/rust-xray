//! RouteContext + DomainStrategy parity tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use prost::Message;
use uuid::Uuid;

use crate::api::proto::app::router::command::RoutingContext;
use crate::api::proto::app::router::{Config as RouterConfig, RoutingRule};
use crate::api::proto::common::net::{Network, PortList, PortRange};
use crate::api::proto::common::serial::TypedMessage;
use crate::config::xray::raw::OutboundObject;
use crate::dns::engine::DnsEngine;
use crate::routing::conditions::{Condition, ProtocolMatcher, RouteMatchState};
use crate::routing::context::RouteContext;
use crate::routing::{
    route_context_from_proto, route_context_from_vless, route_decision_to_proto,
    sniff_protocol_from_payload, vless_route_from_uuid, NetworkKind, RouteSocketMeta,
    RuntimeRouter, TargetResolver, ROUTER_CONFIG_TYPE,
};
use crate::runtime::RuntimeOutboundManager;
use crate::vless::config::parse_vless_user_id;
use crate::vless::protocol::{VlessDestination, VlessRequest};
use crate::vless::user_manager::{ManagedUser, VlessAuthenticatedClient, VlessUserManager};

const STATIC_UUID: &str = "00000000-0000-1234-0000-000000000001";

fn static_uuid() -> Uuid {
    Uuid::parse_str(STATIC_UUID).expect("static uuid")
}

fn vless_route_from_bytes(id: &Uuid) -> u16 {
    let bytes = id.as_bytes();
    ((bytes[6] as u16) << 8) | (bytes[7] as u16)
}

#[test]
fn vless_route_from_static_uuid() {
    let id = static_uuid();
    assert_eq!(vless_route_from_uuid(&id), 0x1234);
    assert_eq!(vless_route_from_uuid(&id), vless_route_from_bytes(&id));
}

#[test]
fn vless_route_dynamic_user_same_as_static() {
    const DYNAMIC_ID: &str = "22222222-2222-2222-2222-222222222222";
    let manager = VlessUserManager::new(
        "vless-in",
        vec![crate::vless::config::VlessClient {
            id: static_uuid(),
            email: Some("static@example.test".to_string()),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        }],
    );
    let dynamic_id = Uuid::parse_str(DYNAMIC_ID).expect("dynamic uuid");
    manager
        .add_user(ManagedUser {
            id: dynamic_id,
            email: "dynamic@example.test".to_string(),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
            expiry_secs: None,
        })
        .expect("add dynamic user");

    let static_auth = VlessAuthenticatedClient {
        id: static_uuid(),
        email: Some("static@example.test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        inbound_tag: "vless-in".to_string(),
    };
    let dynamic_auth = VlessAuthenticatedClient {
        id: dynamic_id,
        email: Some("dynamic@example.test".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        inbound_tag: "vless-in".to_string(),
    };
    let static_ctx = route_context_from_vless(
        "vless-in",
        &static_auth,
        &VlessDestination::Ip(Ipv4Addr::LOCALHOST.into(), 443),
        &[],
        &RouteSocketMeta::default(),
        false,
        NetworkKind::Tcp,
    );
    let dynamic_ctx = route_context_from_vless(
        "vless-in",
        &dynamic_auth,
        &VlessDestination::Ip(Ipv4Addr::LOCALHOST.into(), 443),
        &[],
        &RouteSocketMeta::default(),
        false,
        NetworkKind::Tcp,
    );
    assert_eq!(
        static_ctx.vless_route,
        vless_route_from_uuid(&static_uuid())
    );
    assert_eq!(dynamic_ctx.vless_route, vless_route_from_uuid(&dynamic_id));
    assert_ne!(static_ctx.vless_route, dynamic_ctx.vless_route);
}

#[test]
fn vless_route_custom_id_uses_effective_uuid() {
    const CUSTOM_ID: &str = "route-custom-id";
    let effective = parse_vless_user_id(CUSTOM_ID).expect("custom id maps to uuid");
    let lookup = crate::vless::vless_lookup_uuid(&effective);
    let manager = VlessUserManager::new("vless-in", vec![]);
    manager
        .add_user(ManagedUser {
            id: lookup,
            email: "custom@example.test".to_string(),
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
            expiry_secs: None,
        })
        .expect("add custom user");

    let request = VlessRequest {
        version: 0,
        user_id: effective,
        command: crate::vless::protocol::VlessCommand::Tcp,
        destination: VlessDestination::Ip(Ipv4Addr::LOCALHOST.into(), 443),
        additional_info: Vec::new(),
    };
    let auth = manager
        .authenticate(&request)
        .expect("authenticate custom user");
    let ctx = route_context_from_vless(
        "vless-in",
        &auth,
        &request.destination,
        &[],
        &RouteSocketMeta::default(),
        false,
        NetworkKind::Tcp,
    );
    assert_eq!(ctx.vless_route, vless_route_from_uuid(&effective));
    assert_eq!(ctx.vless_route, vless_route_from_bytes(&effective));
}

fn vless_route_rule_message(route: u16, tag: &str, rule_tag: &str) -> TypedMessage {
    TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: RouterConfig {
            rule: vec![RoutingRule {
                target_tag: Some(
                    crate::api::proto::app::router::routing_rule::TargetTag::Tag(tag.to_string()),
                ),
                rule_tag: rule_tag.to_string(),
                vless_route_list: Some(PortList {
                    range: vec![PortRange {
                        from: u32::from(route),
                        to: u32::from(route),
                    }],
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec(),
    }
}

#[tokio::test]
async fn vless_route_matcher_matches_and_rejects() {
    let outbound = RuntimeOutboundManager::new();
    for tag in ["direct-a", "direct-b"] {
        outbound
            .register_startup_outbound(&OutboundObject {
                tag: Some(tag.to_string()),
                protocol: Some("freedom".to_string()),
                extra: Default::default(),
            })
            .expect("outbound");
    }
    let router = RuntimeRouter::new(
        None,
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router");
    let route = vless_route_from_uuid(&static_uuid());
    router
        .add_rule(
            &vless_route_rule_message(route, "direct-b", "vless-route-rule"),
            true,
        )
        .expect("add vless route rule");

    let matched = router
        .pick_route_with_default(RouteContext {
            vless_route: route,
            ..Default::default()
        })
        .await
        .expect("matching route");
    assert_eq!(matched.outbound_tag, "direct-b");
    assert_eq!(matched.rule_tag, "vless-route-rule");

    let unmatched = router
        .pick_route_with_default(RouteContext {
            vless_route: route.wrapping_add(1),
            ..Default::default()
        })
        .await
        .expect("default outbound");
    assert_eq!(unmatched.outbound_tag, "direct-a");
    assert!(unmatched.rule_tag.is_empty());
}

#[test]
fn protocol_tls_detected() {
    let tls = [0x16_u8, 0x03, 0x01, 0x00];
    assert_eq!(sniff_protocol_from_payload(&tls), "tls");
    let mut ctx = RouteContext {
        protocol: sniff_protocol_from_payload(&tls),
        ..Default::default()
    };
    let mut state = RouteMatchState::new(&mut ctx, false);
    assert!(ProtocolMatcher::new(vec!["tls".to_string()]).matches(&mut state));
}

#[test]
fn protocol_http_detected() {
    let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(sniff_protocol_from_payload(http), "http");
    let mut ctx = RouteContext {
        protocol: sniff_protocol_from_payload(http),
        ..Default::default()
    };
    let mut state = RouteMatchState::new(&mut ctx, false);
    assert!(ProtocolMatcher::new(vec!["http".to_string()]).matches(&mut state));
}

#[test]
fn protocol_unknown_empty() {
    let unknown = b"\x00\x01\x02\x03";
    assert!(sniff_protocol_from_payload(unknown).is_empty());
    let mut ctx = RouteContext::default();
    let mut state = RouteMatchState::new(&mut ctx, false);
    assert!(!ProtocolMatcher::new(vec!["tls".to_string()]).matches(&mut state));
}

struct CountingResolver {
    queries: AtomicUsize,
    result: Result<Vec<IpAddr>, String>,
}

#[async_trait]
impl TargetResolver for CountingResolver {
    async fn lookup_target_ips(&self, _domain: &str) -> Result<Vec<IpAddr>, String> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

fn counted_router(strategy: &str, resolver: Arc<CountingResolver>) -> Arc<RuntimeRouter> {
    use crate::config::xray::raw::{RoutingConfig, RoutingRuleObject};
    use std::collections::BTreeMap;

    let outbound = RuntimeOutboundManager::new();
    for tag in ["domain-out", "ip-out", "fallback-out"] {
        outbound
            .register_startup_outbound(&OutboundObject {
                tag: Some(tag.to_string()),
                protocol: Some("freedom".to_string()),
                extra: Default::default(),
            })
            .expect("outbound");
    }
    let routing = RoutingConfig {
        domain_strategy: Some(strategy.to_string()),
        rules: vec![
            RoutingRuleObject {
                outbound_tag: Some("domain-out".to_string()),
                rule_type: Some("field".to_string()),
                extra: BTreeMap::from([(
                    "domain".to_string(),
                    serde_json::json!(["full:domain.example"]),
                )]),
                ..Default::default()
            },
            RoutingRuleObject {
                outbound_tag: Some("ip-out".to_string()),
                rule_type: Some("field".to_string()),
                extra: BTreeMap::from([("ip".to_string(), serde_json::json!(["203.0.113.0/24"]))]),
                ..Default::default()
            },
            RoutingRuleObject {
                outbound_tag: Some("fallback-out".to_string()),
                rule_type: Some("field".to_string()),
                extra: BTreeMap::from([("ip".to_string(), serde_json::json!(["198.51.100.0/24"]))]),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    RuntimeRouter::new_with_resolver(
        Some(&routing),
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        resolver,
        false,
        None,
    )
    .expect("router")
}

#[tokio::test]
async fn asis_does_not_resolve() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.9".parse().expect("ip")]),
    });
    let router = counted_router("AsIs", Arc::clone(&resolver));
    assert!(matches!(
        router
            .pick_route(RouteContext {
                target_domain: "resolve.example".to_string(),
                ..Default::default()
            })
            .await,
        Err(crate::routing::RouteError::NoClue)
    ));
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ip_on_demand_domain_match_is_lazy() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.9".parse().expect("ip")]),
    });
    let router = counted_router("IpOnDemand", Arc::clone(&resolver));
    let decision = router
        .pick_route(RouteContext {
            target_domain: "domain.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("domain rule");
    assert_eq!(decision.outbound_tag, "domain-out");
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ip_on_demand_resolves_once_when_needed() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.9".parse().expect("ip")]),
    });
    let router = counted_router("IpOnDemand", Arc::clone(&resolver));
    let decision = router
        .pick_route(RouteContext {
            target_domain: "resolve.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("ip rule");
    assert_eq!(decision.outbound_tag, "ip-out");
    assert_eq!(decision.context.target_domain, "resolve.example");
    assert_eq!(
        decision.context.target_ips,
        vec!["203.0.113.9".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ip_if_non_match_skips_dns_when_first_pass_matches() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.10".parse().expect("ip")]),
    });
    let router = counted_router("IpIfNonMatch", Arc::clone(&resolver));
    let decision = router
        .pick_route(RouteContext {
            target_domain: "domain.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("domain rule");
    assert_eq!(decision.outbound_tag, "domain-out");
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ip_if_non_match_resolves_once_on_second_pass() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.10".parse().expect("ip")]),
    });
    let router = counted_router("IpIfNonMatch", Arc::clone(&resolver));
    let decision = router
        .pick_route(RouteContext {
            target_domain: "resolve.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("ip rule on second pass");
    assert_eq!(decision.outbound_tag, "ip-out");
    assert_eq!(decision.context.target_domain, "resolve.example");
    assert_eq!(decision.context.target_ips.len(), 1);
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn skip_dns_resolve_prevents_lookup() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.12".parse().expect("ip")]),
    });
    for strategy in ["IpOnDemand", "IpIfNonMatch"] {
        let router = counted_router(strategy, Arc::clone(&resolver));
        assert!(router
            .pick_route(RouteContext {
                target_domain: "dns-transport.example".to_string(),
                skip_dns_resolve: true,
                ..Default::default()
            })
            .await
            .is_err());
    }
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dns_failure_is_bounded() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Err("resolver failed".to_string()),
    });
    for strategy in ["IpOnDemand", "IpIfNonMatch"] {
        let router = counted_router(strategy, Arc::clone(&resolver));
        assert!(router
            .pick_route(RouteContext {
                target_domain: "failure.example".to_string(),
                ..Default::default()
            })
            .await
            .is_err());
    }
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn ip_target_skips_dns() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.9".parse().expect("ip")]),
    });
    let router = counted_router("IpOnDemand", Arc::clone(&resolver));

    let v4 = router
        .pick_route(RouteContext {
            target_domain: String::new(),
            target_ips: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44))],
            ..Default::default()
        })
        .await
        .expect("ipv4 target route");
    assert_eq!(v4.outbound_tag, "ip-out");

    let _ = router
        .pick_route(RouteContext {
            target_domain: String::new(),
            target_ips: vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        })
        .await;
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 0);
}

#[test]
fn route_context_ipv4_bytes() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let ctx = RouteContext {
        target_ips: vec![ip],
        ..Default::default()
    };
    let proto = route_decision_to_proto(&crate::routing::RouteDecision {
        context: ctx.clone(),
        outbound_tag: String::new(),
        outbound_group_tags: vec![],
        rule_tag: String::new(),
    });
    assert_eq!(proto.target_i_ps.len(), 1);
    assert_eq!(proto.target_i_ps[0].len(), 4);
    assert_eq!(
        proto.target_i_ps[0],
        Ipv4Addr::new(1, 2, 3, 4).octets().to_vec()
    );
    let back = route_context_from_proto(&RoutingContext {
        target_i_ps: proto.target_i_ps.clone(),
        ..Default::default()
    });
    assert_eq!(back.target_ips, vec![ip]);
}

#[test]
fn route_context_ipv6_bytes() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1));
    let ctx = RouteContext {
        source_ips: vec![ip],
        local_ips: vec![ip],
        ..Default::default()
    };
    let proto = route_decision_to_proto(&crate::routing::RouteDecision {
        context: ctx.clone(),
        outbound_tag: String::new(),
        outbound_group_tags: vec![],
        rule_tag: String::new(),
    });
    assert_eq!(proto.source_i_ps.len(), 1);
    assert_eq!(proto.source_i_ps[0].len(), 16);
    assert_eq!(proto.local_i_ps.len(), 1);
    assert_eq!(proto.local_i_ps[0].len(), 16);
    let back = route_context_from_proto(&RoutingContext {
        source_i_ps: proto.source_i_ps.clone(),
        local_i_ps: proto.local_i_ps.clone(),
        network: Network::Tcp as i32,
        ..Default::default()
    });
    assert_eq!(back.source_ips, vec![ip]);
    assert_eq!(back.local_ips, vec![ip]);
    assert_eq!(back.network, crate::routing::NetworkKind::Tcp);
}
