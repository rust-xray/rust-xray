use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::api::proto::common::geodata::domain;
use crate::api::proto::common::geodata::{domain_rule, Domain, DomainRule};
use crate::config::xray::raw::OutboundObject;
use crate::dns::engine::DnsEngine;
use crate::routing::conditions::{Condition, DomainMatcher, RouteMatchState};
use crate::routing::context::RouteContext;
use crate::routing::router::{DomainStrategy, RuntimeRouter};
use crate::routing::TargetResolver;
use crate::runtime::RuntimeOutboundManager;
use async_trait::async_trait;

fn domain_ctx(domain: &str) -> RouteContext {
    RouteContext {
        target_domain: domain.to_string(),
        ..Default::default()
    }
}

fn matches(matcher: &DomainMatcher, domain: &str) -> bool {
    let mut ctx = domain_ctx(domain);
    let mut state = RouteMatchState::new(&mut ctx, false);
    matcher.matches(&mut state)
}

#[test]
fn domain_matches_case_insensitive_candidate() {
    let matcher = DomainMatcher::new(vec![], vec!["example.com".to_string()], vec![], vec![]);
    assert!(matches(&matcher, "WWW.Example.COM"));
    assert!(matches(&matcher, "example.com"));
}

#[test]
fn domain_rule_patterns_normalized_at_compile_time() {
    let matcher = DomainMatcher::new(vec![], vec!["Example.COM".to_string()], vec![], vec![]);
    assert!(matches(&matcher, "www.example.com"));
}

#[test]
fn substr_matches_substring() {
    let matcher = DomainMatcher::new(vec![], vec![], vec!["google".to_string()], vec![]);
    assert!(matches(&matcher, "www.google.com"));
    assert!(!matches(&matcher, "example.com"));
}

#[test]
fn domain_matches_exact_and_subdomain_only() {
    let matcher = DomainMatcher::new(vec![], vec!["example.com".to_string()], vec![], vec![]);
    assert!(matches(&matcher, "example.com"));
    assert!(matches(&matcher, "www.example.com"));
    assert!(!matches(&matcher, "badexample.com"));
}

#[test]
fn full_matches_exact_only() {
    let matcher = DomainMatcher::new(vec!["example.com".to_string()], vec![], vec![], vec![]);
    assert!(matches(&matcher, "example.com"));
    assert!(!matches(&matcher, "www.example.com"));
}

#[test]
fn regex_matches_pattern() {
    let re = regex::Regex::new(r"^www\.example\.com$").expect("regex");
    let matcher = DomainMatcher::new(vec![], vec![], vec![], vec![re]);
    assert!(matches(&matcher, "www.example.com"));
    assert!(!matches(&matcher, "example.com"));
}

fn test_router_with_strategy(strategy: &str) -> Arc<RuntimeRouter> {
    use crate::config::xray::raw::{RoutingConfig, RoutingRuleObject};
    use std::collections::BTreeMap;
    let outbound = RuntimeOutboundManager::new();
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("direct-a".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("outbound");
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("direct-b".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("outbound");
    let routing = RoutingConfig {
        domain_strategy: Some(strategy.to_string()),
        rules: vec![
            RoutingRuleObject {
                outbound_tag: Some("direct-a".to_string()),
                rule_type: Some("field".to_string()),
                extra: BTreeMap::from([
                    (
                        "domain".to_string(),
                        serde_json::json!(["domain:win.example"]),
                    ),
                    ("ruleTag".to_string(), serde_json::json!("domain-rule")),
                ]),
                ..Default::default()
            },
            RoutingRuleObject {
                outbound_tag: Some("direct-b".to_string()),
                rule_type: Some("field".to_string()),
                extra: BTreeMap::from([
                    ("ip".to_string(), serde_json::json!(["127.0.0.1/32"])),
                    ("ruleTag".to_string(), serde_json::json!("ip-rule")),
                ]),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    RuntimeRouter::new(
        Some(&routing),
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router")
}

struct CountingResolver {
    queries: AtomicUsize,
    result: Result<Vec<std::net::IpAddr>, String>,
}

#[async_trait]
impl TargetResolver for CountingResolver {
    async fn lookup_target_ips(&self, _domain: &str) -> Result<Vec<std::net::IpAddr>, String> {
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
async fn ip_if_non_match_domain_rule_wins_before_ip_resolution() {
    let router = test_router_with_strategy("IpIfNonMatch");
    assert_eq!(router.domain_strategy(), DomainStrategy::IpIfNonMatch);
    let decision = router
        .pick_route(RouteContext {
            target_domain: "win.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("decision");
    assert_eq!(decision.outbound_tag, "direct-a");
    assert_eq!(decision.rule_tag, "domain-rule");
}

#[tokio::test]
async fn ip_on_demand_is_lazy_and_caches_one_lookup_per_evaluation() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.9".parse().expect("ip")]),
    });
    let router = counted_router("IpOnDemand", Arc::clone(&resolver));

    let domain = router
        .pick_route(RouteContext {
            target_domain: "domain.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("domain route");
    assert_eq!(domain.outbound_tag, "domain-out");
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 0);

    let ip = router
        .pick_route(RouteContext {
            target_domain: "resolve.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("ip route");
    assert_eq!(ip.outbound_tag, "ip-out");
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ip_if_non_match_is_exactly_two_passes_with_one_lookup() {
    let resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.10".parse().expect("ip")]),
    });
    let router = counted_router("IpIfNonMatch", Arc::clone(&resolver));

    let domain = router
        .pick_route(RouteContext {
            target_domain: "domain.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("domain route");
    assert_eq!(domain.outbound_tag, "domain-out");
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 0);

    let ip = router
        .pick_route(RouteContext {
            target_domain: "resolve.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("ip route");
    assert_eq!(ip.outbound_tag, "ip-out");
    assert_eq!(resolver.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn as_is_skip_dns_and_dns_failure_do_not_retry_or_recurse() {
    let as_is_resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.11".parse().expect("ip")]),
    });
    let as_is = counted_router("AsIs", Arc::clone(&as_is_resolver));
    assert!(matches!(
        as_is
            .pick_route(RouteContext {
                target_domain: "resolve.example".to_string(),
                ..Default::default()
            })
            .await,
        Err(crate::routing::RouteError::NoClue)
    ));
    assert_eq!(as_is_resolver.queries.load(Ordering::SeqCst), 0);

    let skip_resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Ok(vec!["203.0.113.12".parse().expect("ip")]),
    });
    let skip = counted_router("IpOnDemand", Arc::clone(&skip_resolver));
    assert!(skip
        .pick_route(RouteContext {
            target_domain: "dns-transport.example".to_string(),
            skip_dns_resolve: true,
            ..Default::default()
        })
        .await
        .is_err());
    assert_eq!(skip_resolver.queries.load(Ordering::SeqCst), 0);

    let failed_resolver = Arc::new(CountingResolver {
        queries: AtomicUsize::new(0),
        result: Err("resolver failed".to_string()),
    });
    let failed = counted_router("IpOnDemand", Arc::clone(&failed_resolver));
    assert!(failed
        .pick_route(RouteContext {
            target_domain: "failure.example".to_string(),
            ..Default::default()
        })
        .await
        .is_err());
    assert_eq!(failed_resolver.queries.load(Ordering::SeqCst), 1);
}

#[test]
fn geosite_dat_round_trip() {
    use crate::routing::geodata::{encode_geosite_dat, load_geosite_domains};
    use tempfile::NamedTempFile;

    let domains = vec![Domain {
        r#type: domain::Type::Full as i32,
        value: "example.com".to_string(),
        attribute: vec![],
    }];
    let bytes = encode_geosite_dat("TEST", &domains);
    let file = NamedTempFile::new().expect("temp");
    std::fs::write(file.path(), bytes).expect("write");
    let loaded = load_geosite_domains(file.path().to_str().unwrap(), "TEST", "").expect("load");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].value, "example.com");
}

#[test]
fn geodata_cache_decodes_each_file_and_code_once_across_rules() {
    use crate::api::proto::common::geodata::Cidr;
    use crate::routing::geodata::{encode_geoip_dat, encode_geosite_dat, GeodataCache};
    use tempfile::NamedTempFile;

    let site_file = NamedTempFile::new().expect("site temp");
    std::fs::write(
        site_file.path(),
        encode_geosite_dat(
            "TEST",
            &[Domain {
                r#type: domain::Type::Full as i32,
                value: "cached.example".to_string(),
                attribute: vec![],
            }],
        ),
    )
    .expect("site write");
    let ip_file = NamedTempFile::new().expect("ip temp");
    std::fs::write(
        ip_file.path(),
        encode_geoip_dat(
            "TEST",
            vec![Cidr {
                ip: vec![203, 0, 113, 0],
                prefix: 24,
            }],
        ),
    )
    .expect("ip write");

    let cache = GeodataCache::default();
    let site = site_file.path().to_str().expect("site path");
    let ip = ip_file.path().to_str().expect("ip path");
    cache.load_geosite(site, "TEST", "").expect("site first");
    cache.load_geosite(site, "test", "").expect("site cached");
    cache.load_geoip(ip, "TEST", false).expect("ip first");
    cache
        .load_geoip(ip, "test", true)
        .expect("same decoded IP data, reverse matcher");
    assert_eq!(cache.load_counts(), (1, 1));
}

#[test]
fn add_rule_invalid_geosite_leaves_table_unchanged() {
    use crate::api::proto::app::router::{Config as RouterConfig, RoutingRule};
    use crate::api::proto::common::serial::TypedMessage;
    use crate::routing::ROUTER_CONFIG_TYPE;
    use prost::Message;

    let outbound = RuntimeOutboundManager::new();
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("direct-a".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("outbound");
    let router = RuntimeRouter::new(
        None,
        Arc::clone(&outbound),
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router");

    let before = router.list_rules().len();
    let config = RouterConfig {
        rule: vec![RoutingRule {
            domain: vec![DomainRule {
                value: Some(domain_rule::Value::Geosite(
                    crate::api::proto::common::geodata::GeoSiteRule {
                        file: "missing.dat".to_string(),
                        code: "NOPE".to_string(),
                        attrs: String::new(),
                    },
                )),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = router
        .add_rule(
            &TypedMessage {
                r#type: ROUTER_CONFIG_TYPE.to_string(),
                value: config.encode_to_vec(),
            },
            true,
        )
        .expect_err("geosite failure");
    assert!(err.to_string().contains("missing.dat") || err.to_string().contains("failed"));
    assert_eq!(router.list_rules().len(), before);
}
