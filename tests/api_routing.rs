use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use prost::Message;
use rust_xray::api::proto::app::router::command::routing_service_client::RoutingServiceClient;
use rust_xray::api::proto::app::router::command::{
    AddRuleRequest, GetBalancerInfoRequest, ListRuleRequest, OverrideBalancerTargetRequest,
    RemoveRuleRequest, RoutingContext, SubscribeRoutingStatsRequest, TestRouteRequest,
};
use rust_xray::api::proto::app::router::{Config as RouterConfig, RoutingRule};
use rust_xray::api::proto::common::geodata::{domain, domain_rule, Domain, DomainRule};
use rust_xray::api::proto::common::net::Network;
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::routing::ROUTER_CONFIG_TYPE;
use rust_xray::runtime::{encode_freedom_outbound, HandlerRuntime};
use rust_xray::stats::StatsRegistry;
use tokio::net::TcpListener;
use tonic::transport::Endpoint;
use tonic::Code;

async fn spawn_routing_server(
    handler_runtime: Arc<HandlerRuntime>,
    registry: Arc<StatsRegistry>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Routing, ApiService::Handler],
            registry,
            handler_runtime,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    addr
}

fn domain_rule(full: &str) -> TypedMessage {
    let config = RouterConfig {
        rule: vec![RoutingRule {
            target_tag: Some(
                rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                    "direct-b".to_string(),
                ),
            ),
            rule_tag: "rule-example".to_string(),
            domain: vec![DomainRule {
                value: Some(domain_rule::Value::Custom(Domain {
                    r#type: domain::Type::Full as i32,
                    value: full.to_string(),
                    attribute: vec![],
                })),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: config.encode_to_vec(),
    }
}

fn routing_context(domain: &str) -> RoutingContext {
    RoutingContext {
        inbound_tag: "vless-in".to_string(),
        network: Network::Tcp as i32,
        target_domain: domain.to_string(),
        target_port: 443,
        ..Default::default()
    }
}

#[tokio::test]
async fn routing_stats_disabled_returns_internal_error() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
    let addr = spawn_routing_server(runtime, registry).await;
    let mut client = RoutingServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect"),
    );
    let err = client
        .subscribe_routing_stats(SubscribeRoutingStatsRequest {
            field_selectors: vec![],
        })
        .await
        .expect_err("stats disabled");
    assert_eq!(err.code(), Code::Internal);
    assert!(err.message().contains("Routing statistics not enabled"));
}

#[tokio::test]
async fn test_route_selects_matching_rule_without_dispatch() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-a"))
        .expect("direct-a");
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-b"))
        .expect("direct-b");
    let addr = spawn_routing_server(Arc::clone(&runtime), registry).await;
    let mut client = RoutingServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect"),
    );

    client
        .add_rule(AddRuleRequest {
            config: Some(domain_rule("example.com")),
            should_append: true,
        })
        .await
        .expect("add rule")
        .into_inner();

    let response = client
        .test_route(TestRouteRequest {
            routing_context: Some(routing_context("example.com")),
            field_selectors: vec!["outbound".to_string(), "domain".to_string()],
            publish_result: false,
        })
        .await
        .expect("test route")
        .into_inner();

    assert_eq!(response.outbound_tag, "direct-b");
    assert_eq!(response.target_domain, "example.com");
}

#[tokio::test]
async fn add_and_remove_rule_changes_test_route_result() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-a"))
        .expect("direct-a");
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-b"))
        .expect("direct-b");
    let addr = spawn_routing_server(Arc::clone(&runtime), registry).await;
    let mut client = RoutingServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect"),
    );

    client
        .add_rule(AddRuleRequest {
            config: Some(domain_rule("example.com")),
            should_append: true,
        })
        .await
        .expect("add rule");

    let matched = client
        .test_route(TestRouteRequest {
            routing_context: Some(routing_context("example.com")),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("route")
        .into_inner();
    assert_eq!(matched.outbound_tag, "direct-b");

    client
        .remove_rule(RemoveRuleRequest {
            rule_tag: "rule-example".to_string(),
        })
        .await
        .expect("remove");

    let no_clue = client
        .test_route(TestRouteRequest {
            routing_context: Some(routing_context("example.com")),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect_err("router has no matching rule after removal");
    assert_eq!(no_clue.code(), Code::Internal);
    assert!(no_clue.message().contains("no clue"));
}

#[tokio::test]
async fn list_rule_returns_live_rules() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-a"))
        .expect("direct-a");
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-b"))
        .expect("direct-b");
    let addr = spawn_routing_server(Arc::clone(&runtime), registry).await;
    let mut client = RoutingServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect"),
    );

    client
        .add_rule(AddRuleRequest {
            config: Some(domain_rule("example.com")),
            should_append: true,
        })
        .await
        .expect("add");

    let listed = client
        .list_rule(ListRuleRequest {})
        .await
        .expect("list")
        .into_inner();
    assert_eq!(listed.rules.len(), 1);
    assert_eq!(listed.rules[0].tag, "direct-b");
    assert_eq!(listed.rules[0].rule_tag, "rule-example");
}

#[tokio::test]
async fn publish_result_emits_routing_stats_event() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-a"))
        .expect("direct-a");
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-b"))
        .expect("direct-b");
    let addr = spawn_routing_server(Arc::clone(&runtime), registry).await;
    let mut client = RoutingServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect"),
    );

    client
        .add_rule(AddRuleRequest {
            config: Some(domain_rule("example.com")),
            should_append: true,
        })
        .await
        .expect("add");

    let mut stream = client
        .subscribe_routing_stats(SubscribeRoutingStatsRequest {
            field_selectors: vec!["outbound".to_string()],
        })
        .await
        .expect("subscribe")
        .into_inner();
    assert_eq!(
        runtime
            .router
            .routing_stats()
            .expect("enabled stats")
            .subscriber_count(),
        1
    );

    client
        .test_route(TestRouteRequest {
            routing_context: Some(routing_context("example.com")),
            field_selectors: vec![],
            publish_result: true,
        })
        .await
        .expect("test route publish");

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), stream.message())
        .await
        .expect("timeout")
        .expect("message")
        .expect("payload");
    assert_eq!(event.outbound_tag, "direct-b");

    drop(stream);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if runtime
                .router
                .routing_stats()
                .expect("enabled stats")
                .subscriber_count()
                == 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("subscriber removed after cancellation");
}

#[tokio::test]
async fn routing_context_ip_bytes_round_trip() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-a"))
        .expect("direct-a");
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-b"))
        .expect("direct-b");
    let addr = spawn_routing_server(Arc::clone(&runtime), registry).await;
    let mut client = RoutingServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect"),
    );

    client
        .add_rule(AddRuleRequest {
            config: Some(domain_rule("example.com")),
            should_append: true,
        })
        .await
        .expect("add rule");

    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let mut ctx = routing_context("example.com");
    ctx.target_i_ps = vec![match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }];

    let response = client
        .test_route(TestRouteRequest {
            routing_context: Some(ctx),
            field_selectors: vec!["ip_target".to_string()],
            publish_result: false,
        })
        .await
        .expect("test route")
        .into_inner();

    assert_eq!(response.target_i_ps.len(), 1);
    assert_eq!(
        response.target_i_ps[0],
        Ipv4Addr::new(203, 0, 113, 10).octets().to_vec()
    );
}

#[tokio::test]
async fn get_and_override_balancer_target() {
    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("proxy-a"))
        .expect("proxy-a");
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("proxy-b"))
        .expect("proxy-b");

    let balancer_config = RouterConfig {
        balancing_rule: vec![rust_xray::api::proto::app::router::BalancingRule {
            tag: "balancer-1".to_string(),
            outbound_selector: vec!["proxy".to_string()],
            strategy: "random".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    runtime
        .router
        .add_rule(
            &TypedMessage {
                r#type: ROUTER_CONFIG_TYPE.to_string(),
                value: balancer_config.encode_to_vec(),
            },
            true,
        )
        .expect("add balancer");

    let addr = spawn_routing_server(Arc::clone(&runtime), registry).await;
    let mut client = RoutingServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect"),
    );

    client
        .override_balancer_target(OverrideBalancerTargetRequest {
            balancer_tag: "balancer-1".to_string(),
            target: "proxy-b".to_string(),
        })
        .await
        .expect("override");

    let info = client
        .get_balancer_info(GetBalancerInfoRequest {
            tag: "balancer-1".to_string(),
        })
        .await
        .expect("info")
        .into_inner();
    let balancer = info.balancer.expect("balancer");
    assert_eq!(
        balancer.r#override.map(|o| o.target).as_deref(),
        Some("proxy-b")
    );
    assert_eq!(
        balancer.principle_target.expect("principle").tag,
        vec!["proxy-a".to_string(), "proxy-b".to_string()]
    );
}

#[tokio::test]
async fn add_rule_append_replace_duplicate_and_rollback_semantics_match_upstream() {
    fn message(config: RouterConfig) -> TypedMessage {
        TypedMessage {
            r#type: ROUTER_CONFIG_TYPE.to_string(),
            value: config.encode_to_vec(),
        }
    }
    fn rule(domain_value: Domain, rule_tag: &str) -> RoutingRule {
        RoutingRule {
            target_tag: Some(
                rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                    "direct-b".to_string(),
                ),
            ),
            rule_tag: rule_tag.to_string(),
            domain: vec![DomainRule {
                value: Some(domain_rule::Value::Custom(domain_value)),
            }],
            ..Default::default()
        }
    }
    fn full(value: &str) -> Domain {
        Domain {
            r#type: domain::Type::Full as i32,
            value: value.to_string(),
            attribute: vec![],
        }
    }

    let registry = Arc::new(StatsRegistry::new());
    let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-a"))
        .expect("direct-a");
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("direct-b"))
        .expect("direct-b");
    let addr = spawn_routing_server(Arc::clone(&runtime), registry).await;
    let mut client = RoutingServiceClient::new(
        Endpoint::from_shared(format!("http://{addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect"),
    );

    client
        .add_rule(AddRuleRequest {
            config: Some(message(RouterConfig {
                rule: vec![rule(full("old.example"), "stable")],
                ..Default::default()
            })),
            should_append: true,
        })
        .await
        .expect("seed old rule");

    let duplicate = client
        .add_rule(AddRuleRequest {
            config: Some(message(RouterConfig {
                rule: vec![rule(full("duplicate.example"), "stable")],
                ..Default::default()
            })),
            should_append: true,
        })
        .await
        .expect_err("duplicate non-empty ruleTag");
    assert!(duplicate.message().contains("duplicate ruleTag stable"));

    for domain in ["empty-one.example", "empty-two.example"] {
        client
            .add_rule(AddRuleRequest {
                config: Some(message(RouterConfig {
                    rule: vec![rule(full(domain), "")],
                    ..Default::default()
                })),
                should_append: true,
            })
            .await
            .expect("empty ruleTag is allowed");
    }

    let invalid = client
        .add_rule(AddRuleRequest {
            config: Some(message(RouterConfig {
                rule: vec![rule(
                    Domain {
                        r#type: domain::Type::Regex as i32,
                        value: "[".to_string(),
                        attribute: vec![],
                    },
                    "invalid-replacement",
                )],
                ..Default::default()
            })),
            should_append: false,
        })
        .await
        .expect_err("invalid replacement");
    assert!(invalid.message().contains("invalid domain regexp"));
    let old = client
        .test_route(TestRouteRequest {
            routing_context: Some(routing_context("old.example")),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("old state survives invalid replacement")
        .into_inner();
    assert_eq!(old.outbound_tag, "direct-b");

    let duplicate_balancer = client
        .add_rule(AddRuleRequest {
            config: Some(message(RouterConfig {
                balancing_rule: vec![
                    rust_xray::api::proto::app::router::BalancingRule {
                        tag: "dup".to_string(),
                        outbound_selector: vec!["direct".to_string()],
                        strategy: "random".to_string(),
                        ..Default::default()
                    },
                    rust_xray::api::proto::app::router::BalancingRule {
                        tag: "dup".to_string(),
                        outbound_selector: vec!["direct".to_string()],
                        strategy: "random".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            })),
            should_append: false,
        })
        .await
        .expect_err("duplicate balancer tag");
    assert!(duplicate_balancer
        .message()
        .contains("duplicate balancer tag"));

    client
        .remove_rule(RemoveRuleRequest {
            rule_tag: "missing".to_string(),
        })
        .await
        .expect("missing non-empty rule tag is a successful no-op");
    let empty_remove = client
        .remove_rule(RemoveRuleRequest {
            rule_tag: String::new(),
        })
        .await
        .expect_err("empty rule tag rejected");
    assert!(empty_remove.message().contains("empty tag name"));

    client
        .add_rule(AddRuleRequest {
            config: Some(message(RouterConfig {
                rule: vec![rule(full("new.example"), "replacement")],
                ..Default::default()
            })),
            should_append: false,
        })
        .await
        .expect("valid atomic replacement");
    assert!(client
        .test_route(TestRouteRequest {
            routing_context: Some(routing_context("old.example")),
            field_selectors: vec![],
            publish_result: false,
        })
        .await
        .is_err());
    let replacement = client
        .test_route(TestRouteRequest {
            routing_context: Some(routing_context("new.example")),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("replacement active")
        .into_inner();
    assert_eq!(replacement.outbound_tag, "direct-b");
}
