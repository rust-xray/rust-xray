//! GeoData, webhook, and balancer routing E2E tests.

#[path = "routing_e2e_harness.rs"]
mod harness;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use harness::*;
use prost::Message;
use rust_xray::api::proto::app::router::command::{
    AddRuleRequest, GetBalancerInfoRequest, OverrideBalancerTargetRequest, TestRouteRequest,
};
use rust_xray::api::proto::app::router::Config as RouterConfig;
use rust_xray::api::proto::common::geodata::{domain, Domain, GeoIp, GeoSite};
use rust_xray::api::proto::common::net::Network;
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::routing::ROUTER_CONFIG_TYPE;
use rust_xray::runtime::{encode_blackhole_outbound, encode_freedom_outbound};
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::user_manager::VlessUserManager;
use tempfile::NamedTempFile;
use uuid::Uuid;

#[tokio::test]
async fn geosite_tonic_add_and_remove_routes_real_vless_traffic() {
    let site_file = NamedTempFile::new().expect("site file");
    std::fs::write(
        site_file.path(),
        encode_geodata_record(&GeoSite {
            code: "TEST".to_string(),
            domain: vec![Domain {
                r#type: domain::Type::Full as i32,
                value: "localhost".to_string(),
                attribute: vec![],
            }],
        }),
    )
    .expect("write geosite");

    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        "geosite-dynamic-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("geosite@example.test".to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let vless_addr = spawn_vless_listener("geosite-dynamic-in", users, router).await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing) = connect_routing_clients(grpc_addr).await;

    let (port_a, hit_a) = spawn_target_listener().await;
    dial_vless_domain(vless_addr, port_a, "localhost")
        .await
        .expect("baseline dial");
    assert!(
        target_hit_within(hit_a, 2000).await,
        "default outbound must reach target before geosite rule"
    );

    tonic_add_rule_replace(
        &mut routing,
        geosite_rule_message(
            site_file.path().to_str().expect("site path"),
            "",
            "direct-b",
            "geosite-dynamic",
        ),
    )
    .await;
    let (port_b, hit_b) = spawn_target_listener().await;
    dial_vless_domain(vless_addr, port_b, "localhost")
        .await
        .expect("geosite dial");
    assert!(
        !target_hit_within(hit_b, 400).await,
        "geosite rule must route matching domain to blackhole"
    );

    tonic_remove_rule(&mut routing, "geosite-dynamic").await;
    let (port_a2, hit_a2) = spawn_target_listener().await;
    dial_vless_domain(vless_addr, port_a2, "localhost")
        .await
        .expect("restored dial");
    assert!(
        target_hit_within(hit_a2, 2000).await,
        "removed geosite rule must restore default outbound"
    );
}

#[tokio::test]
async fn geoip_ipv6_tonic_rule_matches_test_route_and_optional_data_plane() {
    let ip_file = NamedTempFile::new().expect("geoip file");
    std::fs::write(
        ip_file.path(),
        encode_geodata_record(&GeoIp {
            code: "TEST".to_string(),
            cidr: vec![rust_xray::api::proto::common::geodata::Cidr {
                ip: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix: 32,
            }],
            reverse_match: false,
        }),
    )
    .expect("write geoip");

    let runtime = setup_routing_runtime().await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing) = connect_routing_clients(grpc_addr).await;

    tonic_add_rule_replace(
        &mut routing,
        geoip_rule_message(
            ip_file.path().to_str().expect("geoip path"),
            false,
            "direct-b",
            "geoip-v6",
        ),
    )
    .await;

    let inside_ip = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let inside_ctx = rust_xray::api::proto::app::router::command::RoutingContext {
        network: Network::Tcp as i32,
        target_i_ps: vec![inside_ip.to_vec()],
        target_port: 443,
        ..Default::default()
    };
    let inside_test = routing
        .test_route(TestRouteRequest {
            routing_context: Some(inside_ctx.clone()),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("inside test route")
        .into_inner();
    assert_eq!(inside_test.outbound_tag, "direct-b");

    let outside_decision = runtime
        .router
        .pick_route_with_default(rust_xray::routing::route_context_from_proto(
            &rust_xray::api::proto::app::router::command::RoutingContext {
                network: Network::Tcp as i32,
                target_i_ps: vec![std::net::Ipv4Addr::new(203, 0, 113, 10).octets().to_vec()],
                target_port: 443,
                ..Default::default()
            },
        ))
        .await
        .expect("outside pick route");
    assert_eq!(outside_decision.outbound_tag, "direct-a");

    let inside_decision = runtime
        .router
        .pick_route_with_default(rust_xray::routing::route_context_from_proto(
            &rust_xray::api::proto::app::router::command::RoutingContext {
                network: Network::Tcp as i32,
                target_i_ps: vec![inside_ip.to_vec()],
                target_port: 443,
                ..Default::default()
            },
        ))
        .await
        .expect("inside pick route");
    assert_eq!(inside_decision.outbound_tag, "direct-b");

    // Optional host-dependent data-plane proof when loopback IPv6 bind works.
    let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
        eprintln!(
            "geoip_ipv6: TestRoute/pick_route parity proven; data-plane skipped (IPv6 unavailable)"
        );
        return;
    };
    let users = Arc::new(VlessUserManager::new(
        "geoip-v6-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("geoipv6@example.test".to_string()),
            flow: None,
            level: None,
        }],
    ));
    let loopback_file = NamedTempFile::new().expect("loopback geoip file");
    std::fs::write(
        loopback_file.path(),
        encode_geodata_record(&GeoIp {
            code: "TEST".to_string(),
            cidr: vec![rust_xray::api::proto::common::geodata::Cidr {
                ip: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefix: 128,
            }],
            reverse_match: false,
        }),
    )
    .expect("write loopback geoip");
    tonic_add_rule_replace(
        &mut routing,
        geoip_rule_message(
            loopback_file.path().to_str().expect("loopback path"),
            false,
            "direct-b",
            "geoip-v6-loopback",
        ),
    )
    .await;

    let router = Arc::clone(&runtime.router);
    let vless_addr = spawn_vless_listener("geoip-v6-in", users, router).await;
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if listener.accept().await.is_ok() {
            let _ = tx.send(());
        }
    });
    dial_vless_ipv6(
        vless_addr,
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port,
    )
    .await
    .expect("loopback ipv6 dial");
    assert!(
        !target_hit_within(rx, 400).await,
        "IPv6 loopback inside geoip CIDR must route to blackhole"
    );
}

#[tokio::test]
async fn invalid_geodata_replace_leaves_existing_rules_unchanged() {
    let runtime = setup_routing_runtime().await;
    runtime
        .router
        .add_rule(
            &domain_rule_message("keep.example", "direct-b", "keep-rule"),
            true,
        )
        .expect("seed rule");

    let err = runtime
        .router
        .add_rule(
            &TypedMessage {
                r#type: ROUTER_CONFIG_TYPE.to_string(),
                value: RouterConfig {
                    rule: vec![rust_xray::api::proto::app::router::RoutingRule {
                        domain: vec![rust_xray::api::proto::common::geodata::DomainRule {
                            value: Some(
                                rust_xray::api::proto::common::geodata::domain_rule::Value::Geosite(
                                    rust_xray::api::proto::common::geodata::GeoSiteRule {
                                        file: "missing.dat".to_string(),
                                        code: "NOPE".to_string(),
                                        attrs: String::new(),
                                    },
                                ),
                            ),
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }
                .encode_to_vec(),
            },
            false,
        )
        .expect_err("invalid geosite replace");
    assert!(!err.to_string().is_empty());

    let decision = runtime
        .router
        .pick_route_with_default(rust_xray::routing::RouteContext {
            target_domain: "keep.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("existing rule still active");
    assert_eq!(decision.outbound_tag, "direct-b");
    assert_eq!(decision.rule_tag, "keep-rule");
}

#[tokio::test]
async fn webhook_slow_endpoint_does_not_block_routing() {
    let (webhook_url, mut webhook_requests) = spawn_webhook_server(Duration::from_secs(2)).await;
    let runtime = setup_routing_runtime().await;
    let users = Arc::new(VlessUserManager::new(
        "webhook-slow-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("slow-webhook@example.test".to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let vless_addr = spawn_vless_listener("webhook-slow-in", users, router).await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing) = connect_routing_clients(grpc_addr).await;

    routing
        .add_rule(AddRuleRequest {
            config: Some(webhook_rule_message("localhost", "direct-a", webhook_url)),
            should_append: true,
        })
        .await
        .expect("add webhook");

    let (port, hit) = spawn_target_listener().await;
    let started = std::time::Instant::now();
    dial_vless_domain(vless_addr, port, "localhost")
        .await
        .expect("slow webhook dial");
    assert!(
        target_hit_within(hit, 2000).await,
        "routing must complete before slow webhook responds"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "slow webhook must not block data-plane routing"
    );
    let _ = tokio::time::timeout(Duration::from_secs(3), webhook_requests.recv()).await;
}

#[tokio::test]
async fn random_balancer_routes_only_to_candidate_outbounds() {
    let runtime = setup_routing_runtime().await;
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("candidate-a"))
        .expect("candidate-a");
    runtime
        .outbound
        .add_outbound(encode_blackhole_outbound("candidate-b"))
        .expect("candidate-b");

    let users = Arc::new(VlessUserManager::new(
        "random-bal-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("random@example.test".to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let vless_addr = spawn_vless_listener("random-bal-in", users, router).await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing) = connect_routing_clients(grpc_addr).await;

    tonic_add_rule_replace(
        &mut routing,
        balancer_rule_message("random", "candidate-", "random-bal"),
    )
    .await;

    let mut saw_a = false;
    let mut saw_b = false;
    for _ in 0..24 {
        let (port, hit) = spawn_target_listener().await;
        dial_vless_domain(vless_addr, port, "localhost")
            .await
            .expect("random dial");
        if target_hit_within(hit, 500).await {
            saw_a = true;
        } else {
            saw_b = true;
        }
    }
    assert!(saw_a, "random balancer must eventually select candidate-a");
    assert!(saw_b, "random balancer must eventually select candidate-b");
}

#[tokio::test]
async fn dynamic_outbound_is_immediately_visible_to_balancer() {
    let runtime = setup_routing_runtime().await;
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("candidate-a"))
        .expect("candidate-a");

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (mut handler, mut routing) = connect_routing_clients(grpc_addr).await;
    tonic_add_rule_replace(
        &mut routing,
        balancer_rule_message("roundrobin", "candidate-", "dyn-bal"),
    )
    .await;

    let before = routing
        .get_balancer_info(GetBalancerInfoRequest {
            tag: "dyn-bal".to_string(),
        })
        .await
        .expect("info before")
        .into_inner();
    assert_eq!(
        before
            .balancer
            .as_ref()
            .expect("balancer")
            .principle_target
            .as_ref()
            .expect("principle")
            .tag,
        vec!["candidate-a".to_string()]
    );

    tonic_add_outbound(&mut handler, "candidate-b", true).await;
    let after_add = routing
        .get_balancer_info(GetBalancerInfoRequest {
            tag: "dyn-bal".to_string(),
        })
        .await
        .expect("info after add")
        .into_inner();
    let targets: HashSet<_> = after_add
        .balancer
        .as_ref()
        .expect("balancer")
        .principle_target
        .as_ref()
        .expect("principle")
        .tag
        .iter()
        .cloned()
        .collect();
    assert!(targets.contains("candidate-a"));
    assert!(targets.contains("candidate-b"));

    tonic_remove_outbound(&mut handler, "candidate-b").await;
    let after_remove = routing
        .get_balancer_info(GetBalancerInfoRequest {
            tag: "dyn-bal".to_string(),
        })
        .await
        .expect("info after remove")
        .into_inner();
    assert_eq!(
        after_remove
            .balancer
            .as_ref()
            .expect("balancer")
            .principle_target
            .as_ref()
            .expect("principle")
            .tag,
        vec!["candidate-a".to_string()]
    );
}

#[tokio::test]
async fn round_robin_test_route_matches_live_sequence_with_override() {
    let runtime = setup_routing_runtime().await;
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("candidate-a"))
        .expect("candidate-a");
    runtime
        .outbound
        .add_outbound(encode_blackhole_outbound("candidate-b"))
        .expect("candidate-b");

    let users = Arc::new(VlessUserManager::new(
        "rr-parity-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("rr@example.test".to_string()),
            flow: None,
            level: None,
        }],
    ));
    let router = Arc::clone(&runtime.router);
    let vless_addr = spawn_vless_listener("rr-parity-in", users, router).await;
    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_, mut routing) = connect_routing_clients(grpc_addr).await;
    tonic_add_rule_replace(
        &mut routing,
        balancer_rule_message("roundrobin", "candidate-", "rr-bal"),
    )
    .await;

    for expected_hit in [true, false, true] {
        let (port, hit) = spawn_target_listener().await;
        dial_vless_domain(vless_addr, port, "localhost")
            .await
            .expect("round robin dial");
        assert_eq!(
            target_hit_within(hit, if expected_hit { 2000 } else { 400 }).await,
            expected_hit
        );
    }

    routing
        .override_balancer_target(OverrideBalancerTargetRequest {
            balancer_tag: "rr-bal".to_string(),
            target: "candidate-b".to_string(),
        })
        .await
        .expect("override");
    let ctx = routing_context_for_vless_tcp(
        "rr-parity-in",
        "rr@example.test",
        &Uuid::from_bytes(DEFAULT_USER_ID),
        "localhost",
        443,
        "",
    );
    assert_test_route_outbound(&mut routing, ctx.clone(), "candidate-b").await;
    let (port, hit) = spawn_target_listener().await;
    dial_vless_domain(vless_addr, port, "localhost")
        .await
        .expect("override dial");
    assert!(!target_hit_within(hit, 400).await);
    assert_test_route_outbound(&mut routing, ctx, "candidate-b").await;
}
