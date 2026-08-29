//! Stage 8E4-C: live Observatory health wired into RuntimeRouter balancers.

#[path = "routing_e2e_harness.rs"]
mod harness;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use harness::{
    connect_routing_clients, spawn_routing_server, spawn_target_listener, spawn_vless_listener,
    target_hit_within, tonic_add_rule_replace, DEFAULT_USER_ID,
};
use prost::Message;
use rust_xray::api::proto::app::observatory::command::observatory_service_client::ObservatoryServiceClient;
use rust_xray::api::proto::app::observatory::command::{
    GetOutboundStatusRequest, GetOutboundStatusResponse,
};
use rust_xray::api::proto::app::observatory::ObservationResult;
use rust_xray::api::proto::app::router::command::{
    AddRuleRequest, GetBalancerInfoRequest, RoutingContext, TestRouteRequest,
};
use rust_xray::api::proto::app::router::{
    BalancingRule, Config as RouterConfig, RoutingRule, StrategyLeastLoadConfig,
};
use rust_xray::api::proto::common::geodata::{domain, domain_rule, Domain, DomainRule};
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::observatory::{
    BurstObservatoryRuntimeConfig, BurstTestHooks, HealthPingRuntimeConfig,
    ObservatoryRuntimeConfig, ProbeDelaySource,
};
use rust_xray::routing::{NetworkKind, OutboundHealthProvider, RouteContext, ROUTER_CONFIG_TYPE};
use rust_xray::runtime::{encode_blackhole_outbound, encode_freedom_outbound, HandlerRuntime};
use rust_xray::stats::StatsRegistry;
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::user_manager::VlessUserManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tonic::transport::Endpoint;
use uuid::Uuid;

static OBS_HEALTH_TEST_SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn test_serial() -> tokio::sync::MutexGuard<'static, ()> {
    OBS_HEALTH_TEST_SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[derive(Clone, Copy)]
enum ProbeServerMode {
    Ok204,
    Stall,
}

async fn spawn_probe_server(mode: ProbeServerMode) -> (std::net::SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe server");
    let addr = listener.local_addr().expect("probe addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                match mode {
                    ProbeServerMode::Stall => {
                        let _ = n;
                        std::future::pending::<()>().await;
                    }
                    ProbeServerMode::Ok204 => {
                        let _ = n;
                        let response =
                            "HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                }
            });
        }
    });
    (addr, handle)
}

fn probe_url(addr: std::net::SocketAddr) -> String {
    format!("http://{addr}/probe")
}

fn route_context(domain: &str) -> RouteContext {
    RouteContext {
        target_domain: domain.to_string(),
        network: NetworkKind::Tcp,
        ..Default::default()
    }
}

fn tonic_routing_context(domain: &str) -> RoutingContext {
    RoutingContext {
        target_domain: domain.to_string(),
        ..Default::default()
    }
}

fn status_by_tag<'a>(
    result: &'a ObservationResult,
    tag: &str,
) -> Option<&'a rust_xray::api::proto::app::observatory::OutboundStatus> {
    result
        .status
        .iter()
        .find(|status| status.outbound_tag == tag)
}

fn health_outbounds() -> Vec<rust_xray::api::proto::core::OutboundHandlerConfig> {
    vec![
        encode_freedom_outbound("health-direct"),
        encode_blackhole_outbound("health-dead"),
        encode_freedom_outbound("health-fallback"),
    ]
}

fn standard_observatory_runtime(probe: &str) -> Arc<HandlerRuntime> {
    HandlerRuntime::for_observatory_routing_tests(
        Arc::new(StatsRegistry::new()),
        ObservatoryRuntimeConfig::for_test(
            vec!["health-".to_string()],
            probe,
            Duration::from_secs(60),
            true,
        ),
        health_outbounds(),
    )
}

fn burst_observatory_runtime(probe: &str) -> Arc<HandlerRuntime> {
    HandlerRuntime::for_burst_observatory_routing_tests(
        Arc::new(StatsRegistry::new()),
        BurstObservatoryRuntimeConfig::for_test(
            vec!["health-".to_string()],
            HealthPingRuntimeConfig::for_test(
                probe,
                "",
                Duration::from_secs(30),
                3,
                Duration::from_secs(5),
                "HEAD",
            ),
        ),
        health_outbounds(),
    )
}

fn least_ping_balancer_rule(fallback_tag: &str) -> TypedMessage {
    TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: RouterConfig {
            balancing_rule: vec![BalancingRule {
                tag: "health-balancer".to_string(),
                outbound_selector: vec!["health-".to_string()],
                strategy: "leastPing".to_string(),
                fallback_tag: fallback_tag.to_string(),
                ..Default::default()
            }],
            rule: vec![RoutingRule {
                target_tag: Some(
                    rust_xray::api::proto::app::router::routing_rule::TargetTag::BalancingTag(
                        "health-balancer".to_string(),
                    ),
                ),
                rule_tag: "health-route".to_string(),
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

fn least_load_balancer_rule(settings: StrategyLeastLoadConfig, fallback_tag: &str) -> TypedMessage {
    TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: RouterConfig {
            balancing_rule: vec![BalancingRule {
                tag: "health-balancer".to_string(),
                outbound_selector: vec!["health-".to_string()],
                strategy: "leastLoad".to_string(),
                strategy_settings: Some(TypedMessage {
                    r#type: "xray.app.router.StrategyLeastLoadConfig".to_string(),
                    value: settings.encode_to_vec(),
                }),
                fallback_tag: fallback_tag.to_string(),
                ..Default::default()
            }],
            rule: vec![RoutingRule {
                target_tag: Some(
                    rust_xray::api::proto::app::router::routing_rule::TargetTag::BalancingTag(
                        "health-balancer".to_string(),
                    ),
                ),
                rule_tag: "health-route".to_string(),
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

fn random_balancer_rule(fallback_tag: &str) -> TypedMessage {
    balancer_with_strategy("random", fallback_tag)
}

fn round_robin_balancer_rule(fallback_tag: &str) -> TypedMessage {
    balancer_with_strategy("roundRobin", fallback_tag)
}

fn balancer_with_strategy(strategy: &str, fallback_tag: &str) -> TypedMessage {
    TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: RouterConfig {
            balancing_rule: vec![BalancingRule {
                tag: "health-balancer".to_string(),
                outbound_selector: vec!["health-".to_string()],
                strategy: strategy.to_string(),
                fallback_tag: fallback_tag.to_string(),
                ..Default::default()
            }],
            rule: vec![RoutingRule {
                target_tag: Some(
                    rust_xray::api::proto::app::router::routing_rule::TargetTag::BalancingTag(
                        "health-balancer".to_string(),
                    ),
                ),
                rule_tag: "health-route".to_string(),
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

async fn spawn_vless_stack(runtime: Arc<HandlerRuntime>) -> std::net::SocketAddr {
    let users = Arc::new(VlessUserManager::new(
        "vless-in",
        vec![VlessClient {
            id: Uuid::from_bytes(DEFAULT_USER_ID),
            email: Some("health-route@test".to_string()),
            flow: None,
            level: None,
        }],
    ));
    spawn_vless_listener("vless-in", users, Arc::clone(&runtime.router)).await
}

async fn dial_vless_domain(vless_addr: std::net::SocketAddr, domain: &str, port: u16) {
    let mut stream = TcpStream::connect(vless_addr).await.expect("connect vless");
    stream
        .write_all(&harness::build_vless_domain_request(
            &DEFAULT_USER_ID,
            domain,
            port,
        ))
        .await
        .expect("write vless");
    let mut buf = [0_u8; 64];
    let _ = stream.read(&mut buf).await;
    stream.shutdown().await.ok();
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn probe_standard(runtime: &Arc<HandlerRuntime>) {
    let observatory = runtime
        .standard_observatory
        .as_ref()
        .expect("standard observatory");
    observatory.probe_once().await;
}

async fn probe_burst(runtime: &Arc<HandlerRuntime>) {
    let observatory = runtime
        .burst_observatory
        .as_ref()
        .expect("burst observatory");
    observatory
        .check(&["health-direct".to_string(), "health-dead".to_string()])
        .await;
}

#[tokio::test]
async fn router_health_provider_matches_active_observatory_runtime() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;

    let router_provider = runtime.router.health_provider();
    let active_provider = runtime
        .observatory
        .as_ref()
        .expect("active observatory")
        .health_provider();
    assert!(Arc::ptr_eq(&router_provider, &active_provider));

    let api_status = runtime.observatory.as_ref().unwrap().observation_result();
    let router_obs = router_provider.observations().expect("router observations");
    let direct_api = status_by_tag(&api_status, "health-direct").expect("api direct");
    let direct_router = router_obs
        .iter()
        .find(|item| item.outbound_tag == "health-direct")
        .expect("router direct");
    assert_eq!(direct_api.alive, direct_router.alive);
    assert_eq!(direct_api.delay, direct_router.delay_ms);
    assert!(direct_router.health_ping.is_none());
}

#[tokio::test]
async fn least_ping_live_routing_selects_alive_direct_outbound() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_handler, mut routing) = connect_routing_clients(grpc_addr).await;
    routing
        .add_rule(AddRuleRequest {
            config: Some(least_ping_balancer_rule("")),
            should_append: true,
        })
        .await
        .expect("add leastPing rule")
        .into_inner();

    let test = routing
        .test_route(TestRouteRequest {
            routing_context: Some(tonic_routing_context("localhost")),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("test route")
        .into_inner();
    assert_eq!(test.outbound_tag, "health-direct");

    let vless_addr = spawn_vless_stack(Arc::clone(&runtime)).await;
    let (target_port, hit) = spawn_target_listener().await;
    dial_vless_domain(vless_addr, "localhost", target_port).await;
    assert!(
        target_hit_within(hit, 2000).await,
        "leastPing must route live traffic to health-direct"
    );
}

#[tokio::test]
async fn least_ping_without_observations_uses_fallback_or_error() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    runtime
        .router
        .add_rule(&least_ping_balancer_rule("health-fallback"), true)
        .expect("add rule");

    let tag = runtime
        .router
        .pick_route(route_context("localhost"))
        .await
        .expect("fallback before observations")
        .outbound_tag;
    assert_eq!(tag, "health-fallback");

    let runtime_no_fallback = standard_observatory_runtime(&probe_url(probe_addr));
    runtime_no_fallback
        .router
        .add_rule(&least_ping_balancer_rule(""), true)
        .expect("add rule without fallback");
    let err = runtime_no_fallback
        .router
        .pick_route(route_context("localhost"))
        .await;
    assert!(
        matches!(err, Err(rust_xray::routing::RouteError::Balancer(_))),
        "leastPing without observations and without fallback must error"
    );
}

#[tokio::test]
async fn least_ping_health_change_without_router_reload() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;

    runtime
        .router
        .add_rule(&least_ping_balancer_rule(""), true)
        .expect("add rule");
    assert_eq!(
        runtime
            .router
            .pick_route(route_context("localhost"))
            .await
            .expect("route 1")
            .outbound_tag,
        "health-direct"
    );

    runtime
        .outbound
        .remove_outbound("health-direct")
        .expect("remove direct");
    runtime
        .outbound
        .add_outbound(encode_blackhole_outbound("health-direct"))
        .expect("blackhole direct");
    runtime
        .outbound
        .remove_outbound("health-dead")
        .expect("remove dead");
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("health-dead"))
        .expect("freedom dead");
    probe_standard(&runtime).await;

    assert_eq!(
        runtime
            .router
            .pick_route(route_context("localhost"))
            .await
            .expect("route 2")
            .outbound_tag,
        "health-dead"
    );
}

#[tokio::test]
async fn burst_least_load_live_routing_selects_alive_direct() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = burst_observatory_runtime(&probe_url(probe_addr));
    probe_burst(&runtime).await;

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_handler, mut routing) = connect_routing_clients(grpc_addr).await;
    routing
        .add_rule(AddRuleRequest {
            config: Some(least_load_balancer_rule(
                StrategyLeastLoadConfig {
                    expected: 1,
                    ..Default::default()
                },
                "",
            )),
            should_append: true,
        })
        .await
        .expect("add leastLoad rule")
        .into_inner();

    let test = routing
        .test_route(TestRouteRequest {
            routing_context: Some(tonic_routing_context("localhost")),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("test route")
        .into_inner();
    assert_eq!(test.outbound_tag, "health-direct");

    let observations = runtime
        .burst_observatory
        .as_ref()
        .unwrap()
        .observations()
        .expect("burst observations");
    let direct = observations
        .iter()
        .find(|item| item.outbound_tag == "health-direct")
        .expect("direct observation");
    assert!(direct.alive);
    assert!(direct.health_ping.is_some());

    let vless_addr = spawn_vless_stack(Arc::clone(&runtime)).await;
    let (target_port, hit) = spawn_target_listener().await;
    dial_vless_domain(vless_addr, "localhost", target_port).await;
    assert!(
        target_hit_within(hit, 2000).await,
        "burst leastLoad must route to health-direct"
    );
}

#[tokio::test]
async fn standard_least_load_derives_from_delay_without_health_ping() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;

    runtime
        .router
        .add_rule(
            &least_load_balancer_rule(
                StrategyLeastLoadConfig {
                    expected: 1,
                    ..Default::default()
                },
                "",
            ),
            true,
        )
        .expect("add leastLoad");

    let tag = runtime
        .router
        .pick_route(route_context("localhost"))
        .await
        .expect("route")
        .outbound_tag;
    assert_eq!(tag, "health-direct");
}

#[tokio::test]
async fn random_with_fallback_filters_dead_but_keeps_unknown() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("health-unknown"))
        .expect("unknown outbound");
    probe_standard(&runtime).await;

    runtime
        .router
        .add_rule(&random_balancer_rule("health-fallback"), true)
        .expect("add random");

    let mut seen = std::collections::HashSet::new();
    for _ in 0..32 {
        let tag = runtime
            .router
            .pick_route(route_context("localhost"))
            .await
            .expect("pick")
            .outbound_tag;
        seen.insert(tag);
    }
    assert!(!seen.contains("health-dead"));
    assert!(seen.contains("health-direct") || seen.contains("health-unknown"));
}

#[tokio::test]
async fn random_without_fallback_does_not_filter_dead() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;
    runtime
        .router
        .add_rule(&random_balancer_rule(""), true)
        .expect("add random");

    let mut saw_dead = false;
    for _ in 0..64 {
        let tag = runtime
            .router
            .pick_route(route_context("localhost"))
            .await
            .expect("pick")
            .outbound_tag;
        if tag == "health-dead" {
            saw_dead = true;
            break;
        }
    }
    assert!(saw_dead, "random without fallback must not health-filter");
}

#[tokio::test]
async fn round_robin_with_fallback_skips_dead_candidates() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("health-alt"))
        .expect("alt outbound");
    probe_standard(&runtime).await;
    runtime
        .router
        .add_rule(&round_robin_balancer_rule("health-fallback"), true)
        .expect("add round robin");

    let mut sequence = Vec::new();
    for _ in 0..6 {
        sequence.push(
            runtime
                .router
                .pick_route(route_context("localhost"))
                .await
                .expect("pick")
                .outbound_tag,
        );
    }
    assert!(sequence.iter().all(|tag| tag != "health-dead"));
    assert!(sequence.contains(&"health-direct".to_string()));
    assert!(sequence.contains(&"health-alt".to_string()));
}

#[tokio::test]
async fn all_dead_with_fallback_routes_to_fallback() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = Arc::new({
        let outbound = rust_xray::runtime::RuntimeOutboundManager::new();
        outbound
            .add_outbound(encode_blackhole_outbound("health-direct"))
            .expect("direct");
        outbound
            .add_outbound(encode_blackhole_outbound("health-dead"))
            .expect("dead");
        outbound
            .add_outbound(encode_freedom_outbound("health-fallback"))
            .expect("fallback");
        rust_xray::outbound::runtime::OutboundConnectRuntime::init_shared(
            &rust_xray::config::XrayConfig {
                log: None,
                api: None,
                dns: None,
                stats: None,
                policy: None,
                routing: None,
                observatory: None,
                burst_observatory: None,
                outbounds: vec![],
                inbounds: vec![],
                extra: Default::default(),
            },
        );
        HandlerRuntime::for_observatory_routing_tests(
            Arc::new(StatsRegistry::new()),
            ObservatoryRuntimeConfig::for_test(
                vec!["health-".to_string()],
                probe_url(probe_addr),
                Duration::from_secs(60),
                true,
            ),
            vec![
                encode_blackhole_outbound("health-direct"),
                encode_blackhole_outbound("health-dead"),
                encode_freedom_outbound("health-fallback"),
            ],
        )
    });
    probe_standard(&runtime).await;

    for strategy in ["leastPing", "leastLoad"] {
        runtime
            .router
            .add_rule(
                &if strategy == "leastLoad" {
                    least_load_balancer_rule(
                        StrategyLeastLoadConfig {
                            expected: 1,
                            ..Default::default()
                        },
                        "health-fallback",
                    )
                } else {
                    least_ping_balancer_rule("health-fallback")
                },
                false,
            )
            .expect("add rule");
        let tag = runtime
            .router
            .pick_route(route_context("localhost"))
            .await
            .expect(strategy)
            .outbound_tag;
        assert_eq!(tag, "health-fallback", "{strategy}");
    }
}

#[tokio::test]
async fn dynamic_add_rule_after_health_exists_uses_live_provider() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;

    runtime
        .router
        .add_rule(&least_ping_balancer_rule(""), true)
        .expect("dynamic add");
    assert_eq!(
        runtime
            .router
            .get_balancer_principle_targets("health-balancer")
            .expect("principle"),
        vec!["health-direct"]
    );
}

#[tokio::test]
async fn replace_routing_table_keeps_live_health_provider() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_handler, mut routing) = connect_routing_clients(grpc_addr).await;
    tonic_add_rule_replace(&mut routing, least_ping_balancer_rule("")).await;
    let info = routing
        .get_balancer_info(GetBalancerInfoRequest {
            tag: "health-balancer".to_string(),
        })
        .await
        .expect("balancer info")
        .into_inner()
        .balancer
        .expect("balancer");
    assert_eq!(
        info.principle_target.expect("principle").tag,
        vec!["health-direct"]
    );
}

#[tokio::test]
async fn observatory_service_and_router_share_live_state() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind api");
    let addr = listener.local_addr().expect("addr");
    let runtime_for_api = Arc::clone(&runtime);
    tokio::spawn(async move {
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Observatory, ApiService::Routing],
            Arc::new(StatsRegistry::new()),
            runtime_for_api,
            ApiTransportMode::Plaintext,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut observatory = ObservatoryServiceClient::new(channel.clone());
    let mut routing = rust_xray::api::proto::app::router::command::routing_service_client::RoutingServiceClient::new(channel);

    runtime
        .router
        .add_rule(&least_ping_balancer_rule(""), true)
        .expect("add rule");

    let api: GetOutboundStatusResponse = observatory
        .get_outbound_status(GetOutboundStatusRequest {})
        .await
        .expect("api status")
        .into_inner();
    let api_status = api.status.expect("status");
    let api_direct = status_by_tag(&api_status, "health-direct").expect("direct");
    assert!(api_direct.alive);

    let test = routing
        .test_route(TestRouteRequest {
            routing_context: Some(tonic_routing_context("localhost")),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("test route")
        .into_inner();
    assert_eq!(test.outbound_tag, "health-direct");
}

#[tokio::test]
async fn coexistence_router_uses_standard_not_burst_health() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let url = probe_url(probe_addr);
    let runtime = HandlerRuntime::for_coexistence_observatory_tests(
        Arc::new(StatsRegistry::new()),
        ObservatoryRuntimeConfig::for_test(
            vec!["health-".to_string()],
            url.clone(),
            Duration::from_secs(60),
            true,
        ),
        BurstObservatoryRuntimeConfig::for_test(
            vec!["health-".to_string()],
            HealthPingRuntimeConfig::for_test(
                url,
                "",
                Duration::from_secs(30),
                3,
                Duration::from_secs(5),
                "HEAD",
            ),
        ),
        health_outbounds(),
    );
    runtime.start_observatory();
    runtime
        .standard_observatory
        .as_ref()
        .unwrap()
        .probe_once()
        .await;
    runtime
        .burst_observatory
        .as_ref()
        .unwrap()
        .check(&["health-direct".to_string(), "health-dead".to_string()])
        .await;

    let router_provider = runtime.router.health_provider();
    let standard = runtime.standard_observatory.as_ref().unwrap();
    let burst = runtime.burst_observatory.as_ref().unwrap();
    assert!(Arc::ptr_eq(
        &router_provider,
        &(Arc::clone(standard) as Arc<dyn OutboundHealthProvider>)
    ));

    let burst_obs = burst.observations().expect("burst");
    let router_obs = router_provider.observations().expect("router");
    let burst_direct = burst_obs
        .iter()
        .find(|item| item.outbound_tag == "health-direct")
        .expect("burst direct");
    let router_direct = router_obs
        .iter()
        .find(|item| item.outbound_tag == "health-direct")
        .expect("router direct");
    assert!(burst_direct.health_ping.is_some());
    assert!(router_direct.health_ping.is_none());
}

#[tokio::test]
async fn observatory_routing_works_without_observatory_service_api() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;
    runtime
        .router
        .add_rule(&least_ping_balancer_rule(""), true)
        .expect("add rule");
    assert_eq!(
        runtime
            .router
            .pick_route(route_context("localhost"))
            .await
            .expect("route")
            .outbound_tag,
        "health-direct"
    );
}

#[tokio::test]
async fn dynamic_outbound_add_and_remove_interacts_with_live_balancer() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    probe_standard(&runtime).await;
    runtime
        .router
        .add_rule(&least_ping_balancer_rule(""), true)
        .expect("add rule");

    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("health-new"))
        .expect("add outbound");
    runtime
        .standard_observatory
        .as_ref()
        .unwrap()
        .probe_once()
        .await;
    let obs = runtime
        .router
        .health_provider()
        .observations()
        .expect("observations");
    assert!(obs.iter().any(|item| item.outbound_tag == "health-new"));

    runtime
        .outbound
        .remove_outbound("health-direct")
        .expect("remove");
    for _ in 0..8 {
        let tag = runtime
            .router
            .pick_route(route_context("localhost"))
            .await
            .expect("pick")
            .outbound_tag;
        assert_ne!(tag, "health-direct");
    }
}

#[tokio::test]
async fn burst_least_load_tolerance_and_max_rtt_use_live_provider() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = burst_observatory_runtime(&probe_url(probe_addr));
    probe_burst(&runtime).await;

    runtime
        .router
        .add_rule(
            &least_load_balancer_rule(
                StrategyLeastLoadConfig {
                    expected: 1,
                    max_rtt: 50_000_000,
                    tolerance: 0.5,
                    ..Default::default()
                },
                "",
            ),
            true,
        )
        .expect("add leastLoad maxRTT");
    assert_eq!(
        runtime
            .router
            .pick_route(route_context("localhost"))
            .await
            .expect("route")
            .outbound_tag,
        "health-direct"
    );
}

#[tokio::test]
async fn concurrent_probe_and_routing_stress() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = standard_observatory_runtime(&probe_url(probe_addr));
    runtime.start_observatory();
    runtime
        .router
        .add_rule(&least_ping_balancer_rule("health-fallback"), true)
        .expect("add rule");

    let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
    let (_handler, routing) = connect_routing_clients(grpc_addr).await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let runtime = Arc::clone(&runtime);
        handles.push(tokio::spawn(async move {
            for _ in 0..20 {
                let _ = runtime.router.pick_route(route_context("localhost")).await;
            }
        }));
    }
    for _ in 0..4 {
        let mut routing = routing.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..10 {
                let _ = routing
                    .test_route(TestRouteRequest {
                        routing_context: Some(tonic_routing_context("localhost")),
                        field_selectors: vec!["outbound".to_string()],
                        publish_result: false,
                    })
                    .await;
            }
        }));
    }
    for handle in handles {
        handle.await.expect("stress task");
    }
    runtime.shutdown_observatory().await;
}

struct FixedDelaySource {
    direct: Duration,
    dead: Duration,
}

impl ProbeDelaySource for FixedDelaySource {
    fn delay(&self, _max: Duration, seed: u64) -> Duration {
        if seed % 2 == 0 {
            self.direct
        } else {
            self.dead
        }
    }
}

#[tokio::test]
async fn burst_least_load_ranking_uses_health_ping_from_live_provider() {
    let _guard = test_serial().await;
    let (probe_addr, _probe) = spawn_probe_server(ProbeServerMode::Ok204).await;
    let runtime = burst_observatory_runtime(&probe_url(probe_addr));
    let burst = runtime.burst_observatory.as_ref().unwrap();
    burst
        .set_test_hooks(BurstTestHooks {
            delay_source: Some(Arc::new(FixedDelaySource {
                direct: Duration::from_millis(5),
                dead: Duration::from_millis(5),
            })),
            ..Default::default()
        })
        .await;
    runtime
        .outbound
        .add_outbound(encode_freedom_outbound("health-alt"))
        .expect("alt");
    burst
        .check(&[
            "health-direct".to_string(),
            "health-alt".to_string(),
            "health-dead".to_string(),
        ])
        .await;

    runtime
        .router
        .add_rule(
            &least_load_balancer_rule(
                StrategyLeastLoadConfig {
                    expected: 1,
                    ..Default::default()
                },
                "",
            ),
            true,
        )
        .expect("add leastLoad");
    let tag = runtime
        .router
        .pick_route(route_context("localhost"))
        .await
        .expect("route")
        .outbound_tag;
    assert_ne!(tag, "health-dead");
}
