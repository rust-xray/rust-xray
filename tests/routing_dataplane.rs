use std::sync::Arc;

use prost::Message;
use rust_xray::api::proto::app::router::command::RoutingContext;
use rust_xray::api::proto::app::router::{Config as RouterConfig, RoutingRule};
use rust_xray::api::proto::common::geodata::{domain, domain_rule, Domain, DomainRule};
use rust_xray::api::proto::common::net::Network;
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::routing::{route_context_from_proto, ROUTER_CONFIG_TYPE};
use rust_xray::runtime::{encode_freedom_outbound, HandlerRuntime};
use rust_xray::stats::StatsRegistry;

#[tokio::test]
async fn test_route_matches_runtime_pick_route_for_user_rule() {
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
    runtime
        .router
        .add_rule(
            &TypedMessage {
                r#type: ROUTER_CONFIG_TYPE.to_string(),
                value: RouterConfig {
                    rule: vec![RoutingRule {
                        target_tag: Some(
                            rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                                "direct-b".to_string(),
                            ),
                        ),
                        rule_tag: "user-rule".to_string(),
                        user_email: vec!["alice@example.com".to_string()],
                        ..Default::default()
                    }],
                    ..Default::default()
                }
                .encode_to_vec(),
            },
            true,
        )
        .expect("add rule");

    let route_ctx = route_context_from_proto(&RoutingContext {
        inbound_tag: "vless-in".to_string(),
        network: Network::Tcp as i32,
        user: "alice@example.com".to_string(),
        ..Default::default()
    });
    let picked = runtime
        .router
        .pick_route_with_default(route_ctx.clone())
        .await
        .expect("pick");
    let again = runtime
        .router
        .pick_route_with_default(route_ctx)
        .await
        .expect("pick again");
    assert_eq!(picked.outbound_tag, "direct-b");
    assert_eq!(picked.rule_tag, "user-rule");
    assert_eq!(again.outbound_tag, picked.outbound_tag);
    assert_eq!(again.rule_tag, picked.rule_tag);
}

#[tokio::test]
async fn domain_rule_pick_route_matches_test_route_semantics() {
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
    runtime
        .router
        .add_rule(
            &TypedMessage {
                r#type: ROUTER_CONFIG_TYPE.to_string(),
                value: RouterConfig {
                    rule: vec![RoutingRule {
                        target_tag: Some(
                            rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                                "direct-b".to_string(),
                            ),
                        ),
                        rule_tag: "domain-rule".to_string(),
                        domain: vec![DomainRule {
                            value: Some(domain_rule::Value::Custom(Domain {
                                r#type: domain::Type::Domain as i32,
                                value: "example.com".to_string(),
                                attribute: vec![],
                            })),
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }
                .encode_to_vec(),
            },
            true,
        )
        .expect("add");

    let ctx = route_context_from_proto(&RoutingContext {
        target_domain: "www.example.com".to_string(),
        ..Default::default()
    });
    let decision = runtime
        .router
        .pick_route_with_default(ctx)
        .await
        .expect("route");
    assert_eq!(decision.outbound_tag, "direct-b");
    assert_eq!(decision.rule_tag, "domain-rule");
}

mod e2e {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use prost::Message;
    use rust_xray::api::proto::app::proxyman::command::handler_service_client::HandlerServiceClient;
    use rust_xray::api::proto::app::proxyman::command::{
        AddOutboundRequest, AddUserOperation, AlterInboundRequest,
    };
    use rust_xray::api::proto::app::router::command::routing_service_client::RoutingServiceClient;
    use rust_xray::api::proto::app::router::command::{
        AddRuleRequest, OverrideBalancerTargetRequest, RemoveRuleRequest, TestRouteRequest,
    };
    use rust_xray::api::proto::app::router::{
        BalancingRule, Config as RouterConfig, RoutingRule, WebhookConfig,
    };
    use rust_xray::api::proto::common::geodata::{
        domain, domain_rule, ip_rule, Cidr, Domain, DomainRule, GeoIp, GeoIpRule, GeoSite,
        GeoSiteRule, IpRule,
    };
    use rust_xray::api::proto::common::net::{Network, PortList, PortRange};
    use rust_xray::api::proto::common::protocol::User;
    use rust_xray::api::proto::common::serial::TypedMessage;
    use rust_xray::api::proto::proxy::vless::Account;
    use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
    use rust_xray::config::XrayConfig;
    use rust_xray::dns::config::{parse_dns_server, DnsConfig, QueryStrategy};
    use rust_xray::dns::tcp_codec::{encode_dns_tcp_frame, read_dns_tcp_response};
    use rust_xray::outbound::OutboundConnectRuntime;
    use rust_xray::routing::{vless_route_from_uuid, ROUTER_CONFIG_TYPE};
    use rust_xray::runtime::{encode_blackhole_outbound, encode_freedom_outbound, HandlerRuntime};
    use rust_xray::stats::StatsRegistry;
    use rust_xray::vless::config::VlessClient;
    use rust_xray::vless::handle_vless_tcp_inbound;
    use rust_xray::vless::user_manager::VlessUserManager;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tonic::transport::Endpoint;
    use uuid::Uuid;

    const USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    fn build_vless_domain_request(user_id: &[u8; 16], domain: &str, port: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(user_id);
        buf.push(0);
        buf.push(0x01);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.push(0x02);
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain.as_bytes());
        buf
    }

    fn example_test_dns_query() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(b"\x0bexample\x04test\0");
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        packet
    }

    fn build_dns_a_response(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[6] = 0;
        resp[7] = 1;
        resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
        resp.extend_from_slice(&ip.octets());
        resp
    }

    async fn spawn_mock_dns_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind dns");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let query = match read_dns_tcp_response(&mut stream, 512).await {
                        Ok(query) => query,
                        Err(_) => return,
                    };
                    let response = build_dns_a_response(&query, Ipv4Addr::LOCALHOST);
                    let frame = encode_dns_tcp_frame(&response).expect("frame");
                    let _ = stream.write_all(&frame).await;
                });
            }
        });
        port
    }

    async fn spawn_target_listener() -> (u16, oneshot::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            if listener.accept().await.is_ok() {
                let _ = tx.send(());
            }
        });
        (port, rx)
    }

    async fn spawn_webhook_server() -> (String, tokio::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind webhook");
        let addr = listener.local_addr().expect("webhook addr");
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0_u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut buf).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..read]);
                        let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let head = String::from_utf8_lossy(&request[..header_end + 4]);
                        let content_len = head
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if request.len() >= header_end + 4 + content_len {
                            break;
                        }
                    }
                    let _ = tx
                        .send(String::from_utf8_lossy(&request).into_owned())
                        .await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        (format!("http://{addr}/route"), rx)
    }

    async fn init_connect_runtime(dns_port: u16) {
        let server = parse_dns_server(&format!("tcp://127.0.0.1:{dns_port}")).expect("dns server");
        let dns = DnsConfig {
            servers: vec![server],
            query_strategy: QueryStrategy::UseIPv4,
            disable_cache: false,
            extra: Default::default(),
        };
        rust_xray::dns::DnsEngine::init_shared(Some(&dns));
        let xray = XrayConfig {
            log: None,
            api: None,
            dns: Some(dns.clone()),
            stats: None,
            policy: None,
            routing: Some(rust_xray::config::xray::raw::RoutingConfig {
                domain_strategy: Some("UseIp".to_string()),
                ..Default::default()
            }),
            observatory: None,
            burst_observatory: None,
            outbounds: vec![],
            inbounds: vec![],
            extra: Default::default(),
        };
        OutboundConnectRuntime::init_shared(&xray);
    }

    async fn spawn_routing_server(runtime: Arc<HandlerRuntime>) -> SocketAddr {
        let registry = Arc::new(StatsRegistry::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind grpc");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = serve_grpc_on(
                listener,
                vec![ApiService::Routing, ApiService::Handler],
                registry,
                runtime,
                ApiTransportMode::Plaintext,
            )
            .await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        addr
    }

    fn domain_rule_message(domain: &str, tag: &str, rule_tag: &str) -> TypedMessage {
        TypedMessage {
            r#type: ROUTER_CONFIG_TYPE.to_string(),
            value: RouterConfig {
                rule: vec![RoutingRule {
                    target_tag: Some(
                        rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                            tag.to_string(),
                        ),
                    ),
                    rule_tag: rule_tag.to_string(),
                    domain: vec![DomainRule {
                        value: Some(domain_rule::Value::Custom(Domain {
                            r#type: domain::Type::Full as i32,
                            value: domain.to_string(),
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

    async fn dial_vless(
        vless_addr: SocketAddr,
        target_port: u16,
        domain: &str,
    ) -> std::io::Result<()> {
        let mut stream = TcpStream::connect(vless_addr).await?;
        stream
            .write_all(&build_vless_domain_request(&USER_ID, domain, target_port))
            .await?;
        let mut buf = [0u8; 64];
        let _ = stream.read(&mut buf).await?;
        stream.shutdown().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    fn build_vless_ip_request(user_id: &[u8; 16], port: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(user_id);
        buf.push(0);
        buf.push(0x01);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.push(0x01);
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf
    }

    async fn dial_vless_ip(vless_addr: SocketAddr, target_port: u16) -> std::io::Result<()> {
        let mut stream = TcpStream::connect(vless_addr).await?;
        stream
            .write_all(&build_vless_ip_request(&USER_ID, target_port))
            .await?;
        let mut buf = [0u8; 64];
        let _ = stream.read(&mut buf).await?;
        stream.shutdown().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    fn user_rule_message(email: &str, tag: &str, rule_tag: &str) -> TypedMessage {
        TypedMessage {
            r#type: ROUTER_CONFIG_TYPE.to_string(),
            value: RouterConfig {
                rule: vec![RoutingRule {
                    target_tag: Some(
                        rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                            tag.to_string(),
                        ),
                    ),
                    rule_tag: rule_tag.to_string(),
                    user_email: vec![email.to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        }
    }

    fn protocol_rule_message(protocol: &str, tag: &str, rule_tag: &str) -> TypedMessage {
        TypedMessage {
            r#type: ROUTER_CONFIG_TYPE.to_string(),
            value: RouterConfig {
                rule: vec![RoutingRule {
                    target_tag: Some(
                        rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                            tag.to_string(),
                        ),
                    ),
                    rule_tag: rule_tag.to_string(),
                    protocol: vec![protocol.to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        }
    }

    fn vless_route_rule_message(route: u16, tag: &str, rule_tag: &str) -> TypedMessage {
        TypedMessage {
            r#type: ROUTER_CONFIG_TYPE.to_string(),
            value: RouterConfig {
                rule: vec![RoutingRule {
                    target_tag: Some(
                        rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                            tag.to_string(),
                        ),
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

    fn encode_geodata_record<M: Message>(message: &M) -> Vec<u8> {
        let body = message.encode_to_vec();
        let mut out = vec![0_u8];
        let mut len = body.len() as u64;
        loop {
            let mut byte = (len & 0x7f) as u8;
            len >>= 7;
            if len != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if len == 0 {
                break;
            }
        }
        out.extend_from_slice(&body);
        out
    }

    fn geosite_rule_message(file: &str, attrs: &str, tag: &str, rule_tag: &str) -> TypedMessage {
        TypedMessage {
            r#type: ROUTER_CONFIG_TYPE.to_string(),
            value: RouterConfig {
                rule: vec![RoutingRule {
                    target_tag: Some(
                        rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                            tag.to_string(),
                        ),
                    ),
                    rule_tag: rule_tag.to_string(),
                    domain: vec![DomainRule {
                        value: Some(domain_rule::Value::Geosite(GeoSiteRule {
                            file: file.to_string(),
                            code: "TEST".to_string(),
                            attrs: attrs.to_string(),
                        })),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        }
    }

    fn geoip_rule_message(
        file: &str,
        reverse_match: bool,
        tag: &str,
        rule_tag: &str,
    ) -> TypedMessage {
        TypedMessage {
            r#type: ROUTER_CONFIG_TYPE.to_string(),
            value: RouterConfig {
                rule: vec![RoutingRule {
                    target_tag: Some(
                        rust_xray::api::proto::app::router::routing_rule::TargetTag::Tag(
                            tag.to_string(),
                        ),
                    ),
                    rule_tag: rule_tag.to_string(),
                    ip: vec![IpRule {
                        value: Some(ip_rule::Value::Geoip(GeoIpRule {
                            file: file.to_string(),
                            code: "TEST".to_string(),
                            reverse_match,
                        })),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec(),
        }
    }

    fn webhook_rule_message(domain: &str, tag: &str, url: String) -> TypedMessage {
        let mut config = domain_rule_message(domain, tag, "webhook-rule");
        let mut decoded = RouterConfig::decode(config.value.as_slice()).expect("decode rule");
        decoded.rule[0].webhook = Some(WebhookConfig {
            url,
            deduplication: 2,
            headers: [("X-Routing-Test".to_string(), "stage-8e2".to_string())]
                .into_iter()
                .collect(),
        });
        config.value = decoded.encode_to_vec();
        config
    }

    fn balancer_rule_message(strategy: &str) -> TypedMessage {
        TypedMessage {
            r#type: ROUTER_CONFIG_TYPE.to_string(),
            value: RouterConfig {
                balancing_rule: vec![BalancingRule {
                    tag: "live-balancer".to_string(),
                    outbound_selector: vec!["candidate-".to_string()],
                    strategy: strategy.to_string(),
                    ..Default::default()
                }],
                rule: vec![RoutingRule {
                    target_tag: Some(
                        rust_xray::api::proto::app::router::routing_rule::TargetTag::BalancingTag(
                            "live-balancer".to_string(),
                        ),
                    ),
                    rule_tag: "live-balancer-rule".to_string(),
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

    fn add_user_request(inbound_tag: &str, email: &str, id: &str) -> AlterInboundRequest {
        let account = Account {
            id: id.to_string(),
            encryption: "none".to_string(),
            ..Default::default()
        };
        AlterInboundRequest {
            tag: inbound_tag.to_string(),
            operation: Some(TypedMessage {
                r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
                value: AddUserOperation {
                    user: Some(User {
                        email: email.to_string(),
                        account: Some(TypedMessage {
                            r#type: "xray.proxy.vless.Account".to_string(),
                            value: account.encode_to_vec(),
                        }),
                        ..Default::default()
                    }),
                }
                .encode_to_vec(),
            }),
        }
    }

    async fn dial_vless_ip_with_payload(
        vless_addr: SocketAddr,
        target_port: u16,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let mut request = build_vless_ip_request(&USER_ID, target_port);
        request.extend_from_slice(payload);
        let mut stream = TcpStream::connect(vless_addr).await?;
        stream.write_all(&request).await?;
        let mut response = [0_u8; 2];
        let _ = stream.read(&mut response).await?;
        stream.shutdown().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn target_hit_within(rx: oneshot::Receiver<()>, ms: u64) -> bool {
        tokio::time::timeout(Duration::from_millis(ms), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
    }

    #[tokio::test]
    async fn vless_tcp_add_rule_routes_user_to_blackhole_and_remove_restores_freedom() {
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("direct-a");
        runtime
            .outbound
            .add_outbound(encode_blackhole_outbound("direct-b"))
            .expect("direct-b");

        let users = Arc::new(VlessUserManager::new(
            "vless-in",
            vec![VlessClient {
                id: Uuid::from_bytes(USER_ID),
                email: Some("route-user@example.com".to_string()),
                flow: None,
                level: None,
            }],
        ));
        let router = Arc::clone(&runtime.router);

        let vless_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
        let vless_addr = vless_listener.local_addr().expect("vless addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = vless_listener.accept().await else {
                    break;
                };
                let users = Arc::clone(&users);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _ = handle_vless_tcp_inbound(
                        stream,
                        users.as_ref(),
                        None,
                        Some(peer.ip()),
                        Some(&router),
                    )
                    .await;
                });
            }
        });

        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let mut routing = RoutingServiceClient::new(
            Endpoint::from_shared(format!("http://{grpc_addr}"))
                .expect("endpoint")
                .connect()
                .await
                .expect("connect"),
        );

        let (target_port, hit_a) = spawn_target_listener().await;
        dial_vless_ip(vless_addr, target_port)
            .await
            .expect("vless dial default");
        assert!(
            target_hit_within(hit_a, 2000).await,
            "default freedom outbound must reach target"
        );

        routing
            .add_rule(AddRuleRequest {
                config: Some(user_rule_message(
                    "route-user@example.com",
                    "direct-b",
                    "route-user",
                )),
                should_append: true,
            })
            .await
            .expect("add rule")
            .into_inner();

        let (target_port, hit_b) = spawn_target_listener().await;
        dial_vless_ip(vless_addr, target_port)
            .await
            .expect("vless dial blackhole");
        assert!(
            !target_hit_within(hit_b, 500).await,
            "blackhole outbound must not reach target"
        );

        routing
            .remove_rule(RemoveRuleRequest {
                rule_tag: "route-user".to_string(),
            })
            .await
            .expect("remove rule")
            .into_inner();

        let (target_port, hit_a2) = spawn_target_listener().await;
        dial_vless_ip(vless_addr, target_port)
            .await
            .expect("vless dial restored");
        assert!(
            target_hit_within(hit_a2, 2000).await,
            "removed rule must restore freedom outbound"
        );
    }

    #[tokio::test]
    async fn vless_route_covers_static_dynamic_and_custom_ids_on_real_connections() {
        const INBOUND: &str = "vless-route-in";
        const DYNAMIC_ID: &str = "22222222-2222-2222-2222-222222222222";
        const OUTSIDE_ID: &str = "33333333-3333-3333-3333-333333333333";
        const CUSTOM_ID: &str = "route-custom-id";

        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("direct-a");
        runtime
            .outbound
            .add_outbound(encode_blackhole_outbound("direct-b"))
            .expect("direct-b");

        let outside_uuid = Uuid::parse_str(OUTSIDE_ID).expect("outside uuid");
        let users = Arc::new(VlessUserManager::new(
            INBOUND,
            vec![
                VlessClient {
                    id: Uuid::from_bytes(USER_ID),
                    email: Some("static-route@example.test".to_string()),
                    flow: None,
                    level: None,
                },
                VlessClient {
                    id: outside_uuid,
                    email: Some("outside-route@example.test".to_string()),
                    flow: None,
                    level: None,
                },
            ],
        ));
        runtime.inbound.user_managers().register(Arc::clone(&users));

        let router = Arc::clone(&runtime.router);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
        let vless_addr = listener.local_addr().expect("vless addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let socket_meta = rust_xray::routing::RouteSocketMeta::from_tcp_stream(&stream);
                let users = Arc::clone(&users);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _ = rust_xray::vless::handle_vless_tcp_inbound_with_socket_meta(
                        stream,
                        users.as_ref(),
                        None,
                        &socket_meta,
                        Some(&router),
                    )
                    .await;
                });
            }
        });

        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let channel = Endpoint::from_shared(format!("http://{grpc_addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect");
        let mut handler = HandlerServiceClient::new(channel.clone());
        let mut routing = RoutingServiceClient::new(channel);
        handler
            .alter_inbound(add_user_request(
                INBOUND,
                "dynamic-route@example.test",
                DYNAMIC_ID,
            ))
            .await
            .expect("add dynamic uuid");
        handler
            .alter_inbound(add_user_request(
                INBOUND,
                "custom-route@example.test",
                CUSTOM_ID,
            ))
            .await
            .expect("add custom id");

        let dynamic_uuid = Uuid::parse_str(DYNAMIC_ID).expect("dynamic uuid");
        let custom_uuid = rust_xray::vless::parse_vless_user_id(CUSTOM_ID).expect("custom uuid");
        for (name, id) in [
            ("static", Uuid::from_bytes(USER_ID)),
            ("dynamic", dynamic_uuid),
            ("custom", custom_uuid),
        ] {
            routing
                .add_rule(AddRuleRequest {
                    config: Some(vless_route_rule_message(
                        vless_route_from_uuid(&id),
                        "direct-b",
                        &format!("vless-route-{name}"),
                    )),
                    should_append: true,
                })
                .await
                .expect("add vless route rule");

            let (target_port, hit) = spawn_target_listener().await;
            let mut stream = TcpStream::connect(vless_addr).await.expect("connect vless");
            stream
                .write_all(&build_vless_ip_request(id.as_bytes(), target_port))
                .await
                .expect("write request");
            let mut response = [0_u8; 2];
            let _ = stream.read(&mut response).await;
            assert!(
                !target_hit_within(hit, 300).await,
                "{name} VlessRoute must select blackhole"
            );
        }

        let (target_port, hit) = spawn_target_listener().await;
        let mut stream = TcpStream::connect(vless_addr)
            .await
            .expect("connect outside");
        stream
            .write_all(&build_vless_ip_request(
                outside_uuid.as_bytes(),
                target_port,
            ))
            .await
            .expect("write outside");
        let mut response = [0_u8; 2];
        let _ = stream.read(&mut response).await;
        assert!(
            target_hit_within(hit, 2000).await,
            "user outside every VlessRoute range must use default outbound"
        );
    }

    #[tokio::test]
    async fn handler_add_user_and_routing_user_email_rule_drive_real_traffic() {
        const INBOUND: &str = "dynamic-user-in";
        const DYNAMIC_ID: &str = "44444444-4444-4444-4444-444444444444";
        const OTHER_ID: &str = "55555555-5555-5555-5555-555555555555";

        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("direct-a");
        runtime
            .outbound
            .add_outbound(encode_blackhole_outbound("direct-b"))
            .expect("direct-b");
        let other_uuid = Uuid::parse_str(OTHER_ID).expect("other uuid");
        let users = Arc::new(VlessUserManager::new(
            INBOUND,
            vec![VlessClient {
                id: other_uuid,
                email: Some("other@example.test".to_string()),
                flow: None,
                level: None,
            }],
        ));
        runtime.inbound.user_managers().register(Arc::clone(&users));
        let router = Arc::clone(&runtime.router);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
        let vless_addr = listener.local_addr().expect("vless addr");
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let users = Arc::clone(&users);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _ = handle_vless_tcp_inbound(
                        stream,
                        users.as_ref(),
                        None,
                        Some(peer.ip()),
                        Some(&router),
                    )
                    .await;
                });
            }
        });

        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let channel = Endpoint::from_shared(format!("http://{grpc_addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect");
        let mut handler = HandlerServiceClient::new(channel.clone());
        let mut routing = RoutingServiceClient::new(channel);
        handler
            .alter_inbound(add_user_request(
                INBOUND,
                "dynamic@example.test",
                DYNAMIC_ID,
            ))
            .await
            .expect("HandlerService AddUser");
        routing
            .add_rule(AddRuleRequest {
                config: Some(user_rule_message(
                    "dynamic@example.test",
                    "direct-b",
                    "dynamic-user-rule",
                )),
                should_append: true,
            })
            .await
            .expect("RoutingService AddRule");

        let dynamic_uuid = Uuid::parse_str(DYNAMIC_ID).expect("dynamic uuid");
        let (target_port, hit) = spawn_target_listener().await;
        let mut stream = TcpStream::connect(vless_addr)
            .await
            .expect("connect dynamic");
        stream
            .write_all(&build_vless_ip_request(
                dynamic_uuid.as_bytes(),
                target_port,
            ))
            .await
            .expect("write dynamic");
        let mut response = [0_u8; 2];
        let _ = stream.read(&mut response).await;
        assert!(!target_hit_within(hit, 400).await, "dynamic user route");

        let (target_port, hit) = spawn_target_listener().await;
        let mut stream = TcpStream::connect(vless_addr).await.expect("connect other");
        stream
            .write_all(&build_vless_ip_request(other_uuid.as_bytes(), target_port))
            .await
            .expect("write other");
        let _ = stream.read(&mut response).await;
        assert!(
            target_hit_within(hit, 2000).await,
            "non-matching user must use default outbound"
        );
    }

    #[tokio::test]
    async fn vless_tcp_add_rule_routes_domain_to_blackhole_and_remove_restores_freedom() {
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("direct-a");
        runtime
            .outbound
            .add_outbound(encode_blackhole_outbound("direct-b"))
            .expect("direct-b");

        let users = Arc::new(VlessUserManager::new(
            "vless-in",
            vec![VlessClient {
                id: Uuid::from_bytes(USER_ID),
                email: Some("user@example.com".to_string()),
                flow: None,
                level: None,
            }],
        ));
        let router = Arc::clone(&runtime.router);

        let vless_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
        let vless_addr = vless_listener.local_addr().expect("vless addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = vless_listener.accept().await else {
                    break;
                };
                let users = Arc::clone(&users);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _ = handle_vless_tcp_inbound(
                        stream,
                        users.as_ref(),
                        None,
                        Some(peer.ip()),
                        Some(&router),
                    )
                    .await;
                });
            }
        });

        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let mut routing = RoutingServiceClient::new(
            Endpoint::from_shared(format!("http://{grpc_addr}"))
                .expect("endpoint")
                .connect()
                .await
                .expect("connect"),
        );

        let (target_port, hit_a) = spawn_target_listener().await;
        dial_vless(vless_addr, target_port, "localhost")
            .await
            .expect("vless dial default");
        assert!(
            target_hit_within(hit_a, 2000).await,
            "default freedom outbound must reach target"
        );

        routing
            .add_rule(AddRuleRequest {
                config: Some(domain_rule_message(
                    "localhost",
                    "direct-b",
                    "route-localhost",
                )),
                should_append: true,
            })
            .await
            .expect("add rule")
            .into_inner();

        let (target_port, hit_b) = spawn_target_listener().await;
        dial_vless(vless_addr, target_port, "localhost")
            .await
            .expect("vless dial blackhole");
        assert!(
            !target_hit_within(hit_b, 300).await,
            "blackhole outbound must not reach target"
        );

        routing
            .remove_rule(RemoveRuleRequest {
                rule_tag: "route-localhost".to_string(),
            })
            .await
            .expect("remove rule")
            .into_inner();

        let (target_port, hit_a2) = spawn_target_listener().await;
        dial_vless(vless_addr, target_port, "localhost")
            .await
            .expect("vless dial restored");
        assert!(
            target_hit_within(hit_a2, 2000).await,
            "removed rule must restore freedom outbound"
        );
    }

    #[tokio::test]
    async fn handler_add_outbound_is_immediately_routable_via_routing_service() {
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("direct-a");
        let users = Arc::new(VlessUserManager::new(
            "vless-in",
            vec![VlessClient {
                id: Uuid::from_bytes(USER_ID),
                email: Some("dynamic-outbound@example.test".to_string()),
                flow: None,
                level: None,
            }],
        ));
        let router = Arc::clone(&runtime.router);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
        let vless_addr = listener.local_addr().expect("vless addr");
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let users = Arc::clone(&users);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _ = handle_vless_tcp_inbound(
                        stream,
                        users.as_ref(),
                        None,
                        Some(peer.ip()),
                        Some(&router),
                    )
                    .await;
                });
            }
        });

        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let channel = Endpoint::from_shared(format!("http://{grpc_addr}"))
            .expect("endpoint")
            .connect()
            .await
            .expect("connect");
        let mut handler = HandlerServiceClient::new(channel.clone());
        let mut routing = RoutingServiceClient::new(channel);
        handler
            .add_outbound(AddOutboundRequest {
                outbound: Some(encode_blackhole_outbound("dynamic-out")),
            })
            .await
            .expect("HandlerService AddOutbound");
        routing
            .add_rule(AddRuleRequest {
                config: Some(domain_rule_message(
                    "dynamic-out.example",
                    "dynamic-out",
                    "dynamic-out-rule",
                )),
                should_append: true,
            })
            .await
            .expect("RoutingService AddRule");

        let (target_port, hit) = spawn_target_listener().await;
        dial_vless(vless_addr, target_port, "dynamic-out.example")
            .await
            .expect("dial routed traffic");
        assert!(
            !target_hit_within(hit, 400).await,
            "dynamically-added blackhole outbound must be used by live routing"
        );
    }

    #[tokio::test]
    async fn sniffed_tls_protocol_routes_only_when_inbound_sniffing_is_enabled() {
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("direct-a");
        runtime
            .outbound
            .add_outbound(encode_blackhole_outbound("direct-b"))
            .expect("direct-b");

        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let mut routing = RoutingServiceClient::new(
            Endpoint::from_shared(format!("http://{grpc_addr}"))
                .expect("endpoint")
                .connect()
                .await
                .expect("connect"),
        );
        routing
            .add_rule(AddRuleRequest {
                config: Some(protocol_rule_message("tls", "direct-b", "tls-rule")),
                should_append: true,
            })
            .await
            .expect("add protocol rule");

        async fn listener_for(runtime: &Arc<HandlerRuntime>, sniffing_enabled: bool) -> SocketAddr {
            let users = Arc::new(VlessUserManager::new_with_sniffing(
                "vless-in",
                vec![VlessClient {
                    id: Uuid::from_bytes(USER_ID),
                    email: Some("protocol@example.com".to_string()),
                    flow: None,
                    level: None,
                }],
                sniffing_enabled,
            ));
            let router = Arc::clone(&runtime.router);
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let address = listener.local_addr().expect("addr");
            tokio::spawn(async move {
                while let Ok((stream, peer)) = listener.accept().await {
                    let users = Arc::clone(&users);
                    let router = Arc::clone(&router);
                    tokio::spawn(async move {
                        let _ = handle_vless_tcp_inbound(
                            stream,
                            users.as_ref(),
                            None,
                            Some(peer.ip()),
                            Some(&router),
                        )
                        .await;
                    });
                }
            });
            address
        }

        let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x00];
        let enabled = listener_for(&runtime, true).await;
        let (port, hit) = spawn_target_listener().await;
        dial_vless_ip_with_payload(enabled, port, &tls_client_hello)
            .await
            .expect("enabled dial");
        assert!(
            !target_hit_within(hit, 400).await,
            "TLS protocol rule must select blackhole when sniffing is enabled"
        );

        let disabled = listener_for(&runtime, false).await;
        let (port, hit) = spawn_target_listener().await;
        dial_vless_ip_with_payload(disabled, port, &tls_client_hello)
            .await
            .expect("disabled dial");
        assert!(
            target_hit_within(hit, 2000).await,
            "payload must not gain protocol metadata when sniffing is disabled"
        );
    }

    #[tokio::test]
    async fn tonic_geosite_attrs_geoip_and_reverse_match_route_real_vless_traffic() {
        let site_file = tempfile::NamedTempFile::new().expect("site file");
        let attr = rust_xray::api::proto::common::geodata::domain::Attribute {
            key: "ads".to_string(),
            typed_value: Some(
                rust_xray::api::proto::common::geodata::domain::attribute::TypedValue::BoolValue(
                    true,
                ),
            ),
        };
        std::fs::write(
            site_file.path(),
            encode_geodata_record(&GeoSite {
                code: "TEST".to_string(),
                domain: vec![
                    Domain {
                        r#type: domain::Type::Full as i32,
                        value: "ads.example".to_string(),
                        attribute: vec![attr],
                    },
                    Domain {
                        r#type: domain::Type::Full as i32,
                        value: "localhost".to_string(),
                        attribute: vec![],
                    },
                ],
            }),
        )
        .expect("write site");
        let inside_file = tempfile::NamedTempFile::new().expect("inside file");
        std::fs::write(
            inside_file.path(),
            encode_geodata_record(&GeoIp {
                code: "TEST".to_string(),
                cidr: vec![Cidr {
                    ip: vec![127, 0, 0, 0],
                    prefix: 8,
                }],
                reverse_match: false,
            }),
        )
        .expect("write inside");
        let outside_file = tempfile::NamedTempFile::new().expect("outside file");
        std::fs::write(
            outside_file.path(),
            encode_geodata_record(&GeoIp {
                code: "TEST".to_string(),
                cidr: vec![Cidr {
                    ip: vec![10, 0, 0, 0],
                    prefix: 8,
                }],
                reverse_match: false,
            }),
        )
        .expect("write outside");

        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("direct-a");
        runtime
            .outbound
            .add_outbound(encode_blackhole_outbound("direct-b"))
            .expect("direct-b");
        let users = Arc::new(VlessUserManager::new(
            "geodata-in",
            vec![VlessClient {
                id: Uuid::from_bytes(USER_ID),
                email: Some("geo@example.test".to_string()),
                flow: None,
                level: None,
            }],
        ));
        let router = Arc::clone(&runtime.router);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
        let vless_addr = listener.local_addr().expect("vless addr");
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let users = Arc::clone(&users);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _ = handle_vless_tcp_inbound(
                        stream,
                        users.as_ref(),
                        None,
                        Some(peer.ip()),
                        Some(&router),
                    )
                    .await;
                });
            }
        });
        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let mut routing = RoutingServiceClient::new(
            Endpoint::from_shared(format!("http://{grpc_addr}"))
                .expect("endpoint")
                .connect()
                .await
                .expect("connect"),
        );

        routing
            .add_rule(AddRuleRequest {
                config: Some(geosite_rule_message(
                    site_file.path().to_str().expect("site path"),
                    "ads",
                    "direct-b",
                    "geosite-attrs",
                )),
                should_append: false,
            })
            .await
            .expect("add geosite");
        let (port, hit) = spawn_target_listener().await;
        dial_vless(vless_addr, port, "ads.example")
            .await
            .expect("ads dial");
        assert!(!target_hit_within(hit, 300).await, "attribute match");
        let (port, hit) = spawn_target_listener().await;
        dial_vless(vless_addr, port, "localhost")
            .await
            .expect("plain dial");
        assert!(
            target_hit_within(hit, 2000).await,
            "non-selected geosite attribute entry"
        );

        routing
            .add_rule(AddRuleRequest {
                config: Some(geoip_rule_message(
                    inside_file.path().to_str().expect("inside path"),
                    false,
                    "direct-b",
                    "geoip-inside",
                )),
                should_append: false,
            })
            .await
            .expect("add geoip inside");
        let (port, hit) = spawn_target_listener().await;
        dial_vless_ip(vless_addr, port).await.expect("inside dial");
        assert!(!target_hit_within(hit, 300).await, "GeoIP inside CIDR");

        routing
            .add_rule(AddRuleRequest {
                config: Some(geoip_rule_message(
                    outside_file.path().to_str().expect("outside path"),
                    false,
                    "direct-b",
                    "geoip-outside",
                )),
                should_append: false,
            })
            .await
            .expect("add geoip outside");
        let (port, hit) = spawn_target_listener().await;
        dial_vless_ip(vless_addr, port).await.expect("outside dial");
        assert!(target_hit_within(hit, 2000).await, "GeoIP outside CIDR");

        routing
            .add_rule(AddRuleRequest {
                config: Some(geoip_rule_message(
                    outside_file.path().to_str().expect("outside path"),
                    true,
                    "direct-b",
                    "geoip-reverse",
                )),
                should_append: false,
            })
            .await
            .expect("add reverse geoip");
        let (port, hit) = spawn_target_listener().await;
        dial_vless_ip(vless_addr, port).await.expect("reverse dial");
        assert!(!target_hit_within(hit, 300).await, "GeoIP reverse_match");
    }

    #[tokio::test]
    async fn webhook_fires_for_real_traffic_deduplicates_and_stops_after_remove() {
        let (webhook_url, mut webhook_requests) = spawn_webhook_server().await;
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("direct-a");
        let users = Arc::new(VlessUserManager::new(
            "webhook-in",
            vec![VlessClient {
                id: Uuid::from_bytes(USER_ID),
                email: Some("webhook@example.test".to_string()),
                flow: None,
                level: None,
            }],
        ));
        let router = Arc::clone(&runtime.router);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
        let vless_addr = listener.local_addr().expect("vless addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let socket_meta = rust_xray::routing::RouteSocketMeta::from_tcp_stream(&stream);
                let users = Arc::clone(&users);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _ = rust_xray::vless::handle_vless_tcp_inbound_with_socket_meta(
                        stream,
                        users.as_ref(),
                        None,
                        &socket_meta,
                        Some(&router),
                    )
                    .await;
                });
            }
        });
        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let mut routing = RoutingServiceClient::new(
            Endpoint::from_shared(format!("http://{grpc_addr}"))
                .expect("endpoint")
                .connect()
                .await
                .expect("connect"),
        );
        routing
            .add_rule(AddRuleRequest {
                config: Some(webhook_rule_message("localhost", "direct-a", webhook_url)),
                should_append: true,
            })
            .await
            .expect("add webhook rule");

        let (port, hit) = spawn_target_listener().await;
        dial_vless(vless_addr, port, "localhost")
            .await
            .expect("first dial");
        assert!(target_hit_within(hit, 2000).await, "first target hit");
        let request = tokio::time::timeout(Duration::from_secs(2), webhook_requests.recv())
            .await
            .expect("webhook timeout")
            .expect("webhook request");
        assert!(request.starts_with("POST /route HTTP/1.1"));
        assert!(request.contains("X-Routing-Test: stage-8e2"));
        assert!(request.contains("\"email\":\"webhook@example.test\""));
        assert!(request.contains("\"inboundTag\":\"webhook-in\""));
        assert!(request.contains("\"outboundTag\":\"direct-a\""));
        assert!(request.contains("\"source\":\"127.0.0.1:"));
        assert!(request.contains("\"inboundLocal\":\"127.0.0.1:"));

        let (port, hit) = spawn_target_listener().await;
        dial_vless(vless_addr, port, "localhost")
            .await
            .expect("dedup dial");
        assert!(target_hit_within(hit, 2000).await, "dedup target hit");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), webhook_requests.recv())
                .await
                .is_err(),
            "same email inside deduplication TTL must not publish twice"
        );

        routing
            .remove_rule(RemoveRuleRequest {
                rule_tag: "webhook-rule".to_string(),
            })
            .await
            .expect("remove webhook rule");
        let (port, hit) = spawn_target_listener().await;
        dial_vless(vless_addr, port, "localhost")
            .await
            .expect("post-remove dial");
        assert!(target_hit_within(hit, 2000).await, "post-remove target hit");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), webhook_requests.recv())
                .await
                .is_err(),
            "removed webhook must not receive later route events"
        );
    }

    #[tokio::test]
    async fn round_robin_and_tonic_override_change_real_outbound_immediately() {
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_routing_tests(Arc::clone(&registry));
        runtime
            .outbound
            .add_outbound(encode_freedom_outbound("candidate-a"))
            .expect("candidate-a");
        runtime
            .outbound
            .add_outbound(encode_blackhole_outbound("candidate-b"))
            .expect("candidate-b");
        let users = Arc::new(VlessUserManager::new(
            "balancer-in",
            vec![VlessClient {
                id: Uuid::from_bytes(USER_ID),
                email: Some("balancer@example.test".to_string()),
                flow: None,
                level: None,
            }],
        ));
        let router = Arc::clone(&runtime.router);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
        let vless_addr = listener.local_addr().expect("vless addr");
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let users = Arc::clone(&users);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let _ = handle_vless_tcp_inbound(
                        stream,
                        users.as_ref(),
                        None,
                        Some(peer.ip()),
                        Some(&router),
                    )
                    .await;
                });
            }
        });
        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let mut routing = RoutingServiceClient::new(
            Endpoint::from_shared(format!("http://{grpc_addr}"))
                .expect("endpoint")
                .connect()
                .await
                .expect("connect"),
        );
        routing
            .add_rule(AddRuleRequest {
                config: Some(balancer_rule_message("roundrobin")),
                should_append: false,
            })
            .await
            .expect("add round robin");

        for (index, expected_hit) in [true, false, true, false].into_iter().enumerate() {
            let (port, hit) = spawn_target_listener().await;
            dial_vless(vless_addr, port, "localhost")
                .await
                .expect("round robin dial");
            assert_eq!(
                target_hit_within(hit, if expected_hit { 2000 } else { 300 }).await,
                expected_hit,
                "round-robin selection at index {index}"
            );
        }

        routing
            .override_balancer_target(OverrideBalancerTargetRequest {
                balancer_tag: "live-balancer".to_string(),
                target: "candidate-b".to_string(),
            })
            .await
            .expect("set override");
        let (port, hit) = spawn_target_listener().await;
        dial_vless(vless_addr, port, "localhost")
            .await
            .expect("override dial");
        assert!(
            !target_hit_within(hit, 300).await,
            "override must immediately force blackhole candidate"
        );

        routing
            .override_balancer_target(OverrideBalancerTargetRequest {
                balancer_tag: "live-balancer".to_string(),
                target: String::new(),
            })
            .await
            .expect("clear override");
        let (port, hit) = spawn_target_listener().await;
        dial_vless(vless_addr, port, "localhost")
            .await
            .expect("resumed strategy dial");
        assert!(
            target_hit_within(hit, 2000).await,
            "empty target must clear override and resume round-robin state"
        );
    }

    #[tokio::test]
    async fn test_route_and_vless_pick_agree_on_domain_rule() {
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
        runtime
            .router
            .add_rule(
                &domain_rule_message("example.com", "direct-b", "parity-domain"),
                true,
            )
            .expect("add rule");

        let ctx = rust_xray::routing::route_context_from_proto(
            &rust_xray::api::proto::app::router::command::RoutingContext {
                inbound_tag: "vless-in".to_string(),
                network: Network::Tcp as i32,
                target_domain: "example.com".to_string(),
                ..Default::default()
            },
        );
        let picked = runtime
            .router
            .pick_route_with_default(ctx)
            .await
            .expect("pick");

        let grpc_addr = spawn_routing_server(Arc::clone(&runtime)).await;
        let mut client = RoutingServiceClient::new(
            Endpoint::from_shared(format!("http://{grpc_addr}"))
                .expect("endpoint")
                .connect()
                .await
                .expect("connect"),
        );
        let tested = client
            .test_route(TestRouteRequest {
                routing_context: Some(
                    rust_xray::api::proto::app::router::command::RoutingContext {
                        inbound_tag: "vless-in".to_string(),
                        network: Network::Tcp as i32,
                        target_domain: "example.com".to_string(),
                        ..Default::default()
                    },
                ),
                field_selectors: vec!["outbound".to_string()],
                publish_result: false,
            })
            .await
            .expect("test route")
            .into_inner();

        assert_eq!(tested.outbound_tag, picked.outbound_tag);
        assert_eq!(picked.rule_tag, "parity-domain");
    }

    #[tokio::test]
    async fn two_handler_runtimes_have_independent_routers() {
        let registry_a = Arc::new(StatsRegistry::new());
        let registry_b = Arc::new(StatsRegistry::new());
        let runtime_a = HandlerRuntime::for_routing_tests(registry_a);
        let runtime_b = HandlerRuntime::for_routing_tests(registry_b);
        assert!(Arc::ptr_eq(runtime_a.inbound.router(), &runtime_a.router));
        assert!(Arc::ptr_eq(runtime_b.inbound.router(), &runtime_b.router));
        assert!(!Arc::ptr_eq(&runtime_a.router, &runtime_b.router));
        runtime_a
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("a");
        runtime_b
            .outbound
            .add_outbound(encode_freedom_outbound("direct-a"))
            .expect("b");

        runtime_a
            .router
            .add_rule(
                &domain_rule_message("only-a.example", "direct-a", "only-a"),
                true,
            )
            .expect("add a");

        let ctx = rust_xray::routing::route_context_from_proto(
            &rust_xray::api::proto::app::router::command::RoutingContext {
                target_domain: "only-a.example".to_string(),
                ..Default::default()
            },
        );
        let a = runtime_a.router.pick_route_with_default(ctx.clone()).await;
        let b = runtime_b.router.pick_route_with_default(ctx).await;
        assert!(a.is_ok());
        assert_ne!(a.expect("a ok").rule_tag, b.expect("b ok").rule_tag);
    }
}
