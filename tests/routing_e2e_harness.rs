//! Shared routing E2E helpers for transport-level integration tests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use rust_xray::api::proto::app::proxyman::command::handler_service_client::HandlerServiceClient;
use rust_xray::api::proto::app::proxyman::command::{
    AddOutboundRequest, AddUserOperation, AlterInboundRequest, RemoveOutboundRequest,
};
use rust_xray::api::proto::app::router::command::routing_service_client::RoutingServiceClient;
use rust_xray::api::proto::app::router::command::{
    AddRuleRequest, RemoveRuleRequest, RoutingContext, TestRouteRequest,
};
use rust_xray::api::proto::app::router::{
    BalancingRule, Config as RouterConfig, RoutingRule, WebhookConfig,
};
use rust_xray::api::proto::common::geodata::{
    domain, domain_rule, ip_rule, Domain, DomainRule, GeoIpRule, GeoSiteRule, IpRule,
};
use rust_xray::api::proto::common::net::{Network, PortList, PortRange};
use rust_xray::api::proto::common::protocol::User;
use rust_xray::api::proto::common::serial::TypedMessage;
use rust_xray::api::proto::proxy::vless::Account;
use rust_xray::api::server::{serve_grpc_on, ApiService, ApiTransportMode};
use rust_xray::routing::{vless_route_from_uuid, RouteSocketMeta, ROUTER_CONFIG_TYPE};
use rust_xray::runtime::{encode_blackhole_outbound, encode_freedom_outbound, HandlerRuntime};
use rust_xray::stats::StatsRegistry;
use rust_xray::vless::config::VlessClient;
use rust_xray::vless::handle_vless_tcp_inbound_with_socket_meta;
use rust_xray::vless::user_manager::VlessUserManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::{Channel, Endpoint};
use uuid::Uuid;

pub const DEFAULT_USER_ID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

pub fn build_vless_ip_request(user_id: &[u8; 16], port: u16) -> Vec<u8> {
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

pub fn build_vless_domain_request(user_id: &[u8; 16], domain: &str, port: u16) -> Vec<u8> {
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

pub fn build_vless_mux_request(user_id: &[u8; 16], initial_mux_payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(0);
    buf.push(0x03);
    buf.extend_from_slice(initial_mux_payload);
    buf
}

pub async fn spawn_target_listener() -> (u16, oneshot::Receiver<()>) {
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

pub async fn target_hit_within(rx: oneshot::Receiver<()>, ms: u64) -> bool {
    tokio::time::timeout(Duration::from_millis(ms), rx)
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
}

pub async fn spawn_routing_server(runtime: Arc<HandlerRuntime>) -> SocketAddr {
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

pub async fn connect_routing_clients(
    grpc_addr: SocketAddr,
) -> (HandlerServiceClient<Channel>, RoutingServiceClient<Channel>) {
    let channel = Endpoint::from_shared(format!("http://{grpc_addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    (
        HandlerServiceClient::new(channel.clone()),
        RoutingServiceClient::new(channel),
    )
}

pub fn domain_rule_message(domain: &str, tag: &str, rule_tag: &str) -> TypedMessage {
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

pub fn user_rule_message(email: &str, tag: &str, rule_tag: &str) -> TypedMessage {
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

pub fn inbound_rule_message(inbound_tag: &str, tag: &str, rule_tag: &str) -> TypedMessage {
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
                inbound_tag: vec![inbound_tag.to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec(),
    }
}

pub fn vless_route_rule_message(route: u16, tag: &str, rule_tag: &str) -> TypedMessage {
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

pub fn protocol_rule_message(protocol: &str, tag: &str, rule_tag: &str) -> TypedMessage {
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

pub fn add_user_request(inbound_tag: &str, email: &str, id: &str) -> AlterInboundRequest {
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

pub async fn setup_routing_runtime() -> Arc<HandlerRuntime> {
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
    runtime
}

pub async fn assert_test_route_outbound(
    routing: &mut RoutingServiceClient<Channel>,
    ctx: RoutingContext,
    expected_outbound: &str,
) {
    let tested = routing
        .test_route(TestRouteRequest {
            routing_context: Some(ctx),
            field_selectors: vec!["outbound".to_string()],
            publish_result: false,
        })
        .await
        .expect("test route")
        .into_inner();
    assert_eq!(tested.outbound_tag, expected_outbound);
}

pub fn routing_context_for_vless_tcp(
    inbound_tag: &str,
    user_email: &str,
    user_id: &Uuid,
    target_domain: &str,
    target_port: u16,
    protocol: &str,
) -> RoutingContext {
    RoutingContext {
        inbound_tag: inbound_tag.to_string(),
        network: Network::Tcp as i32,
        user: user_email.to_string(),
        target_domain: target_domain.to_string(),
        target_port: u32::from(target_port),
        protocol: protocol.to_string(),
        vless_route: u32::from(vless_route_from_uuid(user_id)),
        ..Default::default()
    }
}

pub async fn count_routing_publishes(
    runtime: &HandlerRuntime,
    during: impl std::future::Future<Output = ()>,
) -> usize {
    let stats = runtime
        .router
        .routing_stats()
        .expect("routing stats enabled");
    let mut rx = stats.subscribe();
    during.await;
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    count
}

pub async fn dial_vless_ip(vless_addr: SocketAddr, target_port: u16) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(vless_addr).await?;
    stream
        .write_all(&build_vless_ip_request(&DEFAULT_USER_ID, target_port))
        .await?;
    let mut buf = [0u8; 64];
    let _ = stream.read(&mut buf).await?;
    stream.shutdown().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}

pub async fn tonic_add_rule(routing: &mut RoutingServiceClient<Channel>, config: TypedMessage) {
    routing
        .add_rule(AddRuleRequest {
            config: Some(config),
            should_append: true,
        })
        .await
        .expect("add rule")
        .into_inner();
}

pub async fn tonic_remove_rule(routing: &mut RoutingServiceClient<Channel>, rule_tag: &str) {
    routing
        .remove_rule(RemoveRuleRequest {
            rule_tag: rule_tag.to_string(),
        })
        .await
        .expect("remove rule")
        .into_inner();
}

pub async fn tonic_remove_outbound(handler: &mut HandlerServiceClient<Channel>, tag: &str) {
    handler
        .remove_outbound(RemoveOutboundRequest {
            tag: tag.to_string(),
        })
        .await
        .expect("remove outbound")
        .into_inner();
}

pub async fn tonic_add_outbound(
    handler: &mut HandlerServiceClient<Channel>,
    tag: &str,
    blackhole: bool,
) {
    let outbound = if blackhole {
        encode_blackhole_outbound(tag)
    } else {
        encode_freedom_outbound(tag)
    };
    handler
        .add_outbound(AddOutboundRequest {
            outbound: Some(outbound),
        })
        .await
        .expect("add outbound")
        .into_inner();
}

pub fn encode_geodata_record<M: Message>(message: &M) -> Vec<u8> {
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

pub fn geosite_rule_message(file: &str, attrs: &str, tag: &str, rule_tag: &str) -> TypedMessage {
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

pub fn geoip_rule_message(
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

pub fn balancer_rule_message(strategy: &str, selector: &str, balancer_tag: &str) -> TypedMessage {
    TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: RouterConfig {
            balancing_rule: vec![BalancingRule {
                tag: balancer_tag.to_string(),
                outbound_selector: vec![selector.to_string()],
                strategy: strategy.to_string(),
                ..Default::default()
            }],
            rule: vec![RoutingRule {
                target_tag: Some(
                    rust_xray::api::proto::app::router::routing_rule::TargetTag::BalancingTag(
                        balancer_tag.to_string(),
                    ),
                ),
                rule_tag: format!("{balancer_tag}-rule"),
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

pub fn build_vless_ipv6_request(user_id: &[u8; 16], ip: [u8; 16], port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(0);
    buf.push(0x01);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.push(0x03);
    buf.extend_from_slice(&ip);
    buf
}

pub async fn dial_vless_domain(
    vless_addr: SocketAddr,
    target_port: u16,
    domain: &str,
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(vless_addr).await?;
    stream
        .write_all(&build_vless_domain_request(
            &DEFAULT_USER_ID,
            domain,
            target_port,
        ))
        .await?;
    let mut buf = [0u8; 64];
    let _ = stream.read(&mut buf).await?;
    stream.shutdown().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}

pub async fn dial_vless_ipv6(
    vless_addr: SocketAddr,
    ip: [u8; 16],
    target_port: u16,
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(vless_addr).await?;
    stream
        .write_all(&build_vless_ipv6_request(&DEFAULT_USER_ID, ip, target_port))
        .await?;
    let mut buf = [0u8; 64];
    let _ = stream.read(&mut buf).await?;
    stream.shutdown().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}

pub async fn spawn_vless_listener(
    _inbound_tag: &str,
    users: Arc<VlessUserManager>,
    router: Arc<rust_xray::routing::RuntimeRouter>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let socket_meta = RouteSocketMeta::from_tcp_stream(&stream);
            let users = Arc::clone(&users);
            let router = Arc::clone(&router);
            tokio::spawn(async move {
                let _ = handle_vless_tcp_inbound_with_socket_meta(
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
    addr
}

pub async fn spawn_webhook_server(
    response_delay: Duration,
) -> (String, tokio::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind webhook");
    let addr = listener.local_addr().expect("webhook addr");
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(response_delay).await;
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
                    let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
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

pub fn webhook_rule_message(domain: &str, tag: &str, url: String) -> TypedMessage {
    let mut config = domain_rule_message(domain, tag, "webhook-rule");
    let mut decoded = RouterConfig::decode(config.value.as_slice()).expect("decode rule");
    decoded.rule[0].webhook = Some(WebhookConfig {
        url,
        deduplication: 2,
        headers: [("X-Test".to_string(), "stage8e2".to_string())]
            .into_iter()
            .collect(),
    });
    config.value = decoded.encode_to_vec();
    config
}

pub async fn tonic_add_rule_replace(
    routing: &mut RoutingServiceClient<Channel>,
    config: TypedMessage,
) {
    routing
        .add_rule(AddRuleRequest {
            config: Some(config),
            should_append: false,
        })
        .await
        .expect("add rule replace")
        .into_inner();
}
