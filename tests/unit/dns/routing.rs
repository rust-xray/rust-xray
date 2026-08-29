use std::sync::Arc;

use super::*;
use crate::config::XrayConfig;
use crate::dns::engine::DnsEngine;
use crate::routing::RuntimeRouter;
use crate::runtime::RuntimeOutboundManager;

fn context(inbound_tag: Option<&str>, network: Network, port: u16) -> DnsRoutingContext {
    DnsRoutingContext {
        network,
        destination_host: "1.1.1.1".to_string(),
        destination_port: port,
        inbound_tag: inbound_tag.map(str::to_string),
        protocol: Some("dns".to_string()),
    }
}

fn selector_from_config(config: &XrayConfig) -> DnsOutboundSelector {
    let outbound = RuntimeOutboundManager::new();
    for ob in &config.outbounds {
        outbound.register_startup_outbound(ob).expect("outbound");
    }
    let router = RuntimeRouter::new(
        config.routing.as_ref(),
        Arc::clone(&outbound),
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router");
    DnsOutboundSelector::new(router)
}

#[tokio::test]
async fn dns_tcp_port_53_selects_proxy() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"freedom"}],
              "routing": {"rules": [{"type":"field","port":53,"network":"tcp","outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let router = selector_from_config(&config);
    assert_eq!(
        router
            .select_outbound_tag(&context(None, Network::Tcp, 53))
            .await,
        Some("proxy".to_string())
    );
}

#[tokio::test]
async fn dns_inbound_tag_selects_proxy() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"freedom"}],
              "routing": {"rules": [{"type":"field","inboundTag":["dns-in"],"outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let router = selector_from_config(&config);
    assert_eq!(
        router
            .select_outbound_tag(&context(Some("dns-in"), Network::Tcp, 53))
            .await,
        Some("proxy".to_string())
    );
}

#[tokio::test]
async fn no_match_uses_first_outbound() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "outbounds": [{"tag":"first","protocol":"freedom"},{"tag":"proxy","protocol":"freedom"}],
              "routing": {"rules": [{"type":"field","port":443,"outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let router = selector_from_config(&config);
    assert_eq!(
        router
            .select_outbound_tag(&context(None, Network::Tcp, 53))
            .await,
        Some("first".to_string())
    );
}

#[tokio::test]
async fn udp_rule_does_not_match_tcp_dns() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "outbounds": [{"tag":"first","protocol":"freedom"},{"tag":"proxy","protocol":"freedom"}],
              "routing": {"rules": [{"type":"field","port":53,"network":"udp","outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let router = selector_from_config(&config);
    assert_eq!(
        router
            .select_outbound_tag(&context(None, Network::Tcp, 53))
            .await,
        Some("first".to_string())
    );
}
