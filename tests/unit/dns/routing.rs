
use super::*;
use crate::config::XrayConfig;

fn context(inbound_tag: Option<&str>, network: Network, port: u16) -> DnsRoutingContext {
    DnsRoutingContext {
        network,
        destination_host: "1.1.1.1".to_string(),
        destination_port: port,
        inbound_tag: inbound_tag.map(str::to_string),
        protocol: Some("dns".to_string()),
    }
}

#[test]
fn dns_tcp_port_53_selects_proxy() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"vless"}],
              "routing": {"rules": [{"type":"field","port":53,"network":"tcp","outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let router = DnsRouter::new(config.routing, config.outbounds);
    assert_eq!(
        router.select_outbound_tag(&context(None, Network::Tcp, 53)),
        Some("proxy".to_string())
    );
}

#[test]
fn dns_inbound_tag_selects_proxy() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"vless"}],
              "routing": {"rules": [{"type":"field","inboundTag":["dns-in"],"outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let router = DnsRouter::new(config.routing, config.outbounds);
    assert_eq!(
        router.select_outbound_tag(&context(Some("dns-in"), Network::Tcp, 53)),
        Some("proxy".to_string())
    );
}

#[test]
fn no_match_uses_first_outbound() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "outbounds": [{"tag":"first","protocol":"freedom"},{"tag":"proxy","protocol":"vless"}],
              "routing": {"rules": [{"type":"field","port":443,"outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let router = DnsRouter::new(config.routing, config.outbounds);
    assert_eq!(
        router.select_outbound_tag(&context(None, Network::Tcp, 53)),
        Some("first".to_string())
    );
}

#[test]
fn udp_rule_does_not_match_tcp_dns() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "outbounds": [{"tag":"first","protocol":"freedom"},{"tag":"proxy","protocol":"vless"}],
              "routing": {"rules": [{"type":"field","port":53,"network":"udp","outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let router = DnsRouter::new(config.routing, config.outbounds);
    assert_eq!(
        router.select_outbound_tag(&context(None, Network::Tcp, 53)),
        Some("first".to_string())
    );
}
