
use super::*;
use crate::config::{
    first_reality_inbound_runtime, load_xray_config_from_file, validate_xray_panel_config,
    XrayConfig,
};

const TEST_REALITY_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";

fn vless_reality_json(network: &str, with_xhttp: bool) -> String {
    let xhttp = if with_xhttp {
        r#""xhttpSettings": {"path": "/xhttp", "mode": "stream-one"},"#
    } else {
        ""
    };
    format!(
        r#"{{
            "inbounds": [{{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "network": "{network}",
                    "security": "reality",
                    {xhttp}
                    "realitySettings": {{
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    )
}

#[test]
fn raw_tcp_reality_normalizes() {
    let config: XrayConfig = serde_json::from_str(&vless_reality_json("raw", false)).unwrap();
    validate_xray_panel_config(&config).unwrap();
    let normalized = normalize_config(&config).unwrap();
    assert_eq!(normalized.inbounds.len(), 1);
    let NormalizedInbound::VlessReality(inbound) = &normalized.inbounds[0] else {
        panic!("expected VlessReality inbound");
    };
    assert_eq!(inbound.listen_addr, "127.0.0.1:443");
    assert_eq!(inbound.transport, InboundTransportConfig::RawTcp);
    assert_eq!(inbound.reality.dest_addr, "www.example.com:443");
    assert_eq!(inbound.users.len(), 1);

    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert!(vless_reality_matches_runtime(inbound, &runtime));
}

#[test]
fn xhttp_reality_normalizes() {
    let config: XrayConfig = serde_json::from_str(&vless_reality_json("xhttp", true)).unwrap();
    validate_xray_panel_config(&config).unwrap();
    let normalized = normalize_config(&config).unwrap();
    let NormalizedInbound::VlessReality(inbound) = &normalized.inbounds[0] else {
        panic!("expected VlessReality inbound");
    };
    assert_eq!(
        inbound.transport,
        InboundTransportConfig::XHttp(XHttpRuntimeConfig {
            path: "/xhttp".to_string(),
            host: None,
            mode: "stream-one".to_string(),
        })
    );

    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert!(vless_reality_matches_runtime(inbound, &runtime));
}

#[test]
fn splithttp_alias_normalizes_to_xhttp() {
    let config: XrayConfig = serde_json::from_str(&vless_reality_json("splithttp", true)).unwrap();
    validate_xray_panel_config(&config).unwrap();
    let normalized = normalize_config(&config).unwrap();
    let NormalizedInbound::VlessReality(inbound) = &normalized.inbounds[0] else {
        panic!("expected VlessReality inbound");
    };
    assert!(matches!(
        inbound.transport,
        InboundTransportConfig::XHttp(_)
    ));
}

#[test]
fn websocket_reality_rejected() {
    let config: XrayConfig = serde_json::from_str(&vless_reality_json("ws", false)).unwrap();
    let err = normalize_config(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("WebSocket"));
}

#[test]
fn missing_private_key_fails() {
    let json = r#"{
            "inbounds": [{
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "shortIds": [""]
                    }
                }
            }]
        }"#;
    let config: XrayConfig = serde_json::from_str(json).unwrap();
    let err = normalize_config(&config).unwrap_err();
    assert!(err.to_string().contains("privateKey"));
}

#[test]
fn missing_port_fails() {
    let json = r#"{
            "inbounds": [{
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;
    let config: XrayConfig = serde_json::from_str(json).unwrap();
    let err = normalize_config(&config).unwrap_err();
    assert!(err.to_string().contains("port"));
}

#[test]
fn unsupported_grpc_rejected() {
    let config: XrayConfig = serde_json::from_str(&vless_reality_json("grpc", false)).unwrap();
    let err = normalize_config(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn api_dokodemo_door_normalizes() {
    let json = r#"{
            "api": {
                "tag": "api",
                "listen": "127.0.0.1:61000",
                "services": ["StatsService"]
            },
            "inbounds": [{
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 61000,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"}
            }]
        }"#;
    let config: XrayConfig = serde_json::from_str(json).unwrap();
    validate_xray_panel_config(&config).unwrap();
    let normalized = normalize_config(&config).unwrap();
    let api = normalized.api.as_ref().expect("api block");
    assert_eq!(api.tag, "api");
    assert_eq!(api.listen, "127.0.0.1:61000");
    assert_eq!(api.listen_source, ApiListenSource::ApiListenField);

    let NormalizedInbound::Api(inbound) = &normalized.inbounds[0] else {
        panic!("expected Api inbound");
    };
    assert_eq!(inbound.listen_addr, "127.0.0.1:61000");
    assert_eq!(inbound.protocol, "dokodemo-door");
}

#[test]
fn remnawave_routing_api_normalizes() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/remna/remnawave_node_minimal_61000.json"
    );
    let config = load_xray_config_from_file(path).expect("load fixture");
    let normalized = normalize_config(&config).unwrap();

    let api = normalized.api.as_ref().expect("api");
    assert_eq!(api.listen, "127.0.0.1:61000");
    assert_eq!(api.listen_source, ApiListenSource::RoutingRule);
    assert_eq!(api.dokodemo_inbound_tag.as_deref(), Some("api-inbound"));

    let api_inbounds: Vec<_> = normalized
        .inbounds
        .iter()
        .filter_map(|inbound| match inbound {
            NormalizedInbound::Api(api) => Some(api),
            _ => None,
        })
        .collect();
    assert_eq!(api_inbounds.len(), 1);
    assert_eq!(api_inbounds[0].tag.as_deref(), Some("api-inbound"));

    let reality_inbounds: Vec<_> = normalized
        .inbounds
        .iter()
        .filter_map(|inbound| match inbound {
            NormalizedInbound::VlessReality(vless) => Some(vless),
            _ => None,
        })
        .collect();
    assert_eq!(reality_inbounds.len(), 1);
    assert_eq!(reality_inbounds[0].listen_addr, "127.0.0.1:25443");

    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert!(vless_reality_matches_runtime(reality_inbounds[0], &runtime));

    assert!(!normalized.routing.enforced);
    assert_eq!(normalized.routing.rules.len(), 1);
    assert_eq!(
        normalized.routing.rules[0].outbound_tag.as_deref(),
        Some("api")
    );
}
