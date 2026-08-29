use super::*;
use std::collections::BTreeMap;

const TEST_REALITY_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
const TEST_MLDSA65_SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const TEST_MLDSA65_SEED_31_BYTES: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg";
const TEST_MLDSA65_SEED_33_BYTES: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";

const MINIMAL_VLESS_REALITY: &str = r#"{
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.example.com:443",
                    "serverNames": ["www.example.com"],
                    "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                    "shortIds": ["", "0123456789abcdef"]
                },
                "sockopt": {"tcpFastOpen": true}
            },
            "sniffing": {"enabled": true}
        }],
        "outbounds": [{"protocol": "freedom"}],
        "unknownTopLevel": {"enabled": true}
    }"#;

#[test]
fn parse_config_without_inbounds_defaults_to_empty() {
    let json = r#"{"outbounds": [{"protocol": "freedom"}]}"#;

    let config: XrayConfig = serde_json::from_str(json).expect("parse config");

    assert!(config.inbounds.is_empty());
    assert!(find_reality_inbounds(&config).is_empty());

    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        err.to_string(),
        "no supported VLESS TCP REALITY inbound found"
    );
}

#[test]
fn top_level_dns_tcp_server_parse() {
    let json = r#"{"dns":{"servers":["tcp://1.1.1.1:53"],"queryStrategy":"UseIPv4"}}"#;
    let config: XrayConfig = serde_json::from_str(json).expect("parse config");
    let dns = config.dns.expect("dns block");
    assert_eq!(dns.servers.len(), 1);
    assert_eq!(dns.servers[0].host, "1.1.1.1");
    assert_eq!(dns.servers[0].port, 53);
    assert_eq!(
        dns.servers[0].transport,
        crate::dns::DnsServerTransport::Tcp
    );
    assert_eq!(dns.query_strategy, crate::dns::QueryStrategy::UseIPv4);
}

#[test]
fn top_level_dns_udp_and_doh_parse_without_runtime_support() {
    let json = r#"{"dns":{"servers":["1.1.1.1","https://dns.google/dns-query"]}}"#;
    let config: XrayConfig = serde_json::from_str(json).expect("parse config");
    let dns = config.dns.expect("dns block");
    assert_eq!(
        dns.servers[0].transport,
        crate::dns::DnsServerTransport::Udp
    );
    assert_eq!(dns.servers[0].port, 53);
    assert_eq!(
        dns.servers[1].transport,
        crate::dns::DnsServerTransport::Doh
    );
    assert_eq!(dns.servers[1].path.as_deref(), Some("/dns-query"));
}

#[test]
fn parse_minimal_vless_reality_inbound() {
    let config: XrayConfig = serde_json::from_str(MINIMAL_VLESS_REALITY).expect("parse config");
    let inbounds = find_reality_inbounds(&config);

    assert_eq!(inbounds.len(), 1);
    assert_eq!(inbounds[0].protocol.as_deref(), Some("vless"));
    assert_eq!(inbound_listen_addr(inbounds[0]).unwrap(), "0.0.0.0:443");

    let settings = get_inbound_reality_settings(inbounds[0]).unwrap();
    assert_eq!(reality_dest_addr(settings).unwrap(), "www.example.com:443");
    assert_eq!(
        reality_private_key(settings).unwrap(),
        "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4"
    );
    assert_eq!(settings.server_names, vec!["www.example.com".to_string()]);
}

#[test]
fn builds_first_reality_inbound_runtime() {
    let json = r#"{
            "inbounds": [{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "maxTimeDiff": 10000,
                        "shortIds": ["", "0123456789abcdef"]
                    }
                }
            }]
        }"#;

    let config: XrayConfig = serde_json::from_str(json).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();

    assert_eq!(runtime.tag.as_deref(), Some("reality-in"));
    assert_eq!(runtime.protocol.as_deref(), Some("vless"));
    assert_eq!(runtime.listen_addr, "127.0.0.1:443");
    assert_eq!(runtime.dest_addr, "www.example.com:443");
    assert_eq!(runtime.server_names, vec!["www.example.com".to_string()]);
    assert_eq!(
        runtime.short_ids,
        vec![
            Vec::<u8>::new(),
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        ]
    );
    assert_eq!(runtime.max_time_diff, 10000);
    assert!(!runtime.show);
    assert_eq!(runtime.private_key, TEST_REALITY_PRIVATE_KEY);
    assert_eq!(runtime.vless_clients.len(), 1);
    assert_eq!(
        runtime.vless_clients[0].id,
        "00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(runtime.vless_decryption, "none");
}

#[test]
fn inbound_vless_settings_parses_fallback_dest_number() {
    let json = r#"{
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none",
                "fallbacks": [{"dest": 8080}]
            }
        }"#;

    let inbound: InboundObject = serde_json::from_str(json).unwrap();
    let settings = inbound_vless_settings(&inbound).unwrap().unwrap();

    assert_eq!(settings.fallbacks.len(), 1);
    assert_eq!(settings.fallbacks[0].dest.addr, "127.0.0.1:8080");
}

#[test]
fn inbound_vless_settings_parses_clients_and_decryption() {
    let json = r#"{
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "email": "user@example.com",
                    "flow": "xtls-rprx-vision",
                    "level": 0
                }],
                "decryption": "none",
                "fallbacks": []
            }
        }"#;

    let inbound: InboundObject = serde_json::from_str(json).unwrap();
    let settings = inbound_vless_settings(&inbound).unwrap().unwrap();

    assert_eq!(settings.clients.len(), 1);
    assert_eq!(
        settings.clients[0].id,
        "00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(
        settings.clients[0].email.as_deref(),
        Some("user@example.com")
    );
    assert_eq!(
        settings.clients[0].flow.as_deref(),
        Some("xtls-rprx-vision")
    );
    assert_eq!(settings.decryption.as_deref(), Some("none"));
    assert!(settings.fallbacks.is_empty());
    assert_eq!(settings.clients[0].level, Some(0));
}

#[test]
fn inbound_vless_settings_returns_none_for_non_vless_protocol() {
    let json = r#"{
            "protocol": "trojan",
            "settings": {"clients": []}
        }"#;

    let inbound: InboundObject = serde_json::from_str(json).unwrap();

    assert!(inbound_vless_settings(&inbound).unwrap().is_none());
}

#[test]
fn inbound_vless_settings_requires_settings_for_vless() {
    let inbound = InboundObject {
        tag: None,
        listen: None,
        port: None,
        protocol: Some("vless".to_string()),
        settings: None,
        stream_settings: None,
        extra: BTreeMap::new(),
    };

    let err = inbound_vless_settings(&inbound).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn builds_first_reality_inbound_runtime_with_policy_fields() {
    let json = r#"{
            "inbounds": [{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "show": true,
                        "dest": "www.example.com:443",
                        "serverNames": ["Example.COM"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "minClientVer": "1.8.0",
                        "maxClientVer": "24.9.30",
                        "maxTimeDiff": 5000,
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

    let config: XrayConfig = serde_json::from_str(json).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();

    assert_eq!(runtime.tag.as_deref(), Some("reality-in"));
    assert_eq!(runtime.protocol.as_deref(), Some("vless"));
    assert_eq!(runtime.server_names, vec!["Example.COM".to_string()]);
    assert_eq!(runtime.min_client_ver.as_deref(), Some("1.8.0"));
    assert_eq!(runtime.max_client_ver.as_deref(), Some("24.9.30"));
    assert_eq!(runtime.max_time_diff, 5000);
    assert!(runtime.show);
}

fn minimal_reality_runtime_json(
    min_client_ver_field: Option<&str>,
    max_client_ver_field: Option<&str>,
) -> String {
    let min_client_ver = match min_client_ver_field {
        Some(value) => format!(r#""minClientVer": "{value}","#),
        None => String::new(),
    };
    let max_client_ver = match max_client_ver_field {
        Some(value) => format!(r#""maxClientVer": "{value}","#),
        None => String::new(),
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
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        {min_client_ver}
                        {max_client_ver}
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    )
}

#[test]
fn effective_reality_min_client_ver_applies_xray_default() {
    assert_eq!(
        effective_reality_min_client_ver(None),
        DEFAULT_REALITY_MIN_CLIENT_VER
    );
    assert_eq!(
        effective_reality_min_client_ver(Some(String::new())),
        DEFAULT_REALITY_MIN_CLIENT_VER
    );
    assert_eq!(
        effective_reality_min_client_ver(Some("1.8.0".to_string())),
        "1.8.0"
    );
    assert_eq!(
        effective_reality_min_client_ver(Some("0.0.0".to_string())),
        "0.0.0"
    );
}

#[test]
fn effective_reality_max_client_ver_empty_means_unbounded() {
    assert_eq!(effective_reality_max_client_ver(None), None);
    assert_eq!(effective_reality_max_client_ver(Some(String::new())), None);
    assert_eq!(
        effective_reality_max_client_ver(Some("24.9.30".to_string())),
        Some("24.9.30".to_string())
    );
}

#[test]
fn reality_runtime_applies_default_min_client_ver_when_field_missing() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_runtime_json(None, None)).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(
        runtime.min_client_ver.as_deref(),
        Some(DEFAULT_REALITY_MIN_CLIENT_VER)
    );
}

#[test]
fn reality_runtime_applies_default_min_client_ver_when_field_empty() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_runtime_json(Some(""), None)).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(
        runtime.min_client_ver.as_deref(),
        Some(DEFAULT_REALITY_MIN_CLIENT_VER)
    );
}

#[test]
fn reality_runtime_preserves_explicit_min_client_ver() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_runtime_json(Some("1.8.0"), None)).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(runtime.min_client_ver.as_deref(), Some("1.8.0"));
}

#[test]
fn reality_runtime_preserves_explicit_zero_min_client_ver() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_runtime_json(Some("0.0.0"), None)).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(runtime.min_client_ver.as_deref(), Some("0.0.0"));
}

#[test]
fn reality_runtime_rejects_malformed_min_client_ver_at_startup() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_runtime_json(Some("26.bad.27"), None)).unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("minClientVer"));
}

#[test]
fn reality_runtime_rejects_malformed_max_client_ver_at_startup() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_runtime_json(None, Some("26.bad.27"))).unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("maxClientVer"));
}

#[test]
fn reality_runtime_empty_max_client_ver_is_unbounded() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_runtime_json(None, Some(""))).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(runtime.max_client_ver, None);
}

#[test]
fn reality_runtime_preserves_explicit_max_client_ver() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_runtime_json(None, Some("24.9.30"))).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(runtime.max_client_ver.as_deref(), Some("24.9.30"));
}

#[test]
fn parse_reality_settings_supports_target_alias() {
    let json = r#"{
            "inbounds": [{
                "port": 8443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "target": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

    let config: XrayConfig = serde_json::from_str(json).unwrap();
    let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
    assert_eq!(reality_dest_addr(settings).unwrap(), "example.com:443");
}

#[test]
fn parse_reality_settings_rejects_dest_and_target_together() {
    let json = r#"{
            "inbounds": [{
                "port": 8443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "a.example.com:443",
                        "target": "b.example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

    let config: XrayConfig = serde_json::from_str(json).unwrap();
    let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
    let err = reality_dest_addr(settings).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn find_reality_inbounds_skips_non_reality_security() {
    let json = r#"{
            "inbounds": [{
                "port": 443,
                "streamSettings": {
                    "security": "tls",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

    let config: XrayConfig = serde_json::from_str(json).unwrap();
    assert!(find_reality_inbounds(&config).is_empty());
}

#[test]
fn parse_preserves_unknown_fields_in_extra() {
    let config: XrayConfig = serde_json::from_str(MINIMAL_VLESS_REALITY).unwrap();

    assert!(config.extra.contains_key("unknownTopLevel"));
    assert!(config.inbounds[0].extra.contains_key("sniffing"));

    let stream = config.inbounds[0].stream_settings.as_ref().unwrap();
    assert!(stream.extra.contains_key("sockopt"));
    assert_eq!(
        stream.extra["sockopt"]["tcpFastOpen"],
        serde_json::json!(true)
    );
}

#[test]
fn parse_short_ids_empty_and_hex() {
    let json = r#"{
            "inbounds": [{
                "port": 443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": ["", "0123456789abcdef"]
                    }
                }
            }]
        }"#;

    let config: XrayConfig = serde_json::from_str(json).unwrap();
    let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
    let short_ids = reality_short_ids(settings).unwrap();

    assert_eq!(short_ids.len(), 2);
    assert!(short_ids[0].is_empty());
    assert_eq!(
        short_ids[1],
        vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    );
}

const REALISTIC_XRAY_SERVER: &str =
    include_str!("../../../scripts/live_reality_smoke/xray-compatible-server.fixture.json");

#[test]
fn parses_realistic_xray_vless_tcp_reality_server_config() {
    let config: XrayConfig =
        serde_json::from_str(REALISTIC_XRAY_SERVER).expect("parse realistic config");
    let runtime = first_reality_inbound_runtime(&config).expect("runtime");

    assert_eq!(runtime.listen_addr, "127.0.0.1:24443");
    assert_eq!(runtime.dest_addr, "www.microsoft.com:443");
    assert_eq!(runtime.vless_decryption, "none");
    assert!(config.log.is_some());
    assert!(config.routing.is_some());
    assert_eq!(config.outbounds.len(), 2);
    assert!(config.inbounds[0].extra.contains_key("sniffing"));
    assert!(config.inbounds[0]
        .stream_settings
        .as_ref()
        .unwrap()
        .extra
        .contains_key("sockopt"));
}

#[test]
fn accepts_port_as_string() {
    let inbound: InboundObject =
        serde_json::from_str(r#"{"listen":"127.0.0.1","port":"443","protocol":"vless"}"#).unwrap();
    assert_eq!(inbound_listen_addr(&inbound).unwrap(), "127.0.0.1:443");
}

#[test]
fn rejects_port_range() {
    let inbound: InboundObject =
        serde_json::from_str(r#"{"listen":"127.0.0.1","port":"10000-20000"}"#).unwrap();
    let err = inbound_listen_addr(&inbound).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(
        err.to_string(),
        "port ranges are not supported for REALITY inbound: 10000-20000"
    );
}

#[test]
fn formats_ipv6_listen_correctly() {
    assert_eq!(format_listen_host(Some("::")).unwrap(), "[::]");
    assert_eq!(format_listen_host(Some("::1")).unwrap(), "[::1]");
    assert_eq!(format_listen_host(Some("[::1]")).unwrap(), "[::1]");
    assert_eq!(
        inbound_listen_addr(&InboundObject {
            tag: None,
            listen: Some("::1".to_string()),
            port: Some(InboundPortValue::Number(24443)),
            protocol: None,
            settings: None,
            stream_settings: None,
            extra: BTreeMap::new(),
        })
        .unwrap(),
        "[::1]:24443"
    );
}

#[test]
fn accepts_security_and_protocol_case_insensitively() {
    let json = r#"{
            "inbounds": [{
                "port": 443,
                "protocol": "VLESS",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "security": "REALITY",
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
    assert_eq!(find_reality_inbounds(&config).len(), 1);
}

#[test]
fn accepts_network_raw_as_tcp_compatible() {
    let json = r#"{
            "inbounds": [{
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "raw",
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
    assert_eq!(find_reality_inbounds(&config).len(), 1);
    assert!(validate_reality_transport_network(Some("raw")).is_ok());
    assert!(validate_reality_transport_network(Some("tcp")).is_ok());
    assert!(validate_reality_transport_network(None).is_ok());
}

fn vless_reality_inbound_json(network: &str) -> String {
    format!(
        r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{"clients": [], "decryption": "none"}},
                "streamSettings": {{
                    "network": "{network}",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    )
}

#[test]
fn validate_reality_transport_network_accepts_tcp_as_legacy_raw_alias() {
    assert!(validate_reality_transport_network(Some("tcp")).is_ok());
    assert!(validate_reality_transport_network(Some("TCP")).is_ok());
}

#[test]
fn validate_reality_transport_network_accepts_raw() {
    assert!(validate_reality_transport_network(Some("raw")).is_ok());
    assert!(validate_reality_transport_network(Some("RAW")).is_ok());
}

#[test]
fn validate_reality_transport_network_accepts_xhttp_aliases() {
    assert!(validate_reality_transport_network(Some("xhttp")).is_ok());
    assert!(validate_reality_transport_network(Some("splithttp")).is_ok());
    assert!(validate_reality_transport_network(Some("splitHTTP")).is_ok());
}

#[test]
fn validate_reality_transport_network_rejects_grpc_as_unimplemented() {
    let err = validate_reality_transport_network(Some("grpc")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(
        err.to_string(),
        "REALITY over gRPC runtime is not implemented yet"
    );
}

#[test]
fn validate_reality_transport_network_rejects_websocket_variants() {
    for network in ["ws", "websocket", "WebSocket"] {
        let err = validate_reality_transport_network(Some(network)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("WebSocket"));
    }
}

#[test]
fn validate_reality_transport_network_rejects_mkcp_httpupgrade_and_hysteria() {
    let cases = [
        (
            "mkcp",
            "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
        ),
        (
            "kcp",
            "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
        ),
        (
            "httpupgrade",
            "REALITY over HTTPUpgrade transport (network=httpupgrade) is not supported",
        ),
        (
            "hysteria",
            "REALITY over Hysteria transport (network=hysteria) is not supported",
        ),
    ];
    for (network, message) in cases {
        let err = validate_reality_transport_network(Some(network)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{network}");
        assert_eq!(err.to_string(), message, "{network}");
    }
}

#[test]
fn validate_reality_stream_settings_skips_non_reality_security() {
    let stream = StreamSettingsObject {
        network: Some("ws".to_string()),
        security: Some("tls".to_string()),
        reality_settings: None,
        xhttp_settings: None,
        splithttp_settings: None,
        extra: BTreeMap::new(),
    };

    assert!(validate_reality_stream_settings(&stream).is_ok());
}

#[test]
fn validate_reality_stream_settings_accepts_xhttp_with_reality_security() {
    let stream = StreamSettingsObject {
        network: Some("xhttp".to_string()),
        security: Some("reality".to_string()),
        reality_settings: None,
        xhttp_settings: Some(XHttpSettings {
            path: "/xhttp".to_string(),
            mode: Some("stream-one".to_string()),
            ..XHttpSettings::default()
        }),
        splithttp_settings: None,
        extra: BTreeMap::new(),
    };

    validate_reality_stream_settings(&stream).unwrap();
}

#[test]
fn validate_reality_stream_settings_accepts_unimplemented_xhttp_modes() {
    for mode in ["packet-up", "packet-down", "stream-up"] {
        let stream = StreamSettingsObject {
            network: Some("xhttp".to_string()),
            security: Some("reality".to_string()),
            reality_settings: None,
            xhttp_settings: Some(XHttpSettings {
                path: "/xhttp".to_string(),
                mode: Some(mode.to_string()),
                ..XHttpSettings::default()
            }),
            splithttp_settings: None,
            extra: BTreeMap::new(),
        };

        validate_reality_stream_settings(&stream)
            .unwrap_or_else(|err| panic!("mode {mode} should parse tolerant: {err}"));
    }
}

#[test]
fn validate_reality_stream_settings_accepts_raw_with_reality_security() {
    let stream = StreamSettingsObject {
        network: Some("raw".to_string()),
        security: Some("reality".to_string()),
        reality_settings: None,
        xhttp_settings: None,
        splithttp_settings: None,
        extra: BTreeMap::new(),
    };

    assert!(validate_reality_stream_settings(&stream).is_ok());
}

#[test]
fn first_reality_inbound_runtime_accepts_xhttp_transport() {
    let json = vless_reality_inbound_json("xhttp").replace(
        r#""realitySettings": {"#,
        r#""xhttpSettings": {"path": "/xhttp", "mode": "stream-one"}, "realitySettings": {"#,
    );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(runtime.transport, TransportNetwork::XHttp);
    assert_eq!(
        runtime.xhttp_settings.as_ref().unwrap().effective_path(),
        "/xhttp"
    );
    assert_eq!(
        runtime.xhttp_settings.as_ref().unwrap().effective_mode(),
        "stream-one"
    );
}

#[test]
fn first_reality_inbound_runtime_accepts_splithttp_alias() {
    let json = vless_reality_inbound_json("splithttp").replace(
        r#""realitySettings": {"#,
        r#""splithttpSettings": {"path": "/legacy", "mode": "auto"}, "realitySettings": {"#,
    );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(runtime.transport, TransportNetwork::XHttp);
    assert_eq!(
        runtime.xhttp_settings.as_ref().unwrap().effective_path(),
        "/legacy"
    );
    assert_eq!(
        runtime.xhttp_settings.as_ref().unwrap().effective_mode(),
        "auto"
    );
}

#[test]
fn first_reality_inbound_runtime_rejects_vision_flow_over_xhttp() {
    let json = vless_reality_inbound_json("xhttp")
            .replace(
                r#""settings": {"clients": [], "decryption": "none"}"#,
                r#""settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000001", "flow": "xtls-rprx-vision"}], "decryption": "none"}"#,
            )
            .replace(
                r#""realitySettings": {"#,
                r#""xhttpSettings": {"path": "/xhttp", "mode": "stream-one"}, "realitySettings": {"#,
            );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("flow=xtls-rprx-vision over XHTTP"));
}

#[test]
fn first_reality_inbound_runtime_rejects_grpc_transport() {
    let config: XrayConfig = serde_json::from_str(&vless_reality_inbound_json("grpc")).unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(
        err.to_string(),
        "REALITY over gRPC runtime is not implemented yet"
    );
}

#[test]
fn first_reality_inbound_runtime_rejects_websocket_transport() {
    let config: XrayConfig = serde_json::from_str(&vless_reality_inbound_json("ws")).unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err
        .to_string()
        .contains("REALITY over WebSocket transport (network=ws) is not supported"));
}

#[test]
fn skips_unsupported_ws_reality_inbound_and_selects_next_tcp() {
    let json = r#"{
            "inbounds": [
                {
                    "tag": "ws-reality",
                    "port": 8443,
                    "protocol": "vless",
                    "settings": {"clients": [], "decryption": "none"},
                    "streamSettings": {
                        "network": "ws",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "ws.example.com:443",
                            "serverNames": ["ws.example.com"],
                            "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                            "shortIds": [""]
                        }
                    }
                },
                {
                    "tag": "tcp-reality",
                    "port": 443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "tcp.example.com:443",
                            "serverNames": ["tcp.example.com"],
                            "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                            "shortIds": [""]
                        }
                    }
                }
            ]
        }"#;
    let config: XrayConfig = serde_json::from_str(json).unwrap();
    let inbounds = find_reality_inbounds(&config);
    assert_eq!(inbounds.len(), 1);
    assert_eq!(inbounds[0].tag.as_deref(), Some("tcp-reality"));
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(runtime.dest_addr, "tcp.example.com:443");
}

#[test]
fn dest_without_port_defaults_to_443() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com",
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": [""]
    }))
    .unwrap();
    assert_eq!(reality_dest_addr(&settings).unwrap(), "example.com:443");
}

#[test]
fn ipv6_dest_stays_bracketed() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "[2606:4700:4700::1111]:443",
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": [""]
    }))
    .unwrap();
    assert_eq!(
        reality_dest_addr(&settings).unwrap(),
        "[2606:4700:4700::1111]:443"
    );
}

#[test]
fn rejects_wildcard_server_names() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["*"],
        "privateKey": "abc",
        "shortIds": [""]
    }))
    .unwrap();
    let err = reality_server_names(&settings).unwrap_err();
    assert!(err.to_string().contains("wildcard"));
}

#[test]
fn rejects_empty_server_names_with_clear_error() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": [],
        "privateKey": "abc",
        "shortIds": [""]
    }))
    .unwrap();
    let err = reality_server_names(&settings).unwrap_err();
    assert!(err
        .to_string()
        .contains("serverNames must contain at least one server name"));
}

#[test]
fn accepts_uppercase_short_ids() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": ["0123456789ABCDEF"]
    }))
    .unwrap();
    assert_eq!(
        reality_short_ids(&settings).unwrap(),
        vec![vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]]
    );
}

#[test]
fn rejects_odd_length_short_id() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": ["abc"]
    }))
    .unwrap();
    let err = reality_short_ids(&settings).unwrap_err();
    assert!(err.to_string().contains("abc"));
    assert!(err.to_string().contains("even"));
}

#[test]
fn rejects_too_long_short_id() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": ["0123456789abcdef0"]
    }))
    .unwrap();
    let err = reality_short_ids(&settings).unwrap_err();
    assert!(err.to_string().contains("0123456789abcdef0"));
}

#[test]
fn rejects_non_hex_short_id() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": ["012g"]
    }))
    .unwrap();
    let err = reality_short_ids(&settings).unwrap_err();
    assert!(err.to_string().contains("012g"));
}

#[test]
fn defaults_missing_vless_decryption_to_none() {
    let inbound: InboundObject = serde_json::from_str(
            r#"{"protocol":"vless","settings":{"clients":[{"id":"00000000-0000-0000-0000-000000000001"}]}}"#,
        )
        .unwrap();
    let settings = inbound_vless_settings(&inbound).unwrap().unwrap();
    assert!(settings.decryption.is_none());

    let json = format!(
        r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}]
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert_eq!(runtime.vless_decryption, "none");
}

#[test]
fn rejects_decryption_other_than_none() {
    let inbound: InboundObject = serde_json::from_str(
        r#"{"protocol":"vless","settings":{"clients":[],"decryption":"auto"}}"#,
    )
    .unwrap();
    let err = inbound_vless_settings(&inbound).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn validates_client_uuid_at_runtime() {
    let invalid_id = "a".repeat(31);
    let json = format!(
        r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "{invalid_id}"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert!(err.to_string().contains("invalid VLESS client id"));
}

#[test]
fn rejects_both_dest_and_target() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "a.example.com:443",
        "target": "b.example.com:443",
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": [""]
    }))
    .unwrap();
    let err = reality_dest_addr(&settings).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        err.to_string(),
        "realitySettings.dest and realitySettings.target are mutually exclusive"
    );
}

#[test]
fn rejects_missing_dest_and_target() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": [""]
    }))
    .unwrap();
    let err = reality_dest_addr(&settings).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        err.to_string(),
        "realitySettings.dest or realitySettings.target is required"
    );
}

#[test]
fn accepts_empty_short_id() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": "abc",
        "shortIds": [""]
    }))
    .unwrap();
    assert_eq!(
        reality_short_ids(&settings).unwrap(),
        vec![Vec::<u8>::new()]
    );
}

#[test]
fn preserves_client_flow_vision() {
    let json = format!(
        r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "flow": "xtls-rprx-vision"
                    }}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let settings = inbound_vless_settings(&config.inbounds[0])
        .unwrap()
        .unwrap();
    assert_eq!(
        settings.clients[0].flow.as_deref(),
        Some("xtls-rprx-vision")
    );

    let runtime = first_reality_inbound_runtime(&config).expect("vision runtime");
    assert_eq!(
        runtime.vless_clients[0].flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn missing_flow_is_empty_or_none() {
    let json = format!(
        r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let settings = inbound_vless_settings(&config.inbounds[0])
        .unwrap()
        .unwrap();
    assert!(settings.clients[0].flow.is_none());

    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert!(runtime.vless_clients[0].flow.is_none());
}

#[test]
fn unknown_flow_returns_unsupported_at_runtime_validation() {
    let json = format!(
        r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "flow": "unknown-flow"
                    }}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let settings = inbound_vless_settings(&config.inbounds[0])
        .unwrap()
        .unwrap();
    assert_eq!(settings.clients[0].flow.as_deref(), Some("unknown-flow"));

    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(err.to_string(), "unsupported VLESS flow: unknown-flow");
}

#[test]
fn vision_flow_runtime_accepts_when_implemented() {
    const VISION_FIXTURE: &str = include_str!(
        "../../../scripts/live_reality_smoke/xray-compatible-server-vision.fixture.json"
    );
    let config: XrayConfig = serde_json::from_str(VISION_FIXTURE).expect("parse vision fixture");
    let settings = inbound_vless_settings(&config.inbounds[0])
        .unwrap()
        .unwrap();
    assert_eq!(
        settings.clients[0].flow.as_deref(),
        Some("xtls-rprx-vision")
    );

    let runtime = first_reality_inbound_runtime(&config).expect("vision runtime");
    assert_eq!(
        runtime.vless_clients[0].flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn preserves_unknown_fields() {
    let json = r#"{
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "in",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "alterId": 0,
                        "customClientField": true
                    }],
                    "decryption": "none",
                    "fallbacks": [{"dest": 80}]
                },
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""],
                        "customRealityField": "keep"
                    },
                    "customStreamField": 1
                },
                "customInboundField": "keep"
            }],
            "routing": {"rules": []},
            "unknownTopLevel": true
        }"#;
    let config: XrayConfig = serde_json::from_str(json).unwrap();
    assert_eq!(
        config.log.as_ref().unwrap().loglevel.as_deref(),
        Some("debug")
    );
    assert!(config.routing.is_some());
    assert!(config.extra.contains_key("unknownTopLevel"));
    assert!(config.inbounds[0].extra.contains_key("customInboundField"));
    let stream = config.inbounds[0].stream_settings.as_ref().unwrap();
    assert!(stream.extra.contains_key("customStreamField"));
    let reality = stream.reality_settings.as_ref().unwrap();
    assert!(reality.extra.contains_key("customRealityField"));
    let settings = inbound_vless_settings(&config.inbounds[0])
        .unwrap()
        .unwrap();
    assert_eq!(settings.fallbacks.len(), 1);
    assert_eq!(settings.fallbacks[0].dest.addr, "127.0.0.1:80");
    assert!(settings.clients[0].extra.contains_key("alterId"));
    assert!(settings.clients[0].extra.contains_key("customClientField"));
}

fn minimal_reality_config_json(mldsa65_seed: Option<&str>) -> String {
    let mldsa65_seed_field = match mldsa65_seed {
        Some(seed) => format!(r#","mldsa65Seed": "{seed}""#),
        None => String::new(),
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
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                        {mldsa65_seed_field}
                    }}
                }}
            }}]
        }}"#
    )
}

#[test]
fn accepts_valid_mldsa65_seed_in_runtime_config() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_config_json(Some(TEST_MLDSA65_SEED))).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();

    let seed = runtime.mldsa65_seed.expect("expected parsed mldsa65 seed");
    assert_eq!(seed.as_bytes().len(), crate::reality::MLDSA65_SEED_LEN);
}

#[test]
fn rejects_invalid_mldsa65_seed_base64() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_config_json(Some("not-valid-base64!!!"))).unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("invalid mldsa65Seed base64"));
}

#[test]
fn rejects_mldsa65_seed_with_31_decoded_bytes() {
    let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(Some(
        TEST_MLDSA65_SEED_31_BYTES,
    )))
    .unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected 32 bytes, got 31"));
}

#[test]
fn rejects_mldsa65_seed_with_33_decoded_bytes() {
    let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(Some(
        TEST_MLDSA65_SEED_33_BYTES,
    )))
    .unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected 32 bytes, got 33"));
}

#[test]
fn empty_mldsa65_seed_is_none_in_runtime() {
    let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(Some(""))).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert!(runtime.mldsa65_seed.is_none());

    let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(None)).unwrap();
    let runtime = first_reality_inbound_runtime(&config).unwrap();
    assert!(runtime.mldsa65_seed.is_none());
}

#[test]
fn rejects_mldsa65_seed_equal_to_private_key() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_config_json(Some(TEST_REALITY_PRIVATE_KEY))).unwrap();
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("must not equal privateKey"));
}

fn vless_reality_config_from_reality_json(reality: serde_json::Value) -> XrayConfig {
    let json = serde_json::json!({
        "inbounds": [{
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": reality
            }
        }]
    });
    serde_json::from_value(json).expect("parse config")
}

fn vless_reality_config_from_stream_settings(stream: serde_json::Value) -> XrayConfig {
    let json = serde_json::json!({
        "inbounds": [{
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none"
            },
            "streamSettings": stream
        }]
    });
    serde_json::from_value(json).expect("parse config")
}

#[test]
fn ignores_client_only_public_key_on_inbound_reality_settings() {
    let config = vless_reality_config_from_reality_json(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": TEST_REALITY_PRIVATE_KEY,
        "shortIds": [""],
        "publicKey": "oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg"
    }));
    let runtime = first_reality_inbound_runtime(&config).expect("runtime config");
    assert_eq!(runtime.private_key, TEST_REALITY_PRIVATE_KEY);
    assert!(runtime.mldsa65_seed.is_none());
}

#[test]
fn ignores_client_only_mldsa65_verify_on_inbound_reality_settings() {
    let config = vless_reality_config_from_reality_json(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": TEST_REALITY_PRIVATE_KEY,
        "shortIds": [""],
        "mldsa65Verify": "AAECAwQ"
    }));
    let runtime = first_reality_inbound_runtime(&config).expect("runtime config");
    assert_eq!(runtime.private_key, TEST_REALITY_PRIVATE_KEY);
    assert!(runtime.mldsa65_seed.is_none());
}

#[test]
fn accepts_limit_fallback_upload_at_startup() {
    let config = vless_reality_config_from_reality_json(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": TEST_REALITY_PRIVATE_KEY,
        "shortIds": [""],
        "limitFallbackUpload": {
            "afterBytes": 1024,
            "bytesPerSec": 100,
            "burstBytesPerSec": 200
        }
    }));
    let runtime = first_reality_inbound_runtime(&config).expect("runtime config");
    assert_eq!(runtime.limit_fallback_upload.after_bytes, 1024);
    assert_eq!(runtime.limit_fallback_upload.bytes_per_sec, 100);
    assert_eq!(runtime.limit_fallback_upload.burst_bytes_per_sec, 200);
    assert!(runtime.limit_fallback_download.is_disabled());
}

#[test]
fn accepts_limit_fallback_download_at_startup() {
    let config = vless_reality_config_from_reality_json(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": TEST_REALITY_PRIVATE_KEY,
        "shortIds": [""],
        "limitFallbackDownload": {
            "afterBytes": 2048,
            "bytesPerSec": 50,
            "burstBytesPerSec": 100
        }
    }));
    let runtime = first_reality_inbound_runtime(&config).expect("runtime config");
    assert_eq!(runtime.limit_fallback_download.after_bytes, 2048);
    assert_eq!(runtime.limit_fallback_download.bytes_per_sec, 50);
    assert!(runtime.limit_fallback_upload.is_disabled());
}

#[test]
fn limit_fallback_defaults_and_partial_objects_parse() {
    let base = || {
        vless_reality_config_from_reality_json(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""]
        }))
    };
    let runtime = first_reality_inbound_runtime(&base()).expect("defaults");
    assert!(runtime.limit_fallback_upload.is_disabled());
    assert!(runtime.limit_fallback_download.is_disabled());

    let config = vless_reality_config_from_reality_json(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": TEST_REALITY_PRIVATE_KEY,
        "shortIds": [""],
        "limitFallbackUpload": {}
    }));
    let runtime = first_reality_inbound_runtime(&config).expect("empty upload object");
    assert!(runtime.limit_fallback_upload.is_disabled());

    let config = vless_reality_config_from_reality_json(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": TEST_REALITY_PRIVATE_KEY,
        "shortIds": [""],
        "limitFallbackUpload": { "bytesPerSec": 100_000 }
    }));
    let runtime = first_reality_inbound_runtime(&config).expect("partial upload");
    assert_eq!(runtime.limit_fallback_upload.bytes_per_sec, 100_000);
}

#[test]
fn limit_fallback_accepts_both_directions_and_u64_edges() {
    let config = vless_reality_config_from_reality_json(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": TEST_REALITY_PRIVATE_KEY,
        "shortIds": [""],
        "limitFallbackUpload": {
            "afterBytes": u64::MAX,
            "bytesPerSec": 0,
            "burstBytesPerSec": u64::MAX
        },
        "limitFallbackDownload": {
            "afterBytes": u64::MAX,
            "bytesPerSec": u64::MAX,
            "burstBytesPerSec": u64::MAX
        }
    }));
    let runtime = first_reality_inbound_runtime(&config).expect("u64 edge config");

    assert_eq!(runtime.limit_fallback_upload.after_bytes, u64::MAX);
    assert_eq!(runtime.limit_fallback_upload.burst_bytes_per_sec, u64::MAX);
    assert!(runtime.limit_fallback_upload.is_disabled());
    assert_eq!(runtime.limit_fallback_download.after_bytes, u64::MAX);
    assert_eq!(runtime.limit_fallback_download.bytes_per_sec, u64::MAX);
    assert_eq!(
        runtime.limit_fallback_download.burst_bytes_per_sec,
        u64::MAX
    );
}

#[test]
fn limit_fallback_rejects_malformed_and_negative_values() {
    let malformed = serde_json::from_value::<XrayConfig>(serde_json::json!({
        "inbounds": [{
            "port": 443,
            "protocol": "vless",
            "settings": { "clients": [{"id": "00000000-0000-0000-0000-000000000001"}], "decryption": "none" },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "example.com:443",
                    "serverNames": ["example.com"],
                    "privateKey": TEST_REALITY_PRIVATE_KEY,
                    "shortIds": [""],
                    "limitFallbackUpload": { "bytesPerSec": "fast" }
                }
            }
        }]
    }));
    assert!(malformed.is_err());

    let negative = serde_json::from_value::<XrayConfig>(serde_json::json!({
        "inbounds": [{
            "port": 443,
            "protocol": "vless",
            "settings": { "clients": [{"id": "00000000-0000-0000-0000-000000000001"}], "decryption": "none" },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "example.com:443",
                    "serverNames": ["example.com"],
                    "privateKey": TEST_REALITY_PRIVATE_KEY,
                    "shortIds": [""],
                    "limitFallbackUpload": { "bytesPerSec": -1 }
                }
            }
        }]
    }));
    assert!(negative.is_err());
}

#[test]
fn differing_limit_fallback_configs_do_not_merge() {
    let make = |upload_bytes_per_sec: u64| {
        vless_reality_config_from_reality_json(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""],
            "limitFallbackUpload": { "bytesPerSec": upload_bytes_per_sec }
        }))
    };
    let mut config = make(100);
    config
        .inbounds
        .push(make(200).inbounds.into_iter().next().unwrap());
    config.inbounds[1].tag = Some("reality-in-2".to_string());
    let runtimes = reality_inbound_runtimes(&config).expect("runtimes");
    assert_eq!(runtimes.len(), 2);
}

#[test]
fn rejects_stream_settings_tls_settings_on_reality_inbound() {
    let config = vless_reality_config_from_stream_settings(serde_json::json!({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""]
        },
        "tlsSettings": {
            "serverName": "example.com"
        }
    }));
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("streamSettings.tlsSettings"));
}

#[test]
fn rejects_stream_settings_ws_settings_on_reality_inbound() {
    let config = vless_reality_config_from_stream_settings(serde_json::json!({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""]
        },
        "wsSettings": {
            "path": "/"
        }
    }));
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("streamSettings.wsSettings"));
}

#[test]
fn sockopt_in_stream_settings_extra_remains_valid() {
    let config = vless_reality_config_from_stream_settings(serde_json::json!({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""]
        },
        "sockopt": {
            "tcpFastOpen": true
        }
    }));
    let runtime = first_reality_inbound_runtime(&config).expect("sockopt allowed");
    assert_eq!(runtime.dest_addr, "example.com:443");
}

#[test]
fn reality_type_and_xver_remain_valid_at_startup() {
    let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "privateKey": TEST_REALITY_PRIVATE_KEY,
        "shortIds": [""],
        "type": "tcp",
        "xver": 2
    }))
    .unwrap();

    assert_eq!(settings.transport_type.as_deref(), Some("tcp"));
    assert_eq!(settings.xver, 2);

    let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(None)).unwrap();
    let mut inbound = config.inbounds[0].clone();
    inbound.stream_settings = Some(StreamSettingsObject {
        network: Some("tcp".to_string()),
        security: Some("reality".to_string()),
        reality_settings: Some(settings),
        xhttp_settings: None,
        splithttp_settings: None,
        extra: BTreeMap::new(),
    });
    let config = XrayConfig {
        log: None,
        api: None,
        dns: None,
        stats: None,
        policy: None,
        routing: None,
        observatory: None,
        burst_observatory: None,
        outbounds: Vec::new(),
        inbounds: vec![inbound],
        extra: BTreeMap::new(),
    };
    let runtime = first_reality_inbound_runtime(&config).expect("type and xver allowed");
    assert_eq!(runtime.dest_addr, "example.com:443");
}

#[test]
fn mldsa65_seed_config_still_valid_with_explicit_reject_policy() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_config_json(Some(TEST_MLDSA65_SEED))).unwrap();
    let runtime = first_reality_inbound_runtime(&config).expect("valid seed");
    assert!(runtime.mldsa65_seed.is_some());
}

#[test]
fn parse_http_unix_config_uri_splits_socket_and_redacts_token() {
    let source = "http+unix:///run/a.sock/internal/get-config?token=secret";
    let (socket, path) = parse_http_unix_config_uri(source).expect("parse");
    assert_eq!(socket, "/run/a.sock");
    assert_eq!(path, "/internal/get-config?token=secret");
    let redacted = redact_config_source(source);
    assert!(!redacted.contains("secret"));
    assert!(redacted.contains("?<redacted>"));
}

#[test]
fn parse_http_unix_config_uri_requires_sock_suffix() {
    let err = parse_http_unix_config_uri("http+unix:///run/no-sock-path").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains(".sock"));
}

#[test]
fn is_remnawave_http_unix_detects_internal_get_config() {
    let source = "http+unix:///run/a.sock/internal/get-config?token=secret";
    assert!(is_remnawave_http_unix_config_source(source));
    assert!(!is_remnawave_http_unix_config_source("/etc/xray.json"));
    assert!(!is_remnawave_http_unix_config_source(
        "http+unix:///run/a.sock/other/path"
    ));
}

#[test]
fn parse_api_inbound_tls_settings_from_remnawave_shape() {
    let cert_lines = [
        "-----BEGIN CERTIFICATE-----",
        "TESTCERT",
        "-----END CERTIFICATE-----",
    ];
    let key_lines = [
        "-----BEGIN PRIVATE KEY-----",
        "TESTKEY",
        "-----END PRIVATE KEY-----",
    ];
    let inbound: InboundObject = serde_json::from_value(serde_json::json!({
        "tag": "REMNAWAVE_API_INBOUND",
        "listen": "127.0.0.1",
        "port": 61000,
        "protocol": "dokodemo-door",
        "settings": { "address": "127.0.0.1" },
        "streamSettings": {
            "security": "tls",
            "tlsSettings": {
                "serverName": "internal.remnawave.local",
                "certificates": [
                    {
                        "certificate": cert_lines,
                        "key": key_lines
                    },
                    {
                        "usage": "verify",
                        "certificate": cert_lines
                    }
                ]
            }
        }
    }))
    .expect("parse inbound");
    let material = extract_tls_material_from_inbound(&inbound)
        .expect("extract")
        .expect("material");
    assert_eq!(
        String::from_utf8_lossy(&material.cert_pem),
        "-----BEGIN CERTIFICATE-----\nTESTCERT\n-----END CERTIFICATE-----"
    );
    assert_eq!(
        String::from_utf8_lossy(&material.key_pem),
        "-----BEGIN PRIVATE KEY-----\nTESTKEY\n-----END PRIVATE KEY-----"
    );
    assert_eq!(
        material.server_name.as_deref(),
        Some("internal.remnawave.local")
    );
}

#[test]
fn merge_compatible_reality_inbounds_combines_users_and_flow() {
    let config: XrayConfig = serde_json::from_str(include_str!(
        "../../../tests/fixtures/remna/remnawave_vless_reality_vision_users.json"
    ))
    .expect("parse fixture");
    let runtime = first_reality_inbound_runtime(&config).expect("runtime");
    assert_eq!(runtime.merged_inbound_tags.len(), 2);
    assert_eq!(runtime.vless_clients.len(), 3);
    let distribution = crate::vless::vless_flow_distribution(&runtime.vless_clients);
    assert_eq!(distribution.get("xtls-rprx-vision").copied(), Some(2));
}

#[test]
fn reality_inbound_runtimes_serves_two_listen_addresses() {
    let config: XrayConfig = serde_json::from_str(include_str!(
        "../../../tests/fixtures/remna/remnawave_two_reality_inbounds_flow.json"
    ))
    .expect("parse fixture");
    let runtimes = reality_inbound_runtimes(&config).expect("runtimes");
    assert_eq!(runtimes.len(), 2);
    let listens: Vec<_> = runtimes
        .iter()
        .map(|runtime| runtime.listen_addr.as_str())
        .collect();
    assert!(listens.contains(&"0.0.0.0:443"));
    assert!(listens.contains(&"0.0.0.0:8444"));
}

#[test]
fn inbound_settings_flow_applies_to_clients_missing_flow() {
    let json = format!(
        r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "flow": "xtls-rprx-vision",
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
    );
    let config: XrayConfig = serde_json::from_str(&json).unwrap();
    let runtime = first_reality_inbound_runtime(&config).expect("runtime");
    assert_eq!(
        runtime.vless_clients[0].flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn localhost_api_listen_detection() {
    assert!(is_localhost_api_listen("127.0.0.1:61000"));
    assert!(!is_localhost_api_listen("0.0.0.0:61000"));
}

#[test]
fn reality_inbound_runtime_debug_does_not_expose_secrets() {
    let seed =
        crate::reality::decode_mldsa65_seed(Some(TEST_MLDSA65_SEED), TEST_REALITY_PRIVATE_KEY)
            .unwrap()
            .unwrap();
    let runtime = RealityInboundRuntime {
        tag: Some("reality-in".to_string()),
        merged_inbound_tags: vec!["reality-in".to_string()],
        protocol: Some("vless".to_string()),
        listen_addr: "127.0.0.1:443".to_string(),
        dest_addr: "www.example.com:443".to_string(),
        private_key: TEST_REALITY_PRIVATE_KEY.to_string(),
        server_names: vec!["www.example.com".to_string()],
        short_ids: vec![Vec::new()],
        max_time_diff: 0,
        min_client_ver: None,
        max_client_ver: None,
        show: false,
        mldsa65_seed: Some(seed),
        vless_clients: vec![VlessClientObject {
            id: "00000000-0000-0000-0000-000000000001".to_string(),
            email: None,
            flow: None,
            level: None,
            extra: BTreeMap::new(),
        }],
        vless_decryption: "none".to_string(),
        vless_fallbacks: Vec::new(),
        transport: TransportNetwork::RawTcp,
        xhttp_settings: None,
        dest_xver: 0,
        dest_transport: crate::reality::RealityDestTransport::Tcp,
        limit_fallback_upload: LimitFallback::default(),
        limit_fallback_download: LimitFallback::default(),
    };
    let debug = format!("{runtime:?}");

    assert!(debug.contains("mldsa65_seed"));
    assert!(debug.contains("private_key"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(TEST_MLDSA65_SEED));
    assert!(!debug.contains(TEST_REALITY_PRIVATE_KEY));
}
