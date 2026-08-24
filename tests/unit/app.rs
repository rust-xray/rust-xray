use super::*;
use crate::vless::{build_fallback_context, resolve_fallback_selection, FallbackContext};

const VLESS_REALITY_CONFIG: &str = r#"{
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
                    "shortIds": [""]
                }
            }
        }]
    }"#;

const TEST_MLDSA65_SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn vless_reality_config_with_mldsa65_seed(seed: &str) -> String {
    VLESS_REALITY_CONFIG.replace(
        r#""shortIds": [""]"#,
        &format!(r#""shortIds": [""], "mldsa65Seed": "{seed}""#),
    )
}

fn vless_reality_config_with_network_and_flow(network: &str, flow: Option<&str>) -> String {
    let flow_field = flow
        .map(|flow| format!(r#","flow":"{flow}""#))
        .unwrap_or_default();
    let xhttp_settings = if network == "xhttp" || network == "splithttp" {
        r#","xhttpSettings":{"path":"/xhttp","mode":"stream-one"}"#
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
                        "clients": [{{"id": "00000000-0000-0000-0000-000000000001"{flow_field}}}],
                        "decryption": "none"
                    }},
                    "streamSettings": {{
                        "network": "{network}",
                        "security": "reality"{xhttp_settings},
                        "realitySettings": {{
                            "show": false,
                            "dest": "www.example.com:443",
                            "serverNames": ["www.example.com"],
                            "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                            "shortIds": [""]
                        }}
                    }}
                }}]
            }}"#
    )
}

#[test]
fn runtime_config_from_xray_builds_vless_clients() {
    let xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
    let config = runtime_config_from_xray(&xray).expect("build runtime config");

    assert_eq!(config.user_manager.user_count(), 1);
    assert!(config
        .user_manager
        .contains_id(uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()));
    assert_eq!(config.inbound.tag.as_deref(), Some("reality-in"));
    assert!(config.inbound.fallbacks.is_empty());
}

#[test]
fn runtime_listener_merge_keeps_different_fallback_limits_separate() {
    let mut xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
    let mut upload_limited = xray.inbounds[0].clone();
    upload_limited.tag = Some("upload-limited".to_string());
    upload_limited
        .stream_settings
        .as_mut()
        .expect("stream settings")
        .reality_settings
        .as_mut()
        .expect("reality settings")
        .limit_fallback_upload
        .bytes_per_sec = 100;

    let mut download_limited = xray.inbounds[0].clone();
    download_limited.tag = Some("download-limited".to_string());
    download_limited
        .stream_settings
        .as_mut()
        .expect("stream settings")
        .reality_settings
        .as_mut()
        .expect("reality settings")
        .limit_fallback_download
        .after_bytes = 1;

    xray.inbounds.extend([upload_limited, download_limited]);
    let runtime = load_runtime_config(&xray, Arc::new(StatsRegistry::new()))
        .expect("build listener runtimes");
    assert_eq!(runtime.inbounds.len(), 3);
}

#[test]
fn runtime_config_uses_normalized_raw_tcp_transport() {
    let xray: XrayConfig = serde_json::from_str(&vless_reality_config_with_network_and_flow(
        "tcp",
        Some("xtls-rprx-vision"),
    ))
    .expect("parse config");
    let config = runtime_config_from_xray(&xray).expect("build runtime config");

    assert_eq!(config.inbound.transport, InboundTransportConfig::RawTcp);
    assert_eq!(
        config.user_manager.list_managed_users()[0].flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn runtime_config_uses_normalized_xhttp_transport_for_empty_flow() {
    let xray: XrayConfig =
        serde_json::from_str(&vless_reality_config_with_network_and_flow("xhttp", None))
            .expect("parse config");
    let config = runtime_config_from_xray(&xray).expect("build runtime config");

    assert!(matches!(
        config.inbound.transport,
        InboundTransportConfig::XHttp(_)
    ));
    assert_eq!(config.user_manager.list_managed_users()[0].flow, None);
}

#[test]
fn runtime_config_rejects_xhttp_vision_flow() {
    let xray: XrayConfig = serde_json::from_str(&vless_reality_config_with_network_and_flow(
        "xhttp",
        Some("xtls-rprx-vision"),
    ))
    .expect("parse config");
    let err = match runtime_config_from_xray(&xray) {
        Ok(_) => panic!("xhttp vision flow should be rejected"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("flow=xtls-rprx-vision over XHTTP"));
}

#[test]
fn runtime_gate_without_seed_is_ok() {
    let xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
    let config = runtime_config_from_xray(&xray).expect("build runtime config");

    assert!(config.inbound.reality.mldsa65_seed.is_none());
    validate_reality_runtime_feature_gates(&config).expect("gate allows absent seed");
}

#[test]
fn mldsa65_runtime_mode_without_seed_is_disabled() {
    let xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
    let config = runtime_config_from_xray(&xray).expect("build runtime config");

    assert!(config.inbound.reality.mldsa65_seed.is_none());
    validate_reality_runtime_feature_gates(&config).expect("absent mldsa65Seed is unchanged");
}

#[test]
fn runtime_gate_with_valid_mldsa65_seed_is_ok() {
    let json = vless_reality_config_with_mldsa65_seed(TEST_MLDSA65_SEED);
    let xray: XrayConfig = serde_json::from_str(&json).expect("parse config");
    let config = runtime_config_from_xray(&xray).expect("build runtime config");

    assert!(config.inbound.reality.mldsa65_seed.is_some());

    validate_reality_runtime_feature_gates(&config).expect("valid seed runtime gate");
}

#[test]
fn invalid_mldsa65_seed_still_fails_before_runtime_gate() {
    let json = vless_reality_config_with_mldsa65_seed("not-valid-base64!!!");
    let xray: XrayConfig = serde_json::from_str(&json).expect("parse config");
    let err = match runtime_config_from_xray(&xray) {
        Ok(_) => panic!("invalid mldsa65Seed should fail before runtime feature gate"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("invalid mldsa65Seed base64"));
}

fn runtime_with_fallbacks() -> InboundListenerConfig {
    runtime_with_fallbacks_json("")
}

fn runtime_with_fallbacks_and_mldsa65_seed() -> InboundListenerConfig {
    runtime_with_fallbacks_json(&format!(r#","mldsa65Seed":"{TEST_MLDSA65_SEED}""#))
}

fn runtime_with_fallbacks_json(reality_extra: &str) -> InboundListenerConfig {
    let json = r#"{
            "inbounds": [{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none",
                    "fallbacks": [
                        {"dest": 19501},
                        {"name": "name-fallback.test", "dest": 19502},
                        {"path": "/smoke-path", "dest": 19503},
                        {"alpn": "http/1.1", "dest": 19505},
                        {"alpn": "h2", "dest": 19506},
                        {"name": "proxy-fallback.test", "dest": 19504, "xver": 1},
                        {"name": "proxy-v2-fallback.test", "dest": 19507, "xver": 2}
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""]__REALITY_EXTRA__
                    }
                }
            }]
        }"#
    .replace("__REALITY_EXTRA__", reality_extra);
    let xray: XrayConfig = serde_json::from_str(&json).expect("parse config");
    runtime_config_from_xray(&xray).expect("build runtime config")
}

fn runtime_selection(config: &InboundListenerConfig, ctx: &FallbackContext) -> (String, u8) {
    let selection = resolve_fallback_selection(
        &config.inbound.fallbacks,
        &config.inbound.reality.dest_addr,
        ctx,
    )
    .expect("resolve fallback");
    (selection.dest, selection.xver)
}

#[test]
fn runtime_resolves_default_fallback_over_reality_dest() {
    let config = runtime_with_fallbacks();

    assert_eq!(
        runtime_selection(&config, &FallbackContext::default()),
        ("127.0.0.1:19501".to_string(), 0)
    );
}

#[test]
fn runtime_resolves_fallback_by_sni_name() {
    let config = runtime_with_fallbacks();
    let ctx = FallbackContext {
        sni: Some("name-fallback.test".to_string()),
        ..FallbackContext::default()
    };

    assert_eq!(
        runtime_selection(&config, &ctx),
        ("127.0.0.1:19502".to_string(), 0)
    );
}

#[test]
fn runtime_resolves_fallback_by_alpn_http11() {
    let config = runtime_with_fallbacks();
    let ctx = FallbackContext {
        alpn: Some("http/1.1".to_string()),
        alpn_offers: vec!["http/1.1".to_string()],
        ..FallbackContext::default()
    };

    assert_eq!(
        runtime_selection(&config, &ctx),
        ("127.0.0.1:19505".to_string(), 0)
    );
}

#[test]
fn runtime_resolves_fallback_by_alpn_h2() {
    let config = runtime_with_fallbacks();
    let ctx = FallbackContext {
        alpn: Some("http/1.1".to_string()),
        alpn_offers: vec!["http/1.1".to_string(), "h2".to_string()],
        ..FallbackContext::default()
    };

    assert_eq!(
        runtime_selection(&config, &ctx),
        ("127.0.0.1:19506".to_string(), 0)
    );
}

#[test]
fn runtime_resolves_fallback_by_plain_http_path() {
    let config = runtime_with_fallbacks();
    let ctx = build_fallback_context(
        None,
        b"GET /smoke-path/resource HTTP/1.1\r\nHost: smoke.local\r\n\r\n",
    );

    assert_eq!(
        runtime_selection(&config, &ctx),
        ("127.0.0.1:19503".to_string(), 0)
    );
}

#[test]
fn runtime_resolves_fallback_xver_values() {
    let config = runtime_with_fallbacks();
    let proxy_v1 = FallbackContext {
        sni: Some("proxy-fallback.test".to_string()),
        ..FallbackContext::default()
    };
    let proxy_v2 = FallbackContext {
        sni: Some("proxy-v2-fallback.test".to_string()),
        ..FallbackContext::default()
    };

    assert_eq!(
        runtime_selection(&config, &proxy_v1),
        ("127.0.0.1:19504".to_string(), 1)
    );
    assert_eq!(
        runtime_selection(&config, &proxy_v2),
        ("127.0.0.1:19507".to_string(), 2)
    );
}

#[test]
fn runtime_fallback_selection_with_mldsa65_seed_stays_on_fallback_targets() {
    let config = runtime_with_fallbacks_and_mldsa65_seed();
    assert!(config.inbound.reality.mldsa65_seed.is_some());

    let path_ctx = build_fallback_context(
        None,
        b"GET /smoke-path/resource HTTP/1.1\r\nHost: smoke.local\r\n\r\n",
    );
    let h2_ctx = FallbackContext {
        alpn: Some("http/1.1".to_string()),
        alpn_offers: vec!["http/1.1".to_string(), "h2".to_string()],
        ..FallbackContext::default()
    };
    let proxy_v1_ctx = FallbackContext {
        sni: Some("proxy-fallback.test".to_string()),
        ..FallbackContext::default()
    };
    let proxy_v2_ctx = FallbackContext {
        sni: Some("proxy-v2-fallback.test".to_string()),
        ..FallbackContext::default()
    };

    assert_eq!(
        runtime_selection(&config, &FallbackContext::default()),
        ("127.0.0.1:19501".to_string(), 0)
    );
    assert_eq!(
        runtime_selection(&config, &path_ctx),
        ("127.0.0.1:19503".to_string(), 0)
    );
    assert_eq!(
        runtime_selection(&config, &h2_ctx),
        ("127.0.0.1:19506".to_string(), 0)
    );
    assert_eq!(
        runtime_selection(&config, &proxy_v1_ctx),
        ("127.0.0.1:19504".to_string(), 1)
    );
    assert_eq!(
        runtime_selection(&config, &proxy_v2_ctx),
        ("127.0.0.1:19507".to_string(), 2)
    );
}

#[test]
fn is_early_eof_detects_unexpected_eof_and_message() {
    let unexpected_eof =
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "connection closed");
    assert!(is_early_eof(&unexpected_eof));

    let message_only = std::io::Error::other("early eof");
    assert!(is_early_eof(&message_only));

    let invalid_data = std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "inbound preamble is neither TLS ClientHello nor HTTP/1.x request",
    );
    assert!(!is_early_eof(&invalid_data));
}

#[test]
fn preamble_read_stats_records_preview_up_to_32_bytes() {
    let mut stats = PreambleReadStats::new();
    stats.record(&[0x16, 0x03, 0x01]);
    assert_eq!(stats.bytes_read, 3);
    assert_eq!(stats.hex_preview(), "160301");

    stats.record(&vec![0xab; 40]);
    assert_eq!(stats.bytes_read, 43);
    assert_eq!(stats.preview.len(), 32);
    assert_eq!(stats.preview[0], 0x16);
}

#[test]
fn preamble_read_error_kind_labels_eof_and_reset() {
    assert_eq!(
        preamble_read_error_kind(&std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
        "UnexpectedEof"
    );
    assert_eq!(
        preamble_read_error_kind(&std::io::Error::other("early eof")),
        "early eof"
    );
    assert_eq!(
        preamble_read_error_kind(&std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        "connection reset"
    );
}

fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

#[tokio::test]
async fn start_xray_api_server_skipped_without_api_block() {
    let xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
    let inbound_users = Arc::new(InboundUserManagers::new());
    let stats_registry = Arc::new(StatsRegistry::new());

    let handle = start_xray_api_server("", &xray, inbound_users, stats_registry)
        .await
        .expect("start api server");

    assert!(handle.is_none());
}

#[tokio::test]
async fn start_xray_api_server_spawned_with_api_block() {
    let saved_transport = std::env::var("RUST_XRAY_API_TRANSPORT").ok();
    std::env::set_var("RUST_XRAY_API_TRANSPORT", "plaintext");
    let api_port = pick_free_port();
    let config_json = format!(
        r#"{{
                "api": {{
                    "tag": "api",
                    "listen": "127.0.0.1:{api_port}",
                    "services": ["StatsService"]
                }},
                "inbounds": []
            }}"#
    );
    let xray: XrayConfig = serde_json::from_str(&config_json).expect("parse config");
    let inbound_users = Arc::new(InboundUserManagers::new());
    let stats_registry = Arc::new(StatsRegistry::new());

    let handle = start_xray_api_server(
        "/tmp/rust-xray-test-config.json",
        &xray,
        inbound_users,
        stats_registry,
    )
    .await
    .expect("start api server")
    .expect("api task should be spawned");

    handle.abort();
    let _ = handle.await;
    match saved_transport {
        Some(value) => std::env::set_var("RUST_XRAY_API_TRANSPORT", value),
        None => std::env::remove_var("RUST_XRAY_API_TRANSPORT"),
    }
}
