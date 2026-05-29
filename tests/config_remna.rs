use rust_xray::config::{
    api_listen_addr, first_reality_inbound_runtime, load_xray_config_from_file,
    load_xray_config_from_source, parse_http_unix_config_uri, redact_config_source,
    resolve_api_listen, validate_xray_panel_config, ApiListenSource, XrayConfig,
};

const REMNA_FIXTURE: &str = include_str!("fixtures/remna/reality_vless_api_config.json");

const REMNA_API_61000_FIXTURE: &str =
    include_str!("fixtures/remna/reality_vless_api_61000_config.json");

const REMNAWAVE_NODE_MINIMAL_61000: &str =
    include_str!("fixtures/remna/remnawave_node_minimal_61000.json");

const REMNA_GENERATED_FIXTURE: &str =
    include_str!("fixtures/remna/remna-generated-reality-vless-api.json");

const SMOKE_FIXTURE: &str =
    include_str!("../scripts/live_reality_smoke/rust-xray-server.raw.fixture.json");

const XRAY_COMPAT_FIXTURE: &str =
    include_str!("../scripts/live_reality_smoke/xray-compatible-server.fixture.json");

fn parse_remna_fixture() -> XrayConfig {
    serde_json::from_str(REMNA_FIXTURE).expect("parse remna fixture")
}

#[test]
fn remna_fixture_parses_and_validates() {
    let config = parse_remna_fixture();
    validate_xray_panel_config(&config).expect("panel validation");

    let api = config.api.as_ref().expect("api block");
    assert_eq!(api.tag, "api");
    assert_eq!(api.listen.as_deref(), Some("127.0.0.1:10085"));
    assert_eq!(
        api_listen_addr(&config).expect("api listen"),
        Some("127.0.0.1:10085".to_string())
    );
    assert_eq!(
        api.services,
        vec!["HandlerService".to_string(), "StatsService".to_string()]
    );

    assert!(config.stats.is_some());
    let policy = config.policy.as_ref().expect("policy block");
    let level0 = policy.levels.get("0").expect("policy level 0");
    assert!(level0.stats_user_uplink);
    assert!(level0.stats_user_downlink);
    assert!(level0.stats_user_online);
    let system = policy.system.as_ref().expect("policy system");
    assert!(system.stats_inbound_uplink);
    assert!(system.stats_inbound_downlink);
    assert!(system.stats_outbound_uplink);
    assert!(system.stats_outbound_downlink);

    let routing = config.routing.as_ref().expect("routing block");
    assert_eq!(routing.domain_strategy.as_deref(), Some("AsIs"));
    assert!(routing.rules.is_empty());

    let runtime = first_reality_inbound_runtime(&config).expect("reality runtime");
    let client = &runtime.vless_clients[0];
    assert_eq!(client.id, "11111111-1111-1111-1111-111111111111");
    assert_eq!(client.email.as_deref(), Some("remna-user@example.test"));
    assert_eq!(client.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(client.level, Some(0));
}

#[test]
fn remna_xray_style_api_listen_resolves_from_tagged_inbound() {
    let mut value: serde_json::Value = serde_json::from_str(REMNA_FIXTURE).expect("parse fixture");
    value
        .get_mut("api")
        .and_then(|api| api.as_object_mut())
        .expect("api object")
        .remove("listen");
    value
        .get_mut("inbounds")
        .and_then(|inbounds| inbounds.as_array_mut())
        .expect("inbounds array")
        .insert(
            0,
            serde_json::json!({
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 61000,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                }
            }),
        );

    let config: XrayConfig = serde_json::from_value(value).expect("parse xray-style api config");
    validate_xray_panel_config(&config).expect("panel validation");
    assert_eq!(
        api_listen_addr(&config).expect("api listen"),
        Some("127.0.0.1:61000".to_string())
    );
    first_reality_inbound_runtime(&config).expect("reality runtime");
}

#[test]
fn remnawave_api_listen_resolves_from_routing_rule_to_api_tag() {
    let mut value: serde_json::Value = serde_json::from_str(REMNA_FIXTURE).expect("parse fixture");
    let api = value
        .get_mut("api")
        .and_then(|api| api.as_object_mut())
        .expect("api object");
    api.remove("listen");
    api.insert(
        "tag".to_string(),
        serde_json::Value::String("REMNAWAVE_API".to_string()),
    );
    value
        .get_mut("inbounds")
        .and_then(|inbounds| inbounds.as_array_mut())
        .expect("inbounds array")
        .insert(
            0,
            serde_json::json!({
                "tag": "REMNAWAVE_API_IN",
                "listen": "127.0.0.1",
                "port": 61000,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                }
            }),
        );
    *value.get_mut("routing").expect("routing") = serde_json::json!({
        "domainStrategy": "AsIs",
        "rules": [{
            "type": "field",
            "inboundTag": ["REMNAWAVE_API_IN"],
            "outboundTag": "REMNAWAVE_API"
        }]
    });

    let config: XrayConfig =
        serde_json::from_value(value).expect("parse remnawave-style api config");
    validate_xray_panel_config(&config).expect("panel validation");
    assert_eq!(
        api_listen_addr(&config).expect("api listen"),
        Some("127.0.0.1:61000".to_string())
    );
    first_reality_inbound_runtime(&config).expect("reality runtime");
}

#[test]
fn remna_generated_smoke_fixture_parses_and_validates() {
    let config: XrayConfig =
        serde_json::from_str(REMNA_GENERATED_FIXTURE).expect("parse generated");
    validate_xray_panel_config(&config).expect("panel validation");
    let api = config.api.as_ref().expect("api");
    assert!(api
        .services
        .iter()
        .any(|service| service.eq_ignore_ascii_case("ReflectionService")));
    first_reality_inbound_runtime(&config).expect("reality runtime");
}

#[test]
fn remnawave_node_minimal_fixture_resolves_api_61000_via_routing() {
    let config: XrayConfig =
        serde_json::from_str(REMNAWAVE_NODE_MINIMAL_61000).expect("parse minimal");
    validate_xray_panel_config(&config).expect("panel validation");
    let (listen, source, tag) = resolve_api_listen(&config)
        .expect("resolve")
        .expect("listen");
    assert_eq!(listen, "127.0.0.1:61000");
    assert_eq!(source, ApiListenSource::RoutingRule);
    assert_eq!(tag.as_deref(), Some("api-inbound"));
    first_reality_inbound_runtime(&config).expect("reality runtime");
}

#[test]
fn remna_api_61000_fixture_parses_listen_and_services() {
    let config: XrayConfig =
        serde_json::from_str(REMNA_API_61000_FIXTURE).expect("parse 61000 fixture");
    validate_xray_panel_config(&config).expect("panel validation");
    let api = config.api.as_ref().expect("api block");
    assert_eq!(api.listen.as_deref(), Some("127.0.0.1:61000"));
    assert_eq!(
        api_listen_addr(&config).expect("api listen"),
        Some("127.0.0.1:61000".to_string())
    );
    assert_eq!(
        api.services,
        vec![
            "HandlerService".to_string(),
            "StatsService".to_string(),
            "ReflectionService".to_string(),
        ]
    );
    first_reality_inbound_runtime(&config).expect("reality runtime");
}

#[test]
fn remna_api_61000_fixture_loads_from_disk() {
    let path = std::path::Path::new("tests/fixtures/remna/reality_vless_api_61000_config.json");
    let config = load_xray_config_from_file(path).expect("load 61000 fixture");
    assert_eq!(
        api_listen_addr(&config).expect("api listen"),
        Some("127.0.0.1:61000".to_string())
    );
}

#[test]
fn remna_fixture_loads_from_disk_via_loader() {
    let path = std::path::Path::new("tests/fixtures/remna/reality_vless_api_config.json");
    let config = load_xray_config_from_file(path).expect("load remna fixture");
    assert!(config.api.is_some());
    assert!(config.stats.is_some());
}

#[tokio::test]
async fn remnawave_http_unix_config_source_fetches_json_and_redacts_token() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("remnawave-internal.sock");
    let listener = UnixListener::bind(&socket).expect("bind unix listener");
    let fixture = REMNA_FIXTURE.to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept unix");
        let mut request = vec![0_u8; 4096];
        let n = stream.read(&mut request).await.expect("read request");
        let request = String::from_utf8_lossy(&request[..n]);
        assert!(request.starts_with("GET /internal/get-config?token=secret-token HTTP/1.1"));
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            fixture.len(),
            fixture
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
    });

    let source = format!(
        "http+unix://{}/internal/get-config?token=secret-token",
        socket.display()
    );
    let redacted = redact_config_source(&source);
    assert!(!redacted.contains("secret-token"));
    assert!(redacted.ends_with("?<redacted>"));

    let config = load_xray_config_from_source(&source)
        .await
        .expect("load http+unix config");
    assert_eq!(
        api_listen_addr(&config).expect("api listen"),
        Some("127.0.0.1:10085".to_string())
    );
}

#[test]
fn smoke_and_xray_compatible_fixtures_still_parse() {
    for (name, json) in [
        ("smoke", SMOKE_FIXTURE),
        ("xray-compatible", XRAY_COMPAT_FIXTURE),
    ] {
        let config: XrayConfig =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("parse {name} fixture: {e}"));
        validate_xray_panel_config(&config)
            .unwrap_or_else(|e| panic!("validate {name} fixture: {e}"));
        first_reality_inbound_runtime(&config)
            .unwrap_or_else(|e| panic!("runtime {name} fixture: {e}"));
    }
}

#[test]
fn routing_rules_are_accepted_as_parsed_only_compatibility() {
    let mut config = parse_remna_fixture();
    config.routing.as_mut().unwrap().rules.push(
        serde_json::from_value(serde_json::json!({
            "type": "field",
            "outboundTag": "direct"
        }))
        .expect("rule object"),
    );

    validate_xray_panel_config(&config).expect("routing rules are parsed-only compatibility");
}

#[test]
fn api_listen_without_port_is_rejected_at_validation() {
    let mut config = parse_remna_fixture();
    config.api.as_mut().expect("api").listen = Some("127.0.0.1".to_string());
    let err = validate_xray_panel_config(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("host:port"));
}

#[test]
fn remna_api_topology_with_observatory_service_validates() {
    let mut value: serde_json::Value = serde_json::from_str(REMNA_FIXTURE).expect("parse fixture");
    value
        .get_mut("api")
        .and_then(|api| api.as_object_mut())
        .expect("api object")
        .remove("listen");
    value
        .get_mut("api")
        .and_then(|api| api.get_mut("services"))
        .and_then(|services| services.as_array_mut())
        .expect("services")
        .push(serde_json::Value::String("ObservatoryService".to_string()));
    value
        .get_mut("inbounds")
        .and_then(|inbounds| inbounds.as_array_mut())
        .expect("inbounds")
        .insert(
            0,
            serde_json::json!({
                "tag": "api-inbound",
                "listen": "127.0.0.1",
                "port": 61000,
                "protocol": "dokodemo-door",
                "settings": { "address": "127.0.0.1" }
            }),
        );
    *value.get_mut("routing").expect("routing") = serde_json::json!({
        "domainStrategy": "AsIs",
        "rules": [{
            "type": "field",
            "inboundTag": ["api-inbound"],
            "outboundTag": "api"
        }]
    });

    let config: XrayConfig = serde_json::from_value(value).expect("parse");
    validate_xray_panel_config(&config).expect("panel validation");
    let (listen, source, tag) = resolve_api_listen(&config)
        .expect("resolve")
        .expect("listen");
    assert_eq!(listen, "127.0.0.1:61000");
    assert_eq!(source, ApiListenSource::RoutingRule);
    assert_eq!(tag.as_deref(), Some("api-inbound"));
}

#[test]
fn ambiguous_api_routing_returns_explicit_error() {
    let mut value: serde_json::Value = serde_json::from_str(REMNA_FIXTURE).expect("parse fixture");
    value
        .get_mut("api")
        .and_then(|api| api.as_object_mut())
        .expect("api")
        .remove("listen");
    value
        .get_mut("inbounds")
        .and_then(|inbounds| inbounds.as_array_mut())
        .expect("inbounds")
        .extend([
            serde_json::json!({
                "tag": "api-a",
                "listen": "127.0.0.1",
                "port": 61000,
                "protocol": "dokodemo-door",
                "settings": { "address": "127.0.0.1" }
            }),
            serde_json::json!({
                "tag": "api-b",
                "listen": "127.0.0.1",
                "port": 61001,
                "protocol": "dokodemo-door",
                "settings": { "address": "127.0.0.1" }
            }),
        ]);
    *value.get_mut("routing").expect("routing") = serde_json::json!({
        "rules": [
            { "inboundTag": ["api-a"], "outboundTag": "api" },
            { "inboundTag": ["api-b"], "outboundTag": "api" }
        ]
    });

    let config: XrayConfig = serde_json::from_value(value).expect("parse");
    let err = resolve_api_listen(&config).unwrap_err();
    assert!(err.to_string().contains("ambiguous"));
}

#[tokio::test]
async fn http_unix_loader_rejects_non_200() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("test.sock");
    let listener = UnixListener::bind(&socket).expect("bind");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = vec![0_u8; 4096];
        let n = stream.read(&mut request).await.expect("read");
        assert!(String::from_utf8_lossy(&request[..n]).contains("GET /cfg"));
        let body = "{}";
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await.expect("write");
    });

    let source = format!("http+unix://{}/cfg", socket.display());
    let err = load_xray_config_from_source(&source).await.unwrap_err();
    assert!(err.to_string().contains("403") || err.to_string().contains("Forbidden"));
    assert!(!err.to_string().contains("secret"));
}

#[test]
fn api_listen_direct_field_wins_over_routing() {
    let config = parse_remna_fixture();
    let (listen, source, _) = resolve_api_listen(&config)
        .expect("resolve")
        .expect("listen");
    assert_eq!(listen, "127.0.0.1:10085");
    assert_eq!(source, ApiListenSource::ApiListenField);
}

#[test]
fn unknown_api_service_is_explicit_error() {
    let mut config = parse_remna_fixture();
    config
        .api
        .as_mut()
        .unwrap()
        .services
        .push("ExampleService".to_string());

    let err = validate_xray_panel_config(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("api.services"));
}
