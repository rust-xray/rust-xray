use rust_xray::config::{
    first_reality_inbound_runtime, load_xray_config_from_file, validate_xray_panel_config,
    XrayConfig,
};

const REMNA_FIXTURE: &str = include_str!("fixtures/remna/reality_vless_api_config.json");

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
    assert_eq!(api.listen, "127.0.0.1:10085");
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
fn remna_fixture_loads_from_disk_via_loader() {
    let path = std::path::Path::new("tests/fixtures/remna/reality_vless_api_config.json");
    let config = load_xray_config_from_file(path).expect("load remna fixture");
    assert!(config.api.is_some());
    assert!(config.stats.is_some());
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
fn routing_rules_are_rejected_when_non_empty() {
    let mut config = parse_remna_fixture();
    config.routing.as_mut().unwrap().rules.push(
        serde_json::from_value(serde_json::json!({
            "type": "field",
            "outboundTag": "direct"
        }))
        .expect("rule object"),
    );

    let err = validate_xray_panel_config(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("routing.rules"));
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
