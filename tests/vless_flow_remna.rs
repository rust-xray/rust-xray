use rust_xray::config::{first_reality_inbound_runtime, reality_inbound_runtimes, XrayConfig};
use rust_xray::vless::{
    build_vless_clients, format_vless_flow_distribution, vless_flow_distribution, VlessUserManager,
};

const REMNAWAVE_VISION_FIXTURE: &str =
    include_str!("fixtures/remna/remnawave_vless_reality_vision_users.json");
const REMNAWAVE_TWO_PORT_FIXTURE: &str =
    include_str!("fixtures/remna/remnawave_two_reality_inbounds_flow.json");

#[test]
fn remnawave_dual_inbound_fixture_merges_users_and_flows() {
    let config: XrayConfig =
        serde_json::from_str(REMNAWAVE_VISION_FIXTURE).expect("parse remnawave vision fixture");
    let runtime = first_reality_inbound_runtime(&config).expect("runtime");
    assert_eq!(runtime.merged_inbound_tags, vec!["Third mice", "Antirkn"]);
    assert_eq!(runtime.vless_clients.len(), 3);

    let distribution = vless_flow_distribution(&runtime.vless_clients);
    assert_eq!(distribution.get("").copied().unwrap_or(0), 1);
    assert_eq!(
        distribution.get("xtls-rprx-vision").copied().unwrap_or(0),
        2
    );

    let shared = runtime
        .vless_clients
        .iter()
        .find(|client| client.id.ends_with("1102"))
        .expect("shared user");
    assert_eq!(shared.flow.as_deref(), Some("xtls-rprx-vision"));

    let manager = VlessUserManager::new(
        runtime
            .tag
            .clone()
            .unwrap_or_else(|| "reality-in".to_string()),
        build_vless_clients(&runtime.vless_clients).expect("clients"),
    );
    assert_eq!(manager.user_count(), 3);
    assert!(
        format_vless_flow_distribution(&manager.flow_distribution()).contains("xtls-rprx-vision")
    );
}

#[test]
fn remnawave_two_port_fixture_plans_both_listeners() {
    let config: XrayConfig =
        serde_json::from_str(REMNAWAVE_TWO_PORT_FIXTURE).expect("parse two-port fixture");
    let runtimes = reality_inbound_runtimes(&config).expect("runtimes");
    assert_eq!(runtimes.len(), 2);

    let third_mice = runtimes
        .iter()
        .find(|runtime| runtime.tag.as_deref() == Some("Third mice"))
        .expect("Third mice runtime");
    assert_eq!(third_mice.listen_addr, "0.0.0.0:443");
    let third_distribution = vless_flow_distribution(&third_mice.vless_clients);
    assert_eq!(third_distribution.get("").copied().unwrap_or(0), 1);
    assert_eq!(
        third_distribution
            .get("xtls-rprx-vision")
            .copied()
            .unwrap_or(0),
        1
    );

    let antirkn = runtimes
        .iter()
        .find(|runtime| runtime.tag.as_deref() == Some("Antirkn"))
        .expect("Antirkn runtime");
    assert_eq!(antirkn.listen_addr, "0.0.0.0:8444");
    let antirkn_distribution = vless_flow_distribution(&antirkn.vless_clients);
    assert_eq!(
        antirkn_distribution
            .get("xtls-rprx-vision")
            .copied()
            .unwrap_or(0),
        1
    );
}

#[test]
fn remnawave_missing_client_flow_inferred_from_raw_reality() {
    let json = r#"{
        "inbounds": [{
            "tag": "vision-in",
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id": "11111111-1111-1111-1111-111111111102",
                    "email": "user@example.test"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "dest": "www.microsoft.com:443",
                    "serverNames": ["example.com"],
                    "privateKey": "MKVGVTTvyEyI7hpl7vP7WKtRXLhH0JieCMHgFdn6A3s",
                    "shortIds": ["0123456789abcdef"]
                }
            }
        }]
    }"#;
    let config: XrayConfig = serde_json::from_str(json).expect("parse config");
    let runtime = first_reality_inbound_runtime(&config).expect("runtime");
    assert_eq!(
        runtime.vless_clients[0].flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}
