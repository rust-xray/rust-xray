use super::*;
use crate::config::{PolicyConfig, PolicyLevel, SystemPolicy};
use crate::stats::{user_online, StatsState};

#[test]
fn stats_disabled_without_stats_block() {
    let config: XrayConfig = serde_json::from_str(r#"{"inbounds":[]}"#).unwrap();
    let policy = stats_policy_from_config(&config);
    assert_eq!(policy, StatsPolicy::disabled());
    assert!(!StatsState::from_xray_config(&config, None).enabled());
}

#[test]
fn stats_only_does_not_enable_policy_flags() {
    let config: XrayConfig = serde_json::from_str(r#"{"stats":{},"inbounds":[]}"#).unwrap();
    let policy = stats_policy_from_config(&config);
    assert_eq!(policy, StatsPolicy::manager_default());
    assert!(StatsState::from_xray_config(&config, None).enabled());

    let state = StatsState::from_xray_config(&config, Some("in".to_string()));
    let session = state
        .session(Some("user@example.com".to_string()), Some(0), None)
        .expect("manager exists");
    session.record_relay(10, 20);
    assert_eq!(
        state
            .registry
            .get("user>>>user@example.com>>>traffic>>>uplink", false),
        Err(crate::stats::GetStatError::NotFound)
    );
    assert_eq!(
        state.registry.get("inbound>>>in>>>traffic>>>uplink", false),
        Err(crate::stats::GetStatError::NotFound)
    );
}

#[test]
fn user_stats_require_policy_flags() {
    let config: XrayConfig = serde_json::from_str(
        r#"{
            "stats": {},
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": true,
                        "statsUserDownlink": true,
                        "statsUserOnline": true
                    }
                }
            },
            "inbounds": []
        }"#,
    )
    .unwrap();
    let state = StatsState::from_xray_config(&config, Some("in".to_string()));
    let session = state
        .session(
            Some("user@example.com".to_string()),
            Some(0),
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        )
        .expect("session");
    let _online = session.begin_session().expect("online guard");
    session.record_relay(10, 20);
    assert_eq!(
        state
            .registry
            .get("user>>>user@example.com>>>traffic>>>uplink", false)
            .unwrap(),
        10
    );
    assert_eq!(
        state
            .registry
            .get_online_map(&user_online("user@example.com"))
            .expect("online map")
            .count(),
        1
    );
}

#[test]
fn system_stats_require_policy_flags() {
    let config: XrayConfig = serde_json::from_str(
        r#"{
            "stats": {},
            "policy": {
                "system": {
                    "statsInboundUplink": true,
                    "statsInboundDownlink": false,
                    "statsOutboundUplink": false,
                    "statsOutboundDownlink": true
                }
            },
            "inbounds": []
        }"#,
    )
    .unwrap();
    let state = StatsState::from_xray_config(&config, Some("in".to_string()));
    let session = state
        .session(Some("user@example.com".to_string()), Some(0), None)
        .expect("session");
    session.record_relay(10, 20);
    assert_eq!(
        state.registry.get("inbound>>>in>>>traffic>>>uplink", false),
        Ok(10)
    );
    assert_eq!(
        state
            .registry
            .get("inbound>>>in>>>traffic>>>downlink", false),
        Err(crate::stats::GetStatError::NotFound)
    );
    assert_eq!(
        state
            .registry
            .get("outbound>>>direct>>>traffic>>>uplink", false),
        Err(crate::stats::GetStatError::NotFound)
    );
    assert_eq!(
        state
            .registry
            .get("outbound>>>direct>>>traffic>>>downlink", false),
        Ok(20)
    );
}

#[test]
fn missing_level_policy_disables_user_stats() {
    let config: XrayConfig = serde_json::from_str(
        r#"{
            "stats": {},
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": true
                    }
                }
            },
            "inbounds": []
        }"#,
    )
    .unwrap();
    let state = StatsState::from_xray_config(&config, Some("in".to_string()));
    let session = state
        .session(Some("user@example.com".to_string()), Some(9), None)
        .expect("session");
    session.record_relay(10, 20);
    assert_eq!(
        state
            .registry
            .get("user>>>user@example.com>>>traffic>>>uplink", false),
        Err(crate::stats::GetStatError::NotFound)
    );
}

#[test]
fn policy_without_stats_app_does_not_collect() {
    let config: XrayConfig = serde_json::from_str(
        r#"{
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": true
                    }
                }
            },
            "inbounds": []
        }"#,
    )
    .unwrap();
    assert!(!StatsState::from_xray_config(&config, None).enabled());
}
