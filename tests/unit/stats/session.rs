use super::*;
use crate::config::{PolicyConfig, PolicyLevel, SystemPolicy};
use crate::stats::user_online;

#[test]
fn policy_flags_disable_user_counters() {
    let registry = Arc::new(StatsRegistry::new());
    let mut levels = std::collections::BTreeMap::new();
    levels.insert(
        "0".to_string(),
        PolicyLevel {
            stats_user_uplink: false,
            stats_user_downlink: true,
            stats_user_online: false,
            handshake: None,
            extra: Default::default(),
        },
    );
    let policy_config = PolicyConfig {
        levels,
        system: Some(SystemPolicy {
            stats_inbound_uplink: true,
            stats_inbound_downlink: true,
            stats_outbound_uplink: false,
            stats_outbound_downlink: false,
            extra: Default::default(),
        }),
        extra: Default::default(),
    };
    let base = StatsPolicy {
        user_uplink: true,
        user_downlink: true,
        user_online: false,
        inbound_uplink: true,
        inbound_downlink: true,
        outbound_uplink: false,
        outbound_downlink: false,
    };
    let session = StatsSession::new(
        Arc::clone(&registry),
        base,
        Some(&policy_config),
        "in".to_string(),
        "direct".to_string(),
        Some("user@example.com".to_string()),
        Some(0),
        None,
    );
    session.record_relay(100, 200);
    assert_eq!(
        registry
            .get("user>>>user@example.com>>>traffic>>>uplink", false)
            .unwrap_err(),
        crate::stats::registry::GetStatError::NotFound
    );
    assert_eq!(
        registry
            .get("user>>>user@example.com>>>traffic>>>downlink", false)
            .unwrap(),
        200
    );
    assert_eq!(
        registry
            .get("inbound>>>in>>>traffic>>>uplink", false)
            .unwrap(),
        100
    );
    assert_eq!(
        registry
            .get("outbound>>>direct>>>traffic>>>uplink", false)
            .unwrap_err(),
        crate::stats::registry::GetStatError::NotFound
    );
}

#[test]
fn online_tracking_respects_policy_and_source_ip() {
    use std::net::{IpAddr, Ipv4Addr};

    let registry = Arc::new(StatsRegistry::new());
    let mut levels = std::collections::BTreeMap::new();
    levels.insert(
        "0".to_string(),
        PolicyLevel {
            stats_user_uplink: false,
            stats_user_downlink: false,
            stats_user_online: true,
            handshake: None,
            extra: Default::default(),
        },
    );
    let policy_config = PolicyConfig {
        levels,
        system: None,
        extra: Default::default(),
    };
    let base = StatsPolicy {
        user_uplink: true,
        user_downlink: true,
        user_online: true,
        inbound_uplink: false,
        inbound_downlink: false,
        outbound_uplink: false,
        outbound_downlink: false,
    };
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let session = StatsSession::new(
        Arc::clone(&registry),
        base,
        Some(&policy_config),
        "in".to_string(),
        "direct".to_string(),
        Some("user@example.com".to_string()),
        Some(0),
        Some(ip),
    );
    let guard = session.begin_session().expect("online guard");
    assert_eq!(
        registry
            .get_online_map(&user_online("user@example.com"))
            .expect("map")
            .count(),
        1
    );
    drop(guard);
    assert_eq!(
        registry
            .get_online_map(&user_online("user@example.com"))
            .expect("map")
            .count(),
        0
    );
}

#[test]
fn online_tracking_disabled_without_policy_opt_in() {
    use std::net::{IpAddr, Ipv4Addr};

    let registry = Arc::new(StatsRegistry::new());
    let mut levels = std::collections::BTreeMap::new();
    levels.insert(
        "0".to_string(),
        PolicyLevel {
            stats_user_uplink: false,
            stats_user_downlink: false,
            stats_user_online: false,
            handshake: None,
            extra: Default::default(),
        },
    );
    let policy_config = PolicyConfig {
        levels,
        system: None,
        extra: Default::default(),
    };
    let session = StatsSession::new(
        Arc::clone(&registry),
        StatsPolicy {
            user_uplink: true,
            user_downlink: true,
            user_online: true,
            inbound_uplink: false,
            inbound_downlink: false,
            outbound_uplink: false,
            outbound_downlink: false,
        },
        Some(&policy_config),
        "in".to_string(),
        "direct".to_string(),
        Some("user@example.com".to_string()),
        Some(0),
        Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
    );
    assert!(session.begin_session().is_none());
    assert!(registry
        .get_online_map(&user_online("user@example.com"))
        .is_none());
}
