use super::*;
use crate::config::{PolicyConfig, PolicyLevel, SystemPolicy};

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
