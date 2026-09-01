use std::collections::BTreeMap;
use std::time::Duration;

use crate::config::xray::raw::{PolicyConfig, PolicyLevel};
use crate::config::XrayConfig;
use crate::vless::policy::VlessInboundPolicy;

#[test]
fn default_handshake_timeout_is_four_seconds() {
    assert_eq!(
        VlessInboundPolicy::default().handshake_timeout,
        Duration::from_secs(4)
    );
}

#[test]
fn policy_level_zero_handshake_override() {
    let mut levels = BTreeMap::new();
    levels.insert(
        "0".to_string(),
        PolicyLevel {
            handshake: Some(8),
            ..Default::default()
        },
    );
    let policy = PolicyConfig {
        levels,
        ..Default::default()
    };
    assert_eq!(
        VlessInboundPolicy::from_policy_config_level_zero(&policy).handshake_timeout,
        Duration::from_secs(8)
    );
}

#[test]
fn missing_policy_uses_default() {
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
        inbounds: Vec::new(),
        extra: BTreeMap::new(),
    };
    assert_eq!(
        VlessInboundPolicy::from_xray_config(&config).handshake_timeout,
        Duration::from_secs(4)
    );
}
