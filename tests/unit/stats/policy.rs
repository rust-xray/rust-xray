
use super::*;

#[test]
fn stats_disabled_without_stats_block() {
    let config: XrayConfig = serde_json::from_str(r#"{"inbounds":[]}"#).unwrap();
    let policy = stats_policy_from_config(&config);
    assert_eq!(policy, StatsPolicy::disabled());
}

#[test]
fn stats_enabled_when_empty_stats_object() {
    let config: XrayConfig = serde_json::from_str(r#"{"stats":{},"inbounds":[]}"#).unwrap();
    let policy = stats_policy_from_config(&config);
    assert_eq!(policy, StatsPolicy::all_enabled());
}
