use crate::config::{PolicyConfig, PolicyLevel, XrayConfig};

/// Effective stats collection flags (from `stats` + `policy` blocks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsPolicy {
    pub user_uplink: bool,
    pub user_downlink: bool,
    pub user_online: bool,
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    pub outbound_uplink: bool,
    pub outbound_downlink: bool,
}

impl StatsPolicy {
    pub const fn disabled() -> Self {
        Self {
            user_uplink: false,
            user_downlink: false,
            user_online: false,
            inbound_uplink: false,
            inbound_downlink: false,
            outbound_uplink: false,
            outbound_downlink: false,
        }
    }

    /// Stats manager present with no policy flags enabled (Xray default when `stats: {}` alone).
    pub const fn manager_default() -> Self {
        Self::disabled()
    }

    pub fn for_user_level(&self, level: &PolicyLevel) -> Self {
        Self {
            user_uplink: level.stats_user_uplink,
            user_downlink: level.stats_user_downlink,
            user_online: level.stats_user_online,
            inbound_uplink: self.inbound_uplink,
            inbound_downlink: self.inbound_downlink,
            outbound_uplink: self.outbound_uplink,
            outbound_downlink: self.outbound_downlink,
        }
    }
}

fn policy_level(policy: &PolicyConfig, level: Option<u32>) -> Option<&PolicyLevel> {
    policy.levels.get(&level.unwrap_or(0).to_string())
}

/// Build stats policy from top-level Xray config.
///
/// When `stats` is absent, the stats manager is disabled. When `stats: {}` is present, the manager
/// exists but all collection flags default to false until enabled by `policy`. System counters
/// follow `policy.system`; user counters follow `policy.levels.<level>`.
pub fn stats_policy_from_config(config: &XrayConfig) -> StatsPolicy {
    if config.stats.is_none() {
        return StatsPolicy::disabled();
    }

    let Some(policy) = config.policy.as_ref() else {
        return StatsPolicy::manager_default();
    };

    let system = policy.system.as_ref();
    StatsPolicy {
        user_uplink: false,
        user_downlink: false,
        user_online: false,
        inbound_uplink: system.map(|s| s.stats_inbound_uplink).unwrap_or(false),
        inbound_downlink: system.map(|s| s.stats_inbound_downlink).unwrap_or(false),
        outbound_uplink: system.map(|s| s.stats_outbound_uplink).unwrap_or(false),
        outbound_downlink: system.map(|s| s.stats_outbound_downlink).unwrap_or(false),
    }
}

pub fn user_policy_for_level(
    base: StatsPolicy,
    policy: Option<&PolicyConfig>,
    level: Option<u32>,
) -> StatsPolicy {
    let Some(policy) = policy else {
        return base;
    };
    let Some(level) = policy_level(policy, level) else {
        return StatsPolicy {
            user_uplink: false,
            user_downlink: false,
            user_online: false,
            ..base
        };
    };
    base.for_user_level(level)
}

pub fn default_outbound_tag(config: &XrayConfig) -> String {
    config
        .outbounds
        .iter()
        .find(|outbound| {
            outbound
                .protocol
                .as_deref()
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case("freedom"))
        })
        .and_then(|outbound| outbound.tag.clone())
        .unwrap_or_else(|| "direct".to_string())
}

#[cfg(test)]
#[path = "../../tests/unit/stats/policy.rs"]
mod tests;
