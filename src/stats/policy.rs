use crate::config::{PolicyConfig, PolicyLevel, XrayConfig};

/// Effective stats collection flags (from `stats` + `policy` blocks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsPolicy {
    pub user_uplink: bool,
    pub user_downlink: bool,
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
            inbound_uplink: false,
            inbound_downlink: false,
            outbound_uplink: false,
            outbound_downlink: false,
        }
    }

    /// Remna-style default when `stats: {}` is present but `policy` is absent.
    pub const fn all_enabled() -> Self {
        Self {
            user_uplink: true,
            user_downlink: true,
            inbound_uplink: true,
            inbound_downlink: true,
            outbound_uplink: true,
            outbound_downlink: true,
        }
    }

    pub fn for_user_level(&self, level: &PolicyLevel) -> Self {
        Self {
            user_uplink: self.user_uplink && level.stats_user_uplink,
            user_downlink: self.user_downlink && level.stats_user_downlink,
            inbound_uplink: self.inbound_uplink,
            inbound_downlink: self.inbound_downlink,
            outbound_uplink: self.outbound_uplink,
            outbound_downlink: self.outbound_downlink,
        }
    }
}

fn policy_level<'a>(policy: &'a PolicyConfig, level: Option<u32>) -> Option<&'a PolicyLevel> {
    if let Some(level) = level {
        policy.levels.get(&level.to_string())
    } else {
        None
    }
    .or_else(|| policy.levels.get("0"))
    .or_else(|| policy.levels.values().next())
}

/// Build stats policy from top-level Xray config.
///
/// When `stats` is absent, all collection is disabled. When `stats: {}` is present without
/// `policy`, all counters are enabled (Remna panel compatibility). When `policy` is present,
/// `policy.system` gates inbound/outbound counters and `policy.levels.*` gates user counters.
pub fn stats_policy_from_config(config: &XrayConfig) -> StatsPolicy {
    if config.stats.is_none() {
        return StatsPolicy::disabled();
    }

    let Some(policy) = config.policy.as_ref() else {
        return StatsPolicy::all_enabled();
    };

    let system = policy.system.as_ref();
    StatsPolicy {
        user_uplink: true,
        user_downlink: true,
        inbound_uplink: system.map(|s| s.stats_inbound_uplink).unwrap_or(true),
        inbound_downlink: system.map(|s| s.stats_inbound_downlink).unwrap_or(true),
        outbound_uplink: system.map(|s| s.stats_outbound_uplink).unwrap_or(true),
        outbound_downlink: system.map(|s| s.stats_outbound_downlink).unwrap_or(true),
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
