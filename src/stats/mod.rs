mod names;
mod online_map;
mod policy;
mod registry;
mod session;

pub use names::{
    inbound_traffic_downlink, inbound_traffic_uplink, outbound_traffic_downlink,
    outbound_traffic_uplink, parse_user_online_email, user_online, user_traffic_downlink,
    user_traffic_uplink,
};
pub use online_map::OnlineMap;
pub use policy::{default_outbound_tag, stats_policy_from_config, StatsPolicy};
pub use registry::{GetStatError, StatEntry, StatsRegistry};
pub use session::{OnlineSessionGuard, StatsConnection, StatsSession};

use std::sync::Arc;

use crate::config::{PolicyConfig, XrayConfig};

/// Shared stats state wired into relay paths and the gRPC API.
#[derive(Debug, Clone)]
pub struct StatsState {
    pub registry: Arc<StatsRegistry>,
    pub base_policy: StatsPolicy,
    pub policy_config: Option<Arc<PolicyConfig>>,
    pub inbound_tag: String,
    pub outbound_tag: String,
    manager_enabled: bool,
}

impl StatsState {
    pub fn from_xray_config(config: &XrayConfig, inbound_tag: Option<String>) -> Self {
        let inbound_tag = inbound_tag
            .filter(|tag| !tag.is_empty())
            .unwrap_or_else(|| "reality-in".to_string());
        Self {
            registry: Arc::new(StatsRegistry::new()),
            base_policy: stats_policy_from_config(config),
            policy_config: config.policy.clone().map(Arc::new),
            inbound_tag,
            outbound_tag: default_outbound_tag(config),
            manager_enabled: config.stats.is_some(),
        }
    }

    pub fn from_xray_config_with_registry(
        config: &XrayConfig,
        registry: Arc<StatsRegistry>,
        inbound_tag: String,
    ) -> Self {
        Self {
            registry,
            base_policy: stats_policy_from_config(config),
            policy_config: config.policy.clone().map(Arc::new),
            inbound_tag,
            outbound_tag: default_outbound_tag(config),
            manager_enabled: config.stats.is_some(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.manager_enabled
    }

    pub fn session(
        &self,
        user_email: Option<String>,
        user_level: Option<u32>,
        source_ip: Option<std::net::IpAddr>,
    ) -> Option<StatsSession> {
        if !self.enabled() {
            return None;
        }
        Some(StatsSession::new(
            Arc::clone(&self.registry),
            self.base_policy,
            self.policy_config.as_deref(),
            self.inbound_tag.clone(),
            self.outbound_tag.clone(),
            user_email,
            user_level,
            source_ip,
        ))
    }
}
