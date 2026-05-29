use std::sync::Arc;

use crate::config::PolicyConfig;
use crate::stats::names::{
    inbound_traffic_downlink, inbound_traffic_uplink, outbound_traffic_downlink,
    outbound_traffic_uplink, user_traffic_downlink, user_traffic_uplink,
};
use crate::stats::policy::{user_policy_for_level, StatsPolicy};
use crate::stats::registry::StatsRegistry;

/// Per-connection stats context (inbound tag, optional user email/level).
#[derive(Debug, Clone)]
pub struct StatsSession {
    registry: Arc<StatsRegistry>,
    policy: StatsPolicy,
    inbound_tag: String,
    outbound_tag: String,
    user_email: Option<String>,
}

impl StatsSession {
    pub fn new(
        registry: Arc<StatsRegistry>,
        base_policy: StatsPolicy,
        policy_config: Option<&PolicyConfig>,
        inbound_tag: String,
        outbound_tag: String,
        user_email: Option<String>,
        user_level: Option<u32>,
    ) -> Self {
        let policy = user_policy_for_level(base_policy, policy_config, user_level);
        Self {
            registry,
            policy,
            inbound_tag,
            outbound_tag,
            user_email,
        }
    }

    pub fn record_uplink(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if self.policy.inbound_uplink {
            self.registry
                .add(&inbound_traffic_uplink(&self.inbound_tag), bytes);
        }
        if self.policy.outbound_uplink {
            self.registry
                .add(&outbound_traffic_uplink(&self.outbound_tag), bytes);
        }
        if let Some(email) = self.user_email.as_deref() {
            if self.policy.user_uplink {
                self.registry.add(&user_traffic_uplink(email), bytes);
            }
        }
    }

    /// Register Xray-compatible counter names after successful VLESS auth (value stays 0 until traffic).
    pub fn ensure_registered(&self) {
        if self.policy.inbound_uplink {
            self.registry
                .ensure(&inbound_traffic_uplink(&self.inbound_tag));
        }
        if self.policy.inbound_downlink {
            self.registry
                .ensure(&inbound_traffic_downlink(&self.inbound_tag));
        }
        if self.policy.outbound_uplink {
            self.registry
                .ensure(&outbound_traffic_uplink(&self.outbound_tag));
        }
        if self.policy.outbound_downlink {
            self.registry
                .ensure(&outbound_traffic_downlink(&self.outbound_tag));
        }
        if let Some(email) = self.user_email.as_deref() {
            if self.policy.user_uplink {
                self.registry.ensure(&user_traffic_uplink(email));
            }
            if self.policy.user_downlink {
                self.registry.ensure(&user_traffic_downlink(email));
            }
        }
    }

    pub fn record_downlink(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if self.policy.inbound_downlink {
            self.registry
                .add(&inbound_traffic_downlink(&self.inbound_tag), bytes);
        }
        if self.policy.outbound_downlink {
            self.registry
                .add(&outbound_traffic_downlink(&self.outbound_tag), bytes);
        }
        if let Some(email) = self.user_email.as_deref() {
            if self.policy.user_downlink {
                self.registry.add(&user_traffic_downlink(email), bytes);
            }
        }
    }

    /// Record a bidirectional relay result (`copy_bidirectional` tuple).
    pub fn record_relay(&self, client_to_dest: u64, dest_to_client: u64) {
        self.record_uplink(client_to_dest);
        self.record_downlink(dest_to_client);
    }
}

#[cfg(test)]
mod tests {
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
}
