use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::PolicyConfig;
use crate::stats::names::{
    inbound_traffic_downlink, inbound_traffic_uplink, outbound_traffic_downlink,
    outbound_traffic_uplink, user_online, user_traffic_downlink, user_traffic_uplink,
};
use crate::stats::online_map::OnlineMap;
use crate::stats::policy::{user_policy_for_level, StatsPolicy};
use crate::stats::registry::StatsRegistry;

fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn canonical_ip_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(_v6) if ip.is_loopback() => "[::1]".to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    }
}

/// RAII guard that decrements online IP reference count on drop.
#[derive(Debug)]
pub struct OnlineSessionGuard {
    map: Arc<OnlineMap>,
    ip: String,
}

impl Drop for OnlineSessionGuard {
    fn drop(&mut self) {
        self.map.remove_ip(&self.ip);
    }
}

/// Active stats context for one authenticated VLESS connection.
#[derive(Debug)]
pub struct StatsConnection {
    session: StatsSession,
    _online: Option<OnlineSessionGuard>,
}

impl StatsConnection {
    pub fn open(session: StatsSession) -> Self {
        let _online = session.begin_session();
        Self { session, _online }
    }

    pub fn session(&self) -> &StatsSession {
        &self.session
    }
}

impl std::ops::Deref for StatsConnection {
    type Target = StatsSession;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

/// Per-connection stats context (inbound tag, optional user email/level, source IP).
#[derive(Debug, Clone)]
pub struct StatsSession {
    registry: Arc<StatsRegistry>,
    policy: StatsPolicy,
    inbound_tag: String,
    outbound_tag: String,
    user_email: Option<String>,
    source_ip: Option<IpAddr>,
}

impl StatsSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Arc<StatsRegistry>,
        base_policy: StatsPolicy,
        policy_config: Option<&PolicyConfig>,
        inbound_tag: String,
        outbound_tag: String,
        user_email: Option<String>,
        user_level: Option<u32>,
        source_ip: Option<IpAddr>,
    ) -> Self {
        let policy = user_policy_for_level(base_policy, policy_config, user_level);
        Self {
            registry,
            policy,
            inbound_tag,
            outbound_tag,
            user_email,
            source_ip,
        }
    }

    /// Register counters and begin online IP tracking after successful VLESS auth.
    pub fn begin_session(&self) -> Option<OnlineSessionGuard> {
        self.ensure_registered();
        self.begin_online_tracking()
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

    /// Track the authenticated user as online for the connection lifetime.
    pub fn begin_online_tracking(&self) -> Option<OnlineSessionGuard> {
        if !self.policy.user_online {
            return None;
        }
        let email = self.user_email.as_deref()?.trim();
        if email.is_empty() {
            return None;
        }
        let ip = self.source_ip?;
        let ip_string = canonical_ip_string(ip);
        let map = self
            .registry
            .get_or_register_online_map(&user_online(email));
        map.add_ip(&ip_string, current_unix_secs());
        Some(OnlineSessionGuard { map, ip: ip_string })
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
#[path = "../../tests/unit/stats/session.rs"]
mod tests;
