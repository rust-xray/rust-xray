use std::sync::{Arc, OnceLock};

use crate::config::XrayConfig;
use crate::dns::routing::DnsRouter;
use crate::dns::{DnsEngine, DnsError};

use super::domain_strategy::OutboundDomainStrategy;

/// Process-wide outbound connect context (DNS engine + domain strategy).
#[derive(Clone)]
pub struct OutboundConnectRuntime {
    pub dns: Arc<DnsEngine>,
    pub domain_strategy: OutboundDomainStrategy,
    pub routing: Option<RoutingDnsRuntime>,
}

/// Routing + DNS resolution skeleton for future rule-driven outbound dials.
#[derive(Clone)]
pub struct RoutingDnsRuntime {
    pub router: DnsRouter,
    pub domain_strategy: OutboundDomainStrategy,
    pub dns: Arc<DnsEngine>,
}

impl RoutingDnsRuntime {
    /// Resolve `domain` when routing policy requires IP lookup (not `AsIs`).
    pub async fn resolve_domain_if_needed(
        &self,
        domain: &str,
    ) -> Result<Option<Vec<std::net::IpAddr>>, DnsError> {
        if !self.domain_strategy.uses_dns_engine() {
            return Ok(None);
        }
        let ips = self
            .dns
            .lookup_ip(domain, self.domain_strategy.to_query_strategy())
            .await?;
        Ok(Some(ips))
    }
}

impl OutboundConnectRuntime {
    pub fn from_xray(xray: &XrayConfig) -> Self {
        let domain_strategy = OutboundDomainStrategy::from_config(
            xray.routing
                .as_ref()
                .and_then(|routing| routing.domain_strategy.as_deref()),
            xray.dns.as_ref().map(|dns| dns.query_strategy),
        );
        let routing = xray.routing.as_ref().map(|routing| RoutingDnsRuntime {
            router: DnsRouter::new(Some(routing.clone()), xray.outbounds.clone()),
            domain_strategy,
            dns: DnsEngine::shared(),
        });
        Self {
            dns: DnsEngine::shared(),
            domain_strategy,
            routing,
        }
    }

    pub fn init_shared(xray: &XrayConfig) {
        static SHARED: OnceLock<Arc<OutboundConnectRuntime>> = OnceLock::new();
        let _ = SHARED.get_or_init(|| Arc::new(Self::from_xray(xray)));
    }

    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<OutboundConnectRuntime>> = OnceLock::new();
        Arc::clone(SHARED.get_or_init(|| {
            Arc::new(Self {
                dns: DnsEngine::shared(),
                domain_strategy: OutboundDomainStrategy::AsIs,
                routing: None,
            })
        }))
    }
}
