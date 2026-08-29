use std::sync::Arc;

use crate::dns::client::Network;
use crate::routing::{NetworkKind, RouteContext, RuntimeRouter};

/// DNS subsystem outbound selection input (not a separate routing engine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRoutingContext {
    pub network: Network,
    pub destination_host: String,
    pub destination_port: u16,
    pub inbound_tag: Option<String>,
    pub protocol: Option<String>,
}

/// Selects DNS upstream dial outbound via the shared RuntimeRouter.
#[derive(Clone)]
pub struct DnsOutboundSelector {
    router: Arc<RuntimeRouter>,
}

impl DnsOutboundSelector {
    pub fn new(router: Arc<RuntimeRouter>) -> Self {
        Self { router }
    }

    pub async fn select_outbound_tag(&self, ctx: &DnsRoutingContext) -> Option<String> {
        let route_ctx = RouteContext {
            inbound_tag: ctx.inbound_tag.clone().unwrap_or_default(),
            network: NetworkKind::Tcp,
            target_domain: ctx.destination_host.clone(),
            target_port: ctx.destination_port,
            protocol: ctx.protocol.clone().unwrap_or_else(|| "dns".to_string()),
            skip_dns_resolve: true,
            ..Default::default()
        };
        self.router
            .pick_route_with_default(route_ctx)
            .await
            .ok()
            .map(|decision| decision.outbound_tag)
    }

    pub fn router(&self) -> &Arc<RuntimeRouter> {
        &self.router
    }
}

#[cfg(test)]
#[path = "../../tests/unit/dns/routing.rs"]
mod tests;
