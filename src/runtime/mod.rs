mod handler_config;
mod inbound_manager;
mod inbound_users;
mod logical_inbound_auth;
mod outbound_manager;

pub use crate::routing::RuntimeRouter;
pub use handler_config::{
    decode_inbound_handler_config, decode_outbound_handler_config, encode_inbound_handler_config,
    encode_outbound_from_startup, encode_outbound_handler_config,
    encode_plain_vless_inbound_handler_config, DecodedInboundHandler, HandlerConfigError,
    OutboundProtocol, BLACKHOLE_CONFIG_TYPE, FREEDOM_CONFIG_TYPE, REALITY_CONFIG_TYPE,
    RECEIVER_CONFIG_TYPE, SPLITHHTTP_CONFIG_TYPE, VLESS_INBOUND_CONFIG_TYPE,
};
pub use inbound_manager::{InboundManagerError, RuntimeInboundManager};
pub use inbound_users::InboundUserManagers;
pub use logical_inbound_auth::{
    LogicalInboundAuthError, LogicalInboundAuthSet, VlessInboundAuthContext,
};
pub use outbound_manager::{
    encode_blackhole_outbound, encode_freedom_outbound, OutboundEntry, OutboundManagerError,
    RuntimeOutboundManager,
};

use std::sync::Arc;

use crate::config::XrayConfig;
use crate::dns::engine::DnsEngine;
use crate::stats::StatsRegistry;

/// Shared HandlerService runtime (inbound + outbound managers + routing).
#[derive(Clone)]
pub struct HandlerRuntime {
    pub inbound: Arc<RuntimeInboundManager>,
    pub outbound: Arc<RuntimeOutboundManager>,
    pub router: Arc<RuntimeRouter>,
}

impl HandlerRuntime {
    pub fn new(
        xray: Arc<XrayConfig>,
        stats_registry: Arc<StatsRegistry>,
        api_dokodemo_tag: Option<String>,
        enable_routing_stats: bool,
    ) -> Result<Self, crate::routing::RouteError> {
        let outbound = RuntimeOutboundManager::new();
        for ob in &xray.outbounds {
            let _ = outbound.register_startup_outbound(ob);
        }
        let dns = DnsEngine::shared();
        let router = RuntimeRouter::new(
            xray.routing.as_ref(),
            Arc::clone(&outbound),
            dns,
            enable_routing_stats,
            None,
        )?;
        let inbound =
            RuntimeInboundManager::new(xray, stats_registry, api_dokodemo_tag, Arc::clone(&router));
        Ok(Self {
            inbound,
            outbound,
            router,
        })
    }

    /// Minimal runtime for HandlerService integration tests (no startup inbounds/outbounds).
    pub fn for_handler_tests(stats_registry: Arc<StatsRegistry>) -> Arc<Self> {
        Self::for_tests(stats_registry, false)
    }

    /// Runtime for RoutingService tests with routing stats channel enabled.
    pub fn for_routing_tests(stats_registry: Arc<StatsRegistry>) -> Arc<Self> {
        Self::for_tests(stats_registry, true)
    }

    fn for_tests(stats_registry: Arc<StatsRegistry>, enable_routing_stats: bool) -> Arc<Self> {
        let xray = Arc::new(XrayConfig {
            log: None,
            api: None,
            dns: None,
            stats: None,
            policy: None,
            routing: None,
            outbounds: vec![],
            inbounds: vec![],
            extra: Default::default(),
        });
        Arc::new(
            Self::new(xray, stats_registry, None, enable_routing_stats)
                .expect("test handler runtime"),
        )
    }
}
