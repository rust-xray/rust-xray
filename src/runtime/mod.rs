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
use crate::observatory::{
    ActiveObservatory, BurstObservatoryRuntimeConfig, ObservatoryRuntimeConfig,
    RuntimeBurstObservatory, RuntimeObservatory,
};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::stats::StatsRegistry;

/// Shared HandlerService runtime (inbound + outbound managers + routing).
#[derive(Clone)]
pub struct HandlerRuntime {
    pub inbound: Arc<RuntimeInboundManager>,
    pub outbound: Arc<RuntimeOutboundManager>,
    pub router: Arc<RuntimeRouter>,
    pub observatory: Option<ActiveObservatory>,
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
        let inbound = RuntimeInboundManager::new(
            Arc::clone(&xray),
            stats_registry,
            api_dokodemo_tag,
            Arc::clone(&router),
        );
        let observatory = build_active_observatory(&xray, Arc::clone(&outbound))?;
        Ok(Self {
            inbound,
            outbound,
            router,
            observatory,
        })
    }

    pub fn start_observatory(self: &Arc<Self>) {
        if let Some(observatory) = self.observatory.as_ref() {
            observatory.start();
        }
    }

    pub async fn shutdown_observatory(&self) {
        if let Some(observatory) = self.observatory.as_ref() {
            observatory.shutdown().await;
        }
    }

    /// Build a handler runtime for Standard Observatory tests.
    pub fn for_observatory_tests(
        stats_registry: Arc<StatsRegistry>,
        observatory_config: ObservatoryRuntimeConfig,
        outbounds: Vec<crate::api::proto::core::OutboundHandlerConfig>,
    ) -> Arc<Self> {
        let outbound = RuntimeOutboundManager::new();
        for config in outbounds {
            outbound
                .add_outbound(config)
                .expect("test outbound must be valid");
        }
        init_test_connect_runtime();
        let xray = Arc::new(empty_test_xray_config());
        let router = test_router(&xray, Arc::clone(&outbound));
        let inbound = RuntimeInboundManager::new(
            Arc::clone(&xray),
            stats_registry,
            None,
            Arc::clone(&router),
        );
        let observatory = ActiveObservatory::Standard(RuntimeObservatory::new(
            observatory_config,
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        ));
        Arc::new(Self {
            inbound,
            outbound,
            router,
            observatory: Some(observatory),
        })
    }

    /// Build a handler runtime for Burst Observatory tests.
    pub fn for_burst_observatory_tests(
        stats_registry: Arc<StatsRegistry>,
        observatory_config: BurstObservatoryRuntimeConfig,
        outbounds: Vec<crate::api::proto::core::OutboundHandlerConfig>,
    ) -> Arc<Self> {
        let outbound = RuntimeOutboundManager::new();
        for config in outbounds {
            outbound
                .add_outbound(config)
                .expect("test outbound must be valid");
        }
        init_test_connect_runtime();
        let xray = Arc::new(empty_test_xray_config());
        let router = test_router(&xray, Arc::clone(&outbound));
        let inbound = RuntimeInboundManager::new(
            Arc::clone(&xray),
            stats_registry,
            None,
            Arc::clone(&router),
        );
        let observatory = ActiveObservatory::Burst(RuntimeBurstObservatory::new(
            observatory_config,
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        ));
        Arc::new(Self {
            inbound,
            outbound,
            router,
            observatory: Some(observatory),
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
        let xray = Arc::new(empty_test_xray_config());
        Arc::new(
            Self::new(xray, stats_registry, None, enable_routing_stats)
                .expect("test handler runtime"),
        )
    }
}

fn build_active_observatory(
    xray: &XrayConfig,
    outbound: Arc<RuntimeOutboundManager>,
) -> Result<Option<ActiveObservatory>, crate::routing::RouteError> {
    if let Some(raw) = xray.observatory.as_ref() {
        let config = ObservatoryRuntimeConfig::from_raw(raw);
        return Ok(Some(ActiveObservatory::Standard(RuntimeObservatory::new(
            config,
            outbound,
            OutboundConnectRuntime::shared(),
        ))));
    }
    if let Some(raw) = xray.burst_observatory.as_ref() {
        let config = BurstObservatoryRuntimeConfig::from_raw(raw)
            .map_err(|err| crate::routing::RouteError::InvalidArgument(err.to_string()))?;
        return Ok(Some(ActiveObservatory::Burst(
            RuntimeBurstObservatory::new(config, outbound, OutboundConnectRuntime::shared()),
        )));
    }
    Ok(None)
}

fn empty_test_xray_config() -> XrayConfig {
    XrayConfig {
        log: None,
        api: None,
        dns: None,
        stats: None,
        policy: None,
        routing: None,
        observatory: None,
        burst_observatory: None,
        outbounds: vec![],
        inbounds: vec![],
        extra: Default::default(),
    }
}

fn init_test_connect_runtime() {
    OutboundConnectRuntime::init_shared(&empty_test_xray_config());
}

fn test_router(
    xray: &Arc<XrayConfig>,
    outbound: Arc<RuntimeOutboundManager>,
) -> Arc<RuntimeRouter> {
    RuntimeRouter::new(
        xray.routing.as_ref(),
        outbound,
        DnsEngine::shared(),
        false,
        None,
    )
    .expect("test router")
}
