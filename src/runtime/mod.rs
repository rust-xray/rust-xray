mod commander_listener;
mod handler_config;
mod inbound_manager;
mod inbound_users;
mod logical_inbound_auth;
mod outbound_manager;

pub use crate::routing::RuntimeRouter;
pub use commander_listener::{
    close_commander_listener, CommanderConnection, CommanderIncoming, CommanderOutboundListener,
    InternalCommanderHandle, COMMANDER_OUTBOUND_BUFFER,
};
pub use handler_config::{
    decode_inbound_handler_config, decode_outbound_handler_config, encode_commander_outbound,
    encode_inbound_handler_config, encode_outbound_from_startup, encode_outbound_handler_config,
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
    /// Active observatory feature for API lookup (standard wins when both configured).
    pub observatory: Option<ActiveObservatory>,
    pub standard_observatory: Option<Arc<RuntimeObservatory>>,
    pub burst_observatory: Option<Arc<RuntimeBurstObservatory>>,
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
        let observatories = build_observatories(&xray, Arc::clone(&outbound))?;
        assemble_handler_runtime(
            outbound,
            xray,
            stats_registry,
            api_dokodemo_tag,
            enable_routing_stats,
            observatories,
        )
    }

    pub fn start_observatory(self: &Arc<Self>) {
        if let Some(observatory) = self.standard_observatory.as_ref() {
            observatory.start();
        }
        if let Some(observatory) = self.burst_observatory.as_ref() {
            observatory.start();
        }
    }

    pub async fn shutdown_observatory(&self) {
        if let Some(observatory) = self.standard_observatory.as_ref() {
            observatory.shutdown().await;
        }
        if let Some(observatory) = self.burst_observatory.as_ref() {
            observatory.shutdown().await;
        }
    }

    /// Build a handler runtime for Standard Observatory + routing integration tests.
    pub fn for_observatory_routing_tests(
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
        let standard_observatory = Some(RuntimeObservatory::new(
            observatory_config,
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        ));
        let observatory = ActiveObservatory::Standard(Arc::clone(
            standard_observatory.as_ref().expect("standard observatory"),
        ));
        Arc::new(
            assemble_handler_runtime(
                outbound,
                xray,
                stats_registry,
                None,
                true,
                ObservatoryRuntimeParts {
                    active: Some(observatory),
                    standard: standard_observatory,
                    burst: None,
                },
            )
            .expect("observatory routing test runtime"),
        )
    }

    /// Build a handler runtime for Burst Observatory + routing integration tests.
    pub fn for_burst_observatory_routing_tests(
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
        let burst_observatory = Some(RuntimeBurstObservatory::new(
            observatory_config,
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        ));
        let observatory = ActiveObservatory::Burst(Arc::clone(
            burst_observatory.as_ref().expect("burst observatory"),
        ));
        Arc::new(
            assemble_handler_runtime(
                outbound,
                xray,
                stats_registry,
                None,
                true,
                ObservatoryRuntimeParts {
                    active: Some(observatory),
                    standard: None,
                    burst: burst_observatory,
                },
            )
            .expect("burst observatory routing test runtime"),
        )
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
        let standard_observatory = Some(RuntimeObservatory::new(
            observatory_config,
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        ));
        let observatory = ActiveObservatory::Standard(Arc::clone(
            standard_observatory.as_ref().expect("standard observatory"),
        ));
        Arc::new(
            assemble_handler_runtime(
                outbound,
                xray,
                stats_registry,
                None,
                false,
                ObservatoryRuntimeParts {
                    active: Some(observatory),
                    standard: standard_observatory,
                    burst: None,
                },
            )
            .expect("observatory test runtime"),
        )
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
        let burst_observatory = Some(RuntimeBurstObservatory::new(
            observatory_config,
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        ));
        let observatory = ActiveObservatory::Burst(Arc::clone(
            burst_observatory.as_ref().expect("burst observatory"),
        ));
        Arc::new(
            assemble_handler_runtime(
                outbound,
                xray,
                stats_registry,
                None,
                false,
                ObservatoryRuntimeParts {
                    active: Some(observatory),
                    standard: None,
                    burst: burst_observatory,
                },
            )
            .expect("burst observatory test runtime"),
        )
    }

    /// Build a handler runtime with both Standard and Burst observatories configured.
    pub fn for_coexistence_observatory_tests(
        stats_registry: Arc<StatsRegistry>,
        standard_config: ObservatoryRuntimeConfig,
        burst_config: BurstObservatoryRuntimeConfig,
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
        let standard_observatory = Some(RuntimeObservatory::new(
            standard_config,
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        ));
        let burst_observatory = Some(RuntimeBurstObservatory::new(
            burst_config,
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        ));
        let observatory = ActiveObservatory::Standard(Arc::clone(
            standard_observatory.as_ref().expect("standard observatory"),
        ));
        Arc::new(
            assemble_handler_runtime(
                outbound,
                xray,
                stats_registry,
                None,
                false,
                ObservatoryRuntimeParts {
                    active: Some(observatory),
                    standard: standard_observatory,
                    burst: burst_observatory,
                },
            )
            .expect("coexistence observatory test runtime"),
        )
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

struct ObservatoryRuntimeParts {
    active: Option<ActiveObservatory>,
    standard: Option<Arc<RuntimeObservatory>>,
    burst: Option<Arc<RuntimeBurstObservatory>>,
}

fn assemble_handler_runtime(
    outbound: Arc<RuntimeOutboundManager>,
    xray: Arc<XrayConfig>,
    stats_registry: Arc<StatsRegistry>,
    api_dokodemo_tag: Option<String>,
    enable_routing_stats: bool,
    observatories: ObservatoryRuntimeParts,
) -> Result<HandlerRuntime, crate::routing::RouteError> {
    let health = observatories
        .active
        .as_ref()
        .map(ActiveObservatory::health_provider);
    let router = RuntimeRouter::new(
        xray.routing.as_ref(),
        Arc::clone(&outbound),
        DnsEngine::shared(),
        enable_routing_stats,
        health,
    )?;
    let inbound = RuntimeInboundManager::new(
        Arc::clone(&xray),
        stats_registry,
        api_dokodemo_tag,
        Arc::clone(&router),
    );
    Ok(HandlerRuntime {
        inbound,
        outbound,
        router,
        observatory: observatories.active,
        standard_observatory: observatories.standard,
        burst_observatory: observatories.burst,
    })
}

fn build_observatories(
    xray: &XrayConfig,
    outbound: Arc<RuntimeOutboundManager>,
) -> Result<ObservatoryRuntimeParts, crate::routing::RouteError> {
    let standard = xray.observatory.as_ref().map(|raw| {
        RuntimeObservatory::new(
            ObservatoryRuntimeConfig::from_raw(raw),
            Arc::clone(&outbound),
            OutboundConnectRuntime::shared(),
        )
    });
    let burst = match xray.burst_observatory.as_ref() {
        Some(raw) => Some(RuntimeBurstObservatory::new(
            BurstObservatoryRuntimeConfig::from_raw(raw)
                .map_err(|err| crate::routing::RouteError::InvalidArgument(err.to_string()))?,
            outbound,
            OutboundConnectRuntime::shared(),
        )),
        None => None,
    };
    let active = standard
        .as_ref()
        .map(|standard| ActiveObservatory::Standard(Arc::clone(standard)))
        .or_else(|| {
            burst
                .as_ref()
                .map(|burst| ActiveObservatory::Burst(Arc::clone(burst)))
        });
    Ok(ObservatoryRuntimeParts {
        active,
        standard,
        burst,
    })
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
