//! Xray-compatible routing runtime (single source of truth for data-plane + RoutingService).

mod balancer;
mod compile;
mod conditions;
mod context;
mod dispatch;
mod geodata;
mod health;
mod proto_convert;
mod resolver;
mod router;
mod sniff;
mod stats;
mod webhook;

pub use compile::decode_router_config;
pub use context::{
    NetworkKind, RouteContext, RouteDecision, RouteError, ATTRIBUTE_RUNTIME_SOURCE,
    PROCESS_RUNTIME_SOURCE,
};
pub use dispatch::{
    connect_routed_outbound, route_context_from_vless, vless_route_from_uuid, RouteSocketMeta,
    RoutedOutbound,
};
pub use health::{
    HealthPingObservation, NoOutboundHealthProvider, OutboundHealthObservation,
    OutboundHealthProvider, SharedHealthProvider,
};
pub use proto_convert::{apply_field_selectors, route_context_from_proto, route_decision_to_proto};
pub use resolver::TargetResolver;
pub use router::{DomainStrategy, RuntimeRouter};
pub use sniff::sniff_protocol_from_payload;
pub use stats::RoutingStatsChannel;

pub const ROUTER_CONFIG_TYPE: &str = "xray.app.router.Config";
