use std::sync::Arc;

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use crate::mux::xudp::XudpManager;
use crate::routing::{RouteSocketMeta, RuntimeRouter};
use crate::stats::StatsSession;
use crate::vless::user_manager::VlessAuthenticatedClient;

/// Per-mux-session routing context shared by substream dispatches.
#[derive(Clone)]
pub struct MuxRouteEnv {
    pub router: Arc<RuntimeRouter>,
    pub inbound_tag: String,
    pub auth: VlessAuthenticatedClient,
    pub socket_meta: RouteSocketMeta,
    pub sniffing_enabled: bool,
    /// When true, Vision+Mux accepts only UDP child substreams.
    pub vision_mux_udp_only: bool,
    pub stats: Option<StatsSession>,
    pub xudp: Arc<XudpManager>,
    /// Test-only counter incremented on each routed Mux UDP dispatch.
    #[cfg(test)]
    pub test_dispatch_counter: Option<Arc<AtomicUsize>>,
}
