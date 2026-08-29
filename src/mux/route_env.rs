use std::sync::Arc;

use crate::routing::{RouteSocketMeta, RuntimeRouter};
use crate::vless::user_manager::VlessAuthenticatedClient;

/// Per-mux-session routing context shared by substream dispatches.
#[derive(Clone)]
pub struct MuxRouteEnv {
    pub router: Arc<RuntimeRouter>,
    pub inbound_tag: String,
    pub auth: VlessAuthenticatedClient,
    pub socket_meta: RouteSocketMeta,
    pub sniffing_enabled: bool,
}
