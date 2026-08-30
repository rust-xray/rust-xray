//! Xray `tunnel` inbound (dokodemo-door alias) for RemnaNode abstract Unix API paths.

mod inbound;

pub use inbound::{start_tunnel_inbound, TunnelInboundHandle};
