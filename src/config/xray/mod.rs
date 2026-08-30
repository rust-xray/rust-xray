//! Xray / Remnawave panel JSON config parsing and validation.

pub mod api;
pub mod api_listen;
mod limit_fallback;
pub mod load;
mod observatory;
pub mod raw;
pub mod reality;
pub mod routing;
pub mod transport;
pub mod validate;
pub mod xhttp;

pub use api::*;
pub use api_listen::{
    api_listen_kind, bind_api_listen, bind_api_listener, is_internal_commander_listen,
    parse_api_grpc_listen_addr, parse_api_tcp_listen_addr, ApiListenKind, BoundApiListener,
};
pub use limit_fallback::LimitFallback;
pub use load::*;
pub use raw::*;
pub use reality::*;
pub use transport::validate_reality_transport_network;
pub use transport::TransportNetwork;
pub use validate::{
    format_listen_host, is_vless_reality_inbound, parse_inbound_port,
    validate_reality_inbound_config_policy, validate_reality_stream_settings,
};

#[cfg(test)]
#[path = "../../../tests/unit/config/xray.rs"]
mod tests;
