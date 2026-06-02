//! Xray / Remnawave panel JSON config parsing and validation.

pub mod api;
pub mod load;
pub mod raw;
pub mod reality;
pub mod routing;
pub mod transport;
pub mod validate;
pub mod xhttp;

pub use api::*;
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
