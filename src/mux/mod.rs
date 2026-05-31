mod encoder;
mod frame;
mod parser;
mod session;
mod state;
mod tcp;
mod udp_dns;

pub use encoder::{encode_mux_end, encode_mux_keep_data, encode_mux_udp_packet};
pub use frame::{
    MuxCommand, MuxDestination, MuxFrame, MuxNetwork, MuxOption, MuxSessionTrace, MuxStatus,
};
pub use parser::{parse_mux_frame, read_mux_frame};
pub use session::{
    handle_mux_cool_inbound, handle_mux_cool_inbound_traced, handle_mux_cool_inbound_with_dns,
    handle_mux_cool_inbound_with_dns_and_trace,
};

/// Primary VLESS entry point for Mux.Cool sessions.
pub use session::handle_mux_cool_inbound as handle_vless_mux;

#[cfg(test)]
pub(crate) use encoder::encode_mux_new_tcp;
