mod encoder;
mod frame;
mod packet_udp;
mod parser;
mod route_env;
mod session;
mod state;
mod tcp;
mod udp_dns;
mod xudp;

pub use encoder::{
    encode_mux_end, encode_mux_keep_data, encode_mux_new_tcp, encode_mux_udp_packet,
};
pub use frame::{
    MuxCommand, MuxDestination, MuxFrame, MuxNetwork, MuxOption, MuxSessionTrace, MuxStatus,
};
pub use parser::{parse_mux_frame, read_mux_frame};
pub use route_env::MuxRouteEnv;
pub use session::{
    handle_mux_cool_inbound, handle_mux_cool_inbound_traced, handle_mux_cool_inbound_with_dns,
    handle_mux_cool_inbound_with_dns_and_trace, handle_mux_cool_inbound_with_env,
};
pub use xudp::{XudpManager, XudpManagerConfig, XudpMuxSessions};

/// Primary VLESS entry point for Mux.Cool sessions.
pub use session::handle_mux_cool_inbound as handle_vless_mux;
