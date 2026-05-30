pub mod dns_outbound;
pub mod domain_strategy;
pub mod freedom;
pub mod resolver;
pub mod runtime;

pub use dns_outbound::log_dns_outbounds;
pub use domain_strategy::OutboundDomainStrategy;
pub use freedom::{
    connect_tcp_destination, connect_tcp_destination_with_resolver,
    connect_tcp_destination_with_runtime, format_vless_destination, forward_tcp_initial_payload,
    relay_tcp_bidirectional,
};
pub use resolver::OutboundDnsResolver;
pub use runtime::{OutboundConnectRuntime, RoutingDnsRuntime};
