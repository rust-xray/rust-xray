pub mod cache;
pub mod client;
pub mod config;
pub mod doh_transport;
pub mod engine;
pub mod error;
pub mod mux_upstream;
pub mod options;
pub mod packet;
pub mod question;
pub mod routing;
pub mod tcp_codec;
pub mod tcp_transport;
pub mod transport;
pub mod udp_transport;

pub use client::{
    AsyncReadWrite, DialPurpose, DialRequest, DnsClient, Network, OutboundManager,
    StandardOutboundManager,
};
pub use config::{DnsConfig, DnsServerConfig, DnsServerTransport, QueryStrategy};
pub use engine::{DnsEngine, DnsQueryRequest, DnsQuerySource};
pub use error::{DnsError, DnsQueryResponse};
pub use options::{DnsEngineOptions, MuxDnsUpstreamMode};
pub use packet::{DnsInflightKey, DnsQuestionKey};
pub use question::{parse_dns_question_for_log, DnsQuestionLog};
pub use tcp_transport::TcpDnsTransport;
pub use transport::{DnsTransport, DnsTransportStack};
pub use udp_transport::UdpDnsTransport;
