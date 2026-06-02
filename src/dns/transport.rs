use std::time::Duration;

use async_trait::async_trait;

use crate::dns::config::{DnsServerConfig, DnsServerTransport};
use crate::dns::error::DnsError;
use crate::dns::tcp_transport::TcpDnsTransport;
use crate::dns::udp_transport::UdpDnsTransport;

#[async_trait]
pub trait DnsTransport: Send + Sync {
    async fn query(
        &self,
        query: &[u8],
        server: &DnsServerConfig,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsError>;
}

pub struct DnsTransportStack {
    pub(crate) udp: UdpDnsTransport,
    tcp: TcpDnsTransport,
}

impl Default for DnsTransportStack {
    fn default() -> Self {
        Self {
            udp: UdpDnsTransport::default(),
            tcp: TcpDnsTransport,
        }
    }
}

impl DnsTransportStack {
    pub async fn query(
        &self,
        query: &[u8],
        server: &DnsServerConfig,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsError> {
        match server.transport {
            DnsServerTransport::Udp => self.udp.query(query, server, timeout).await,
            DnsServerTransport::Tcp => self.tcp.query(query, server, timeout).await,
            DnsServerTransport::Doh | DnsServerTransport::DohLocal => {
                Err(DnsError::UnsupportedTransport(format!(
                    "DNS transport {} is parsed but not implemented yet",
                    server.transport.label()
                )))
            }
            DnsServerTransport::TcpLocal => Err(DnsError::UnsupportedTransport(
                "DNS transport tcp+local is parsed but not implemented yet".to_string(),
            )),
            DnsServerTransport::Unsupported(ref scheme) => Err(DnsError::UnsupportedTransport(
                format!("unsupported DNS transport scheme: {scheme}"),
            )),
        }
    }

    pub fn is_supported(transport: &DnsServerTransport) -> bool {
        matches!(transport, DnsServerTransport::Udp | DnsServerTransport::Tcp)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/dns/transport.rs"]
mod tests;
