use std::time::Duration;

use async_trait::async_trait;

use crate::dns::config::DnsServerConfig;
use crate::dns::error::DnsError;
use crate::dns::transport::DnsTransport;

/// DoH transport placeholder. Parsed `https://` DNS servers are accepted in config
/// but queries return an explicit unsupported error until a TLS/HTTP client is wired.
#[derive(Debug, Default)]
pub struct DohDnsTransport;

#[async_trait]
impl DnsTransport for DohDnsTransport {
    async fn query(
        &self,
        _query: &[u8],
        server: &DnsServerConfig,
        _timeout: Duration,
    ) -> Result<Vec<u8>, DnsError> {
        Err(DnsError::UnsupportedTransport(format!(
            "DNS transport {} is parsed but not implemented yet",
            server.transport.label()
        )))
    }
}
