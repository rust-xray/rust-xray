use std::net::IpAddr;

use async_trait::async_trait;

use crate::dns::{DnsEngine, DnsError, QueryStrategy};

#[async_trait]
pub trait OutboundDnsResolver: Send + Sync {
    async fn lookup_ip(
        &self,
        domain: &str,
        strategy: QueryStrategy,
    ) -> Result<Vec<IpAddr>, DnsError>;
}

#[async_trait]
impl OutboundDnsResolver for DnsEngine {
    async fn lookup_ip(
        &self,
        domain: &str,
        strategy: QueryStrategy,
    ) -> Result<Vec<IpAddr>, DnsError> {
        DnsEngine::lookup_ip(self, domain, strategy).await
    }
}

pub fn dns_error_to_io(err: DnsError) -> std::io::Error {
    std::io::Error::new(err.kind(), err.to_string())
}
