use std::net::IpAddr;

use async_trait::async_trait;

use crate::dns::config::QueryStrategy;
use crate::dns::engine::DnsEngine;

#[async_trait]
pub trait TargetResolver: Send + Sync {
    async fn lookup_target_ips(&self, domain: &str) -> Result<Vec<IpAddr>, String>;
}

#[async_trait]
impl TargetResolver for DnsEngine {
    async fn lookup_target_ips(&self, domain: &str) -> Result<Vec<IpAddr>, String> {
        self.lookup_ip(domain, QueryStrategy::UseIP)
            .await
            .map_err(|err| err.to_string())
    }
}
