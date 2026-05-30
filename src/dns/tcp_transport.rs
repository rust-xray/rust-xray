use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::time;
use tracing::{debug, warn};

use crate::dns::config::DnsServerConfig;
use crate::dns::error::DnsError;
use crate::dns::packet::dns_query_id;
use crate::dns::tcp_codec::{read_dns_tcp_response, write_dns_tcp_query, DNS_TCP_MAX_FRAME_LEN};
use crate::dns::transport::DnsTransport;
use crate::dns::udp_transport::socket_addr_for_server;

#[derive(Debug, Default)]
pub struct TcpDnsTransport;

#[async_trait]
impl DnsTransport for TcpDnsTransport {
    async fn query(
        &self,
        query: &[u8],
        server: &DnsServerConfig,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsError> {
        let expected_id = dns_query_id(query).ok_or(DnsError::MalformedQuery)?;
        let server_addr = socket_addr_for_server(&server.host, server.port)?;
        let started = std::time::Instant::now();

        let mut stream = match time::timeout(timeout, TcpStream::connect(server_addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {
                warn!(%server_addr, dns_id = expected_id, "dns tcp upstream connect timeout");
                return Err(DnsError::Timeout);
            }
        };

        match time::timeout(timeout, write_dns_tcp_query(&mut stream, query)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {
                warn!(%server_addr, dns_id = expected_id, "dns tcp upstream write timeout");
                return Err(DnsError::Timeout);
            }
        }

        let response = match time::timeout(
            timeout,
            read_dns_tcp_response(&mut stream, DNS_TCP_MAX_FRAME_LEN),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {
                warn!(%server_addr, dns_id = expected_id, "dns tcp upstream read timeout");
                return Err(DnsError::Timeout);
            }
        };

        let response_id = dns_query_id(&response).ok_or(DnsError::MalformedQuery)?;
        if response_id != expected_id {
            warn!(
                expected_id,
                response_id, "dns tcp upstream ignored mismatched transaction id"
            );
            return Err(DnsError::Upstream);
        }

        debug!(
            %server_addr,
            response_len = response.len(),
            latency_ms = started.elapsed().as_millis(),
            dns_id = response_id,
            "dns upstream response received"
        );
        Ok(response)
    }
}
