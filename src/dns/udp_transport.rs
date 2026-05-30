use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, trace, warn};

use crate::dns::config::DnsServerConfig;
use crate::dns::error::DnsError;
use crate::dns::packet::dns_query_id;

const MAX_UDP_DNS_PACKET: usize = 65_535;

#[derive(Debug, Default)]
pub struct UdpDnsTransport {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
}

impl UdpDnsTransport {
    pub async fn query(
        &mut self,
        query: &[u8],
        server: &DnsServerConfig,
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsError> {
        let server_addr = socket_addr_for_server(&server.host, server.port)?;
        self.query_at(server_addr, query, timeout).await
    }

    pub async fn query_at(
        &mut self,
        server: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DnsError> {
        let expected_id = dns_query_id(query).ok_or(DnsError::MalformedQuery)?;
        let socket = self.socket_for(server).await?;
        socket.send_to(query, server).await?;
        debug!(
            %server,
            query_len = query.len(),
            dns_id = expected_id,
            "dns upstream query sent"
        );

        let started = std::time::Instant::now();
        let deadline = started + timeout;
        let mut buf = vec![0u8; MAX_UDP_DNS_PACKET];
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                warn!(%server, dns_id = expected_id, "dns upstream timeout");
                return Err(DnsError::Timeout);
            }
            let received = match time::timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, peer))) => {
                    if peer != server {
                        trace!(%peer, %server, "dns upstream ignored packet from unexpected peer");
                        continue;
                    }
                    len
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => {
                    warn!(%server, dns_id = expected_id, "dns upstream timeout");
                    return Err(DnsError::Timeout);
                }
            };
            let response = &buf[..received];
            let response_id = dns_query_id(response).ok_or(DnsError::MalformedQuery)?;
            if response_id != expected_id {
                trace!(
                    expected_id,
                    response_id,
                    response_len = received,
                    "dns upstream ignored mismatched transaction id"
                );
                continue;
            }
            debug!(
                %server,
                response_len = received,
                latency_ms = started.elapsed().as_millis(),
                dns_id = response_id,
                "dns upstream response received"
            );
            return Ok(response.to_vec());
        }
    }

    async fn socket_for(&mut self, server: SocketAddr) -> Result<&UdpSocket, DnsError> {
        if server.is_ipv4() {
            if self.v4.is_none() {
                self.v4 = Some(
                    UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                        .await
                        .map_err(DnsError::from)?,
                );
                debug!(family = "ipv4", "dns udp transport socket bound");
            } else {
                trace!(family = "ipv4", "dns udp transport socket reused");
            }
            return Ok(self.v4.as_ref().expect("ipv4 dns udp socket"));
        }

        if self.v6.is_none() {
            self.v6 = Some(
                UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
                    .await
                    .map_err(DnsError::from)?,
            );
            debug!(family = "ipv6", "dns udp transport socket bound");
        } else {
            trace!(family = "ipv6", "dns udp transport socket reused");
        }
        Ok(self.v6.as_ref().expect("ipv6 dns udp socket"))
    }
}

pub fn socket_addr_for_server(host: &str, port: u16) -> Result<SocketAddr, DnsError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    Err(DnsError::UnsupportedTransport(format!(
        "dns server host must be numeric IP on this stage: {host}"
    )))
}
