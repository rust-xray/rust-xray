use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{timeout, Duration};
use tracing::{debug, error};

use crate::config::OutboundObject;
use crate::outbound::connect_tcp_destination;
use crate::vless::protocol::VlessDestination;

use super::config::{DnsConfig, DnsServerConfig, DnsServerTransport};
use super::question::parse_dns_question_for_log;
use super::routing::{DnsOutboundSelector, DnsRoutingContext};
use super::tcp_codec::{read_dns_tcp_response, write_dns_tcp_query, DNS_TCP_MAX_FRAME_LEN};

pub const DNS_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
pub const DNS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialPurpose {
    Proxy,
    Dns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialRequest {
    pub network: Network,
    pub destination_host: String,
    pub destination_port: u16,
    pub outbound_tag: Option<String>,
    pub source_inbound_tag: Option<String>,
    pub purpose: DialPurpose,
}

pub type DialStream = Box<dyn AsyncReadWrite + Send + Unpin>;

pub trait OutboundManager: Send + Sync {
    fn dial_tcp<'a>(
        &'a self,
        req: DialRequest,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<DialStream>> + Send + 'a>>;
}

#[derive(Debug, Clone)]
pub struct StandardOutboundManager {
    outbounds: Vec<OutboundObject>,
}

impl StandardOutboundManager {
    pub fn new(outbounds: Vec<OutboundObject>) -> Self {
        Self { outbounds }
    }

    fn selected_outbound(&self, tag: Option<&str>) -> Option<&OutboundObject> {
        match tag {
            Some(tag) => self
                .outbounds
                .iter()
                .find(|outbound| outbound.tag.as_deref() == Some(tag))
                .or_else(|| {
                    self.outbounds.iter().find(|outbound| {
                        outbound.tag.is_none()
                            && outbound
                                .protocol
                                .as_deref()
                                .is_some_and(|protocol| protocol.eq_ignore_ascii_case(tag))
                    })
                }),
            None => self.outbounds.first(),
        }
    }
}

impl OutboundManager for StandardOutboundManager {
    fn dial_tcp<'a>(
        &'a self,
        req: DialRequest,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<DialStream>> + Send + 'a>> {
        Box::pin(async move {
            let outbound = self
                .selected_outbound(req.outbound_tag.as_deref())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("selected outbound not found: {:?}", req.outbound_tag),
                    )
                })?;
            let protocol = outbound.protocol.as_deref().unwrap_or("");
            if !protocol.eq_ignore_ascii_case("freedom") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "outbound protocol {protocol:?} is not implemented for DNS dialing yet"
                    ),
                ));
            }
            let destination = match req.destination_host.parse::<IpAddr>() {
                Ok(ip) => VlessDestination::Ip(ip, req.destination_port),
                Err(_) => {
                    VlessDestination::Domain(req.destination_host.clone(), req.destination_port)
                }
            };
            let stream = connect_tcp_destination(&destination).await?;
            Ok(Box::new(stream) as DialStream)
        })
    }
}

pub struct DnsClient {
    config: DnsConfig,
    router: Arc<DnsOutboundSelector>,
    outbound_manager: Arc<dyn OutboundManager>,
}

impl DnsClient {
    pub fn new(
        config: DnsConfig,
        router: Arc<DnsOutboundSelector>,
        outbound_manager: Arc<dyn OutboundManager>,
    ) -> Self {
        Self {
            config,
            router,
            outbound_manager,
        }
    }

    pub async fn query_raw(
        &self,
        query: &[u8],
        inbound_tag: Option<&str>,
    ) -> std::io::Result<Vec<u8>> {
        let started = Instant::now();
        let question = parse_dns_question_for_log(query);
        debug!(
            qname = ?question.as_ref().map(|q| q.qname.as_str()),
            qtype = ?question.as_ref().map(|q| q.qtype),
            inbound_tag,
            "DNS query start"
        );

        let server = self.select_first_supported_server()?;
        if server.transport != DnsServerTransport::Tcp {
            return Err(unsupported_transport(&server.transport));
        }

        let ctx = DnsRoutingContext {
            network: Network::Tcp,
            destination_host: server.host.clone(),
            destination_port: server.port,
            inbound_tag: inbound_tag.map(str::to_string),
            protocol: Some("dns".to_string()),
        };
        let outbound_tag = self.router.select_outbound_tag(&ctx).await;
        debug!(
            transport = "tcp",
            dns_server = %format!("{}:{}", server.host, server.port),
            selected_outbound_tag = ?outbound_tag,
            "DNS server selected"
        );

        let req = DialRequest {
            network: Network::Tcp,
            destination_host: server.host.clone(),
            destination_port: server.port,
            outbound_tag: outbound_tag.clone(),
            source_inbound_tag: inbound_tag.map(str::to_string),
            purpose: DialPurpose::Dns,
        };

        let mut stream = timeout(DNS_DIAL_TIMEOUT, self.outbound_manager.dial_tcp(req))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS outbound dial timed out")
            })??;

        write_dns_tcp_query(&mut stream, query).await?;
        let response = timeout(
            DNS_RESPONSE_TIMEOUT,
            read_dns_tcp_response(&mut stream, DNS_TCP_MAX_FRAME_LEN),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS TCP response timed out")
        })??;

        debug!(
            selected_outbound_tag = ?outbound_tag,
            response_len = response.len(),
            latency_ms = started.elapsed().as_millis(),
            "DNS query completed"
        );
        Ok(response)
    }

    fn select_first_supported_server(&self) -> std::io::Result<&DnsServerConfig> {
        if let Some(server) = self
            .config
            .servers
            .iter()
            .find(|server| server.transport == DnsServerTransport::Tcp)
        {
            return Ok(server);
        }
        let Some(server) = self.config.servers.first() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "dns.servers must contain at least one server",
            ));
        };
        error!(
            transport = server.transport.label(),
            "DNS transport is parsed but not implemented yet"
        );
        Err(unsupported_transport(&server.transport))
    }
}

fn unsupported_transport(transport: &DnsServerTransport) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "DNS transport {} is parsed but not implemented yet",
            transport.label()
        ),
    )
}

#[cfg(test)]
#[path = "../../tests/unit/dns/client.rs"]
mod tests;
