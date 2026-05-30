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
use super::routing::{DnsRouter, DnsRoutingContext};
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
    router: Arc<DnsRouter>,
    outbound_manager: Arc<dyn OutboundManager>,
}

impl DnsClient {
    pub fn new(
        config: DnsConfig,
        router: Arc<DnsRouter>,
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
        let outbound_tag = self.router.select_outbound_tag(&ctx);
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
mod tests {
    use super::*;
    use crate::config::XrayConfig;
    use crate::dns::tcp_codec::{decode_dns_tcp_frame, encode_dns_tcp_frame};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct FakeOutboundManager {
        captured: Arc<Mutex<Vec<DialRequest>>>,
        response: Vec<u8>,
    }

    impl OutboundManager for FakeOutboundManager {
        fn dial_tcp<'a>(
            &'a self,
            req: DialRequest,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<DialStream>> + Send + 'a>> {
            Box::pin(async move {
                self.captured.lock().unwrap().push(req);
                let (client, mut server) = tokio::io::duplex(4096);
                let response = self.response.clone();
                tokio::spawn(async move {
                    let mut prefix = [0u8; 2];
                    server.read_exact(&mut prefix).await.unwrap();
                    let len = u16::from_be_bytes(prefix) as usize;
                    let mut frame = vec![0u8; len + 2];
                    frame[..2].copy_from_slice(&prefix);
                    server.read_exact(&mut frame[2..]).await.unwrap();
                    let raw = decode_dns_tcp_frame(&frame).unwrap();
                    assert_eq!(raw[0], 0x12);
                    let response_frame = encode_dns_tcp_frame(&response).unwrap();
                    server.write_all(&response_frame).await.unwrap();
                });
                Ok(Box::new(client) as DialStream)
            })
        }
    }

    fn dns_query() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        packet
    }

    #[tokio::test]
    async fn dns_client_uses_selected_proxy_outbound_and_returns_raw_response() {
        let config: XrayConfig = serde_json::from_str(
            r#"{
              "dns": {"servers":["tcp://1.1.1.1:53"],"queryStrategy":"UseIPv4"},
              "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"vless"}],
              "routing": {"rules": [{"type":"field","port":53,"network":"tcp","outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
        let dns = config.dns.clone().unwrap();
        let router = Arc::new(DnsRouter::new(config.routing, config.outbounds));
        let fake = Arc::new(FakeOutboundManager {
            captured: Arc::new(Mutex::new(Vec::new())),
            response: vec![0x12, 0x34, 0x81, 0x80],
        });
        let client = DnsClient::new(dns, router, fake.clone());

        let response = client
            .query_raw(&dns_query(), Some("dns-in"))
            .await
            .unwrap();
        assert_eq!(response, vec![0x12, 0x34, 0x81, 0x80]);

        let captured = fake.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].destination_host, "1.1.1.1");
        assert_eq!(captured[0].destination_port, 53);
        assert_eq!(captured[0].outbound_tag.as_deref(), Some("proxy"));
        assert_eq!(captured[0].purpose, DialPurpose::Dns);
    }

    #[tokio::test]
    async fn unsupported_doh_is_explicit() {
        let config: XrayConfig = serde_json::from_str(
            r#"{"dns":{"servers":["https://dns.google/dns-query"]},"outbounds":[{"tag":"proxy","protocol":"vless"}]}"#,
        )
        .unwrap();
        let router = Arc::new(DnsRouter::new(config.routing, config.outbounds));
        let fake = Arc::new(FakeOutboundManager::default());
        let client = DnsClient::new(config.dns.unwrap(), router, fake);

        let err = client.query_raw(&dns_query(), None).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err
            .to_string()
            .contains("DNS transport doh is parsed but not implemented yet"));
    }

    #[tokio::test]
    async fn standard_manager_rejects_proxy_outbound_without_direct_leak() {
        let manager = StandardOutboundManager::new(vec![OutboundObject {
            tag: Some("proxy".to_string()),
            protocol: Some("vless".to_string()),
            extra: Default::default(),
        }]);
        let req = DialRequest {
            network: Network::Tcp,
            destination_host: "1.1.1.1".to_string(),
            destination_port: 53,
            outbound_tag: Some("proxy".to_string()),
            source_inbound_tag: Some("dns-in".to_string()),
            purpose: DialPurpose::Dns,
        };
        let err = match manager.dial_tcp(req).await {
            Ok(_) => panic!("expected unsupported outbound"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
