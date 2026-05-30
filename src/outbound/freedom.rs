use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::outbound::domain_strategy::OutboundDomainStrategy;
use crate::outbound::resolver::{dns_error_to_io, OutboundDnsResolver};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::vless::protocol::VlessDestination;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace};

pub fn format_vless_destination(destination: &VlessDestination) -> String {
    match destination {
        VlessDestination::Ip(addr, port) => match addr {
            IpAddr::V4(v4) => format!("{v4}:{port}"),
            IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        },
        VlessDestination::Domain(domain, port) => format!("{domain}:{port}"),
    }
}

pub async fn connect_tcp_destination(destination: &VlessDestination) -> std::io::Result<TcpStream> {
    connect_tcp_destination_with_runtime(destination, OutboundConnectRuntime::shared()).await
}

pub async fn connect_tcp_destination_with_runtime(
    destination: &VlessDestination,
    runtime: Arc<OutboundConnectRuntime>,
) -> std::io::Result<TcpStream> {
    connect_tcp_destination_with_resolver(
        destination,
        runtime.domain_strategy,
        Some(runtime.dns.as_ref()),
    )
    .await
}

pub async fn connect_tcp_destination_with_resolver(
    destination: &VlessDestination,
    strategy: OutboundDomainStrategy,
    resolver: Option<&dyn OutboundDnsResolver>,
) -> std::io::Result<TcpStream> {
    let dest = format_vless_destination(destination);
    debug!(
        %dest,
        domain_strategy = ?strategy,
        uses_dns_engine = strategy.uses_dns_engine(),
        "freedom outbound connect started"
    );
    let connect_started = Instant::now();

    let stream = match destination {
        VlessDestination::Ip(addr, port) => {
            trace!(%dest, "freedom outbound bypasses DNS engine for literal IP");
            TcpStream::connect((*addr, *port)).await?
        }
        VlessDestination::Domain(domain, port) => {
            if strategy.uses_dns_engine() {
                let resolver = resolver.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "DNS engine resolver required for UseIP/UseIPv4/UseIPv6 outbound strategy",
                    )
                })?;
                let ips = resolver
                    .lookup_ip(domain, strategy.to_query_strategy())
                    .await
                    .map_err(dns_error_to_io)?;
                let record_count = ips.len();
                let ip = ips.into_iter().next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("DNS returned no records for {domain}"),
                    )
                })?;
                debug!(
                    %dest,
                    resolved_ip = %ip,
                    record_count,
                    domain_strategy = ?strategy,
                    "freedom outbound resolved domain via DnsEngine"
                );
                TcpStream::connect((ip, *port)).await?
            } else if strategy.uses_system_resolver() {
                trace!(
                    %dest,
                    domain_strategy = ?strategy,
                    "freedom outbound using explicit system resolver connect path"
                );
                TcpStream::connect((domain.as_str(), *port)).await?
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("unsupported outbound domain strategy: {strategy:?}"),
                ));
            }
        }
    };

    debug!(
        %dest,
        latency_ms = connect_started.elapsed().as_millis(),
        "freedom outbound connected"
    );
    Ok(stream)
}

pub async fn forward_tcp_initial_payload(
    outbound: &mut TcpStream,
    initial_payload: &[u8],
) -> std::io::Result<()> {
    if initial_payload.is_empty() {
        return Ok(());
    }

    outbound.write_all(initial_payload).await
}

pub async fn relay_tcp_bidirectional<S>(
    mut inbound: S,
    outbound: &mut TcpStream,
    stats: Option<&crate::stats::StatsSession>,
) -> std::io::Result<(u64, u64)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (inbound_to_outbound, outbound_to_inbound) =
        copy_bidirectional(&mut inbound, outbound).await?;

    if let Some(stats) = stats {
        stats.record_relay(inbound_to_outbound, outbound_to_inbound);
    }

    debug!(
        inbound_to_outbound,
        outbound_to_inbound, "freedom relay ended"
    );

    Ok((inbound_to_outbound, outbound_to_inbound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsError;
    use crate::dns::QueryStrategy;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockResolver {
        v4: Vec<IpAddr>,
        v6: Vec<IpAddr>,
        lookups: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl OutboundDnsResolver for MockResolver {
        async fn lookup_ip(
            &self,
            _domain: &str,
            strategy: QueryStrategy,
        ) -> Result<Vec<IpAddr>, DnsError> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            match strategy {
                QueryStrategy::UseIPv6 => Ok(self.v6.clone()),
                QueryStrategy::UseIPv4 | QueryStrategy::UseIP | QueryStrategy::UseSystem => {
                    Ok(self.v4.clone())
                }
            }
        }
    }

    #[test]
    fn format_vless_destination_ipv4() {
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert_eq!(format_vless_destination(&destination), "192.168.1.1:8080");
    }

    #[test]
    fn format_vless_destination_ipv6() {
        let destination = VlessDestination::Ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        assert_eq!(format_vless_destination(&destination), "[2001:db8::1]:443");
    }

    #[test]
    fn format_vless_destination_domain() {
        let destination = VlessDestination::Domain("example.com".to_string(), 443);
        assert_eq!(format_vless_destination(&destination), "example.com:443");
    }

    #[test]
    fn freedom_source_does_not_use_system_dns_helpers() {
        let src = include_str!("freedom.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !code.contains("lookup_host("),
            "freedom outbound must not call tokio::net::lookup_host"
        );
        assert!(
            !code.contains("ToSocketAddrs"),
            "freedom outbound must not use ToSocketAddrs"
        );
    }

    #[tokio::test]
    async fn ip_destination_bypasses_dns_engine() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let resolver = MockResolver {
            v4: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            v6: Vec::new(),
            lookups: AtomicUsize::new(0),
        };
        let destination = VlessDestination::Ip(addr.ip(), addr.port());
        tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });
        connect_tcp_destination_with_resolver(
            &destination,
            OutboundDomainStrategy::UseIp,
            Some(&resolver),
        )
        .await
        .unwrap();
        assert_eq!(resolver.lookups.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn use_ipv4_resolves_via_dns_engine_mock() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let resolver = MockResolver {
            v4: vec![addr.ip()],
            v6: Vec::new(),
            lookups: AtomicUsize::new(0),
        };
        let destination = VlessDestination::Domain("example.com".to_string(), addr.port());
        tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });
        connect_tcp_destination_with_resolver(
            &destination,
            OutboundDomainStrategy::UseIpv4,
            Some(&resolver),
        )
        .await
        .unwrap();
        assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn use_ipv6_chooses_aaaa_from_mock() {
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let resolver = MockResolver {
            v4: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            v6: vec![addr.ip()],
            lookups: AtomicUsize::new(0),
        };
        let destination = VlessDestination::Domain("example.com".to_string(), addr.port());
        tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });
        connect_tcp_destination_with_resolver(
            &destination,
            OutboundDomainStrategy::UseIpv6,
            Some(&resolver),
        )
        .await
        .unwrap();
        assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_dns_records_returns_error() {
        let resolver = MockResolver {
            v4: Vec::new(),
            v6: Vec::new(),
            lookups: AtomicUsize::new(0),
        };
        let destination = VlessDestination::Domain("missing.example".to_string(), 443);
        let err = connect_tcp_destination_with_resolver(
            &destination,
            OutboundDomainStrategy::UseIp,
            Some(&resolver),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
