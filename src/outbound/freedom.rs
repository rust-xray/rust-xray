use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use crate::outbound::domain_strategy::OutboundDomainStrategy;
use crate::outbound::resolver::{dns_error_to_io, OutboundDnsResolver};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::vless::protocol::VlessDestination;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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

pub async fn resolve_udp_target(
    destination: &VlessDestination,
    runtime: Arc<OutboundConnectRuntime>,
) -> std::io::Result<SocketAddr> {
    let strategy = runtime.domain_strategy;
    match destination {
        VlessDestination::Ip(addr, port) => Ok(SocketAddr::new(*addr, *port)),
        VlessDestination::Domain(domain, port) => {
            if strategy.uses_dns_engine() {
                let resolver = runtime.dns.as_ref();
                let ips = resolver
                    .lookup_ip(domain, strategy.to_query_strategy())
                    .await
                    .map_err(dns_error_to_io)?;
                let ip = ips.into_iter().next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("DNS returned no records for {domain}"),
                    )
                })?;
                debug!(
                    domain = %domain,
                    resolved_ip = %ip,
                    port,
                    domain_strategy = ?strategy,
                    "freedom outbound resolved UDP domain via DnsEngine"
                );
                Ok(SocketAddr::new(ip, *port))
            } else if strategy.uses_system_resolver() {
                trace!(
                    domain = %domain,
                    port,
                    domain_strategy = ?strategy,
                    "freedom outbound UDP using system resolver lookup"
                );
                let mut addrs = tokio::net::lookup_host((domain.as_str(), *port)).await?;
                addrs.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("system resolver returned no records for {domain}:{port}"),
                    )
                })
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("unsupported outbound domain strategy for UDP: {strategy:?}"),
                ))
            }
        }
    }
}

pub async fn connect_udp_destination_with_runtime(
    destination: &VlessDestination,
    runtime: Arc<OutboundConnectRuntime>,
) -> std::io::Result<(UdpSocket, SocketAddr)> {
    let target = resolve_udp_target(destination, Arc::clone(&runtime)).await?;
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    debug!(%target, "freedom outbound UDP socket bound");
    Ok((socket, target))
}

pub async fn connect_udp_destination(
    destination: &VlessDestination,
) -> std::io::Result<(UdpSocket, SocketAddr)> {
    connect_udp_destination_with_runtime(destination, OutboundConnectRuntime::shared()).await
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
#[path = "../../tests/unit/outbound/freedom.rs"]
mod tests;
