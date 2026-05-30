use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::dns::config::{DnsConfig, DnsServerTransport};
use crate::dns::error::DnsError;
use crate::dns::options::MuxDnsUpstreamMode;
use crate::dns::packet::dns_query_id;
use crate::dns::udp_transport::{socket_addr_for_server, UdpDnsTransport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxDnsCandidate {
    pub addr: SocketAddr,
    pub server_id: String,
}

pub fn build_mux_udp_candidates(
    destination: SocketAddr,
    config: &DnsConfig,
    mode: MuxDnsUpstreamMode,
) -> Vec<MuxDnsCandidate> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    let mut push = |addr: SocketAddr, server_id: String| {
        if seen.insert(addr) {
            candidates.push(MuxDnsCandidate { addr, server_id });
        }
    };

    push(destination, format!("mux:{destination}"));

    if mode == MuxDnsUpstreamMode::DestinationOnly {
        return candidates;
    }

    let mut has_config_udp = false;
    for server in &config.servers {
        if server.transport != DnsServerTransport::Udp {
            continue;
        }
        match socket_addr_for_server(&server.host, server.port) {
            Ok(addr) => {
                has_config_udp = true;
                push(addr, server.original.clone());
            }
            Err(_) => continue,
        }
    }

    if !has_config_udp {
        for (host, port) in [("1.1.1.1", 53u16), ("8.8.8.8", 53)] {
            if let Ok(addr) = socket_addr_for_server(host, port) {
                push(addr, format!("mux-default:{host}:{port}"));
            }
        }
    }

    candidates
}

fn validate_dns_response_id(query: &[u8], response: &[u8]) -> Result<(), DnsError> {
    let expected = dns_query_id(query).ok_or(DnsError::MalformedQuery)?;
    let actual = dns_query_id(response).ok_or(DnsError::MalformedQuery)?;
    if expected != actual {
        return Err(DnsError::MalformedQuery);
    }
    Ok(())
}

pub async fn execute_mux_udp_upstream(
    udp: &UdpDnsTransport,
    query: &[u8],
    candidates: &[MuxDnsCandidate],
    mode: MuxDnsUpstreamMode,
    timeout: Duration,
) -> Result<(Vec<u8>, String), DnsError> {
    debug!(
        candidates = candidates.len(),
        mode = mode.as_str(),
        "mux dns upstream candidates"
    );

    if candidates.is_empty() {
        return Err(DnsError::Timeout);
    }

    match mode {
        MuxDnsUpstreamMode::DestinationOnly => {
            execute_mux_fallback(udp, query, candidates, timeout).await
        }
        MuxDnsUpstreamMode::DestinationThenConfigFallback => {
            execute_mux_fallback(udp, query, candidates, timeout).await
        }
        MuxDnsUpstreamMode::RaceDestinationAndConfig => {
            execute_mux_race(udp, query, candidates, timeout).await
        }
    }
}

async fn execute_mux_fallback(
    udp: &UdpDnsTransport,
    query: &[u8],
    candidates: &[MuxDnsCandidate],
    timeout: Duration,
) -> Result<(Vec<u8>, String), DnsError> {
    let mut last_err = DnsError::Timeout;
    for (index, candidate) in candidates.iter().enumerate() {
        debug!(
            server = %candidate.addr,
            server_id = %candidate.server_id,
            "mux dns upstream try"
        );
        match udp.query_at(candidate.addr, query, timeout).await {
            Ok(response) => {
                validate_dns_response_id(query, &response)?;
                return Ok((response, candidate.server_id.clone()));
            }
            Err(err @ DnsError::MalformedQuery) => return Err(err),
            Err(err) => {
                if index + 1 < candidates.len() {
                    if matches!(err, DnsError::Timeout) {
                        debug!(
                            server = %candidate.addr,
                            server_id = %candidate.server_id,
                            "mux dns upstream fallback after timeout"
                        );
                    } else {
                        debug!(
                            server = %candidate.addr,
                            server_id = %candidate.server_id,
                            error = %err,
                            "mux dns upstream fallback after failure"
                        );
                    }
                }
                last_err = err;
            }
        }
    }
    warn!(
        candidates = candidates.len(),
        error = %last_err,
        "all mux dns upstreams failed"
    );
    Err(last_err)
}

async fn execute_mux_race(
    udp: &UdpDnsTransport,
    query: &[u8],
    candidates: &[MuxDnsCandidate],
    timeout: Duration,
) -> Result<(Vec<u8>, String), DnsError> {
    let mut tasks = JoinSet::new();
    for candidate in candidates {
        let udp = udp.clone();
        let query = query.to_vec();
        let server_id = candidate.server_id.clone();
        let addr = candidate.addr;
        debug!(
            server = %addr,
            server_id = %server_id,
            "mux dns upstream try"
        );
        tasks.spawn(async move {
            let started = Instant::now();
            let result = udp.query_at(addr, &query, timeout).await;
            (server_id, addr, result, started.elapsed())
        });
    }

    let mut last_err = DnsError::Timeout;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((server_id, addr, Ok(response), latency)) => {
                match validate_dns_response_id(query, &response) {
                    Ok(()) => {
                        tasks.abort_all();
                        debug!(
                            server = %addr,
                            server_id = %server_id,
                            latency_ms = latency.as_millis(),
                            "mux dns upstream winner"
                        );
                        return Ok((response, server_id));
                    }
                    Err(err) => {
                        last_err = err;
                    }
                }
            }
            Ok((server_id, addr, Err(err), _latency)) => {
                debug!(
                    server = %addr,
                    server_id = %server_id,
                    error = %err,
                    "mux dns upstream race candidate failed"
                );
                last_err = err;
            }
            Err(_) => last_err = DnsError::Upstream,
        }
    }

    warn!(
        candidates = candidates.len(),
        error = %last_err,
        "all mux dns upstreams failed"
    );
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::config::parse_dns_server;

    #[test]
    fn deduplicates_destination_when_same_as_config_server() {
        let destination = SocketAddr::from(([1, 1, 1, 1], 53));
        let config = DnsConfig {
            servers: vec![parse_dns_server("1.1.1.1").unwrap()],
            query_strategy: Default::default(),
            disable_cache: false,
            extra: Default::default(),
        };
        let candidates = build_mux_udp_candidates(
            destination,
            &config,
            MuxDnsUpstreamMode::DestinationThenConfigFallback,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].addr, destination);
    }

    #[test]
    fn destination_only_returns_single_candidate() {
        let destination = SocketAddr::from(([1, 1, 1, 1], 53));
        let config = DnsConfig {
            servers: vec![parse_dns_server("8.8.8.8").unwrap()],
            query_strategy: Default::default(),
            disable_cache: false,
            extra: Default::default(),
        };
        let candidates =
            build_mux_udp_candidates(destination, &config, MuxDnsUpstreamMode::DestinationOnly);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].server_id, "mux:1.1.1.1:53");
    }

    #[test]
    fn fallback_includes_destination_and_config_udp_servers() {
        let destination = SocketAddr::from(([1, 1, 1, 1], 53));
        let config = DnsConfig {
            servers: vec![parse_dns_server("8.8.8.8").unwrap()],
            query_strategy: Default::default(),
            disable_cache: false,
            extra: Default::default(),
        };
        let candidates = build_mux_udp_candidates(
            destination,
            &config,
            MuxDnsUpstreamMode::DestinationThenConfigFallback,
        );
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].addr, destination);
        assert_eq!(candidates[1].server_id, "8.8.8.8");
    }
}
