use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::task::JoinSet;
use tokio::time;
use tracing::{debug, warn};

use crate::dns::config::{DnsConfig, DnsServerTransport};
use crate::dns::error::DnsError;
use crate::dns::options::MuxDnsUpstreamMode;
use crate::dns::packet::dns_query_id;
use crate::dns::udp_transport::{socket_addr_for_server, UdpDnsTransport};

const MUX_EMERGENCY_DNS: &[(&str, u16)] = &[("8.8.8.8", 53), ("9.9.9.9", 53)];

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

    for server in &config.servers {
        if server.transport != DnsServerTransport::Udp {
            continue;
        }
        if let Ok(addr) = socket_addr_for_server(&server.host, server.port) {
            push(addr, server.original.clone());
        }
    }

    for (host, port) in MUX_EMERGENCY_DNS {
        if let Ok(addr) = socket_addr_for_server(host, *port) {
            push(addr, format!("mux-emergency:{host}:{port}"));
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

fn candidate_timeout(remaining: Duration, per_candidate_timeout: Duration) -> Duration {
    if remaining.is_zero() {
        Duration::ZERO
    } else {
        remaining.min(per_candidate_timeout)
    }
}

pub async fn execute_mux_udp_upstream(
    udp: &UdpDnsTransport,
    query: &[u8],
    candidates: &[MuxDnsCandidate],
    mode: MuxDnsUpstreamMode,
    per_candidate_timeout: Duration,
    total_timeout: Duration,
) -> Result<(Vec<u8>, String), DnsError> {
    debug!(
        candidates = candidates.len(),
        mode = mode.as_str(),
        timeout_ms = per_candidate_timeout.as_millis(),
        total_timeout_ms = total_timeout.as_millis(),
        "mux dns upstream candidates"
    );

    if candidates.is_empty() {
        return Err(DnsError::Timeout);
    }

    match mode {
        MuxDnsUpstreamMode::DestinationOnly | MuxDnsUpstreamMode::DestinationThenConfigFallback => {
            execute_mux_fallback(udp, query, candidates, per_candidate_timeout, total_timeout).await
        }
        MuxDnsUpstreamMode::RaceDestinationAndConfig => {
            execute_mux_race(udp, query, candidates, per_candidate_timeout, total_timeout).await
        }
    }
}

async fn execute_mux_fallback(
    udp: &UdpDnsTransport,
    query: &[u8],
    candidates: &[MuxDnsCandidate],
    per_candidate_timeout: Duration,
    total_timeout: Duration,
) -> Result<(Vec<u8>, String), DnsError> {
    let deadline = Instant::now() + total_timeout;
    let mut last_err = DnsError::Timeout;

    for (index, candidate) in candidates.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            debug!(
                total_timeout_ms = total_timeout.as_millis(),
                "mux dns upstream fallback total timeout"
            );
            return Err(DnsError::Timeout);
        }

        let actual_timeout = candidate_timeout(remaining, per_candidate_timeout);
        debug!(
            server = %candidate.addr,
            server_id = %candidate.server_id,
            timeout_ms = actual_timeout.as_millis(),
            remaining_ms = remaining.as_millis(),
            "mux dns upstream try"
        );

        let candidate_started = Instant::now();
        match udp.query_at(candidate.addr, query, actual_timeout).await {
            Ok(response) => {
                validate_dns_response_id(query, &response)?;
                return Ok((response, candidate.server_id.clone()));
            }
            Err(err @ DnsError::MalformedQuery) => return Err(err),
            Err(err) => {
                if matches!(err, DnsError::Timeout) {
                    debug!(
                        server = %candidate.addr,
                        server_id = %candidate.server_id,
                        latency_ms = candidate_started.elapsed().as_millis(),
                        "mux dns upstream candidate timeout"
                    );
                }
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
    per_candidate_timeout: Duration,
    total_timeout: Duration,
) -> Result<(Vec<u8>, String), DnsError> {
    debug!(
        candidates = candidates.len(),
        total_timeout_ms = total_timeout.as_millis(),
        "mux dns upstream race started"
    );

    let race_started = Instant::now();
    let deadline = race_started + total_timeout;
    let mut tasks = JoinSet::new();

    for candidate in candidates {
        let udp = udp.clone();
        let query = query.to_vec();
        let server_id = candidate.server_id.clone();
        let addr = candidate.addr;
        let candidate_timeout = per_candidate_timeout;
        debug!(
            server = %addr,
            server_id = %server_id,
            timeout_ms = candidate_timeout.as_millis(),
            "mux dns upstream candidate sent"
        );
        tasks.spawn(async move {
            let started = Instant::now();
            let result = udp.query_at(addr, &query, candidate_timeout).await;
            (server_id, addr, result, started.elapsed())
        });
    }

    let mut last_err = DnsError::Timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            tasks.abort_all();
            debug!(
                total_timeout_ms = total_timeout.as_millis(),
                elapsed_ms = race_started.elapsed().as_millis(),
                "mux dns upstream race total timeout"
            );
            return Err(DnsError::Timeout);
        }

        match time::timeout(remaining, tasks.join_next()).await {
            Ok(Some(Ok((server_id, addr, Ok(response), latency)))) => {
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
                        debug!(
                            server = %addr,
                            server_id = %server_id,
                            "mux dns upstream race ignored response with mismatched transaction id"
                        );
                        last_err = err;
                    }
                }
            }
            Ok(Some(Ok((server_id, addr, Err(err), latency)))) => {
                if matches!(err, DnsError::Timeout) {
                    debug!(
                        server = %addr,
                        server_id = %server_id,
                        latency_ms = latency.as_millis(),
                        "mux dns upstream candidate timeout"
                    );
                } else {
                    debug!(
                        server = %addr,
                        server_id = %server_id,
                        error = %err,
                        latency_ms = latency.as_millis(),
                        "mux dns upstream race candidate failed"
                    );
                }
                last_err = err;
            }
            Ok(Some(Err(_))) => last_err = DnsError::Upstream,
            Ok(None) => break,
            Err(_) => {
                tasks.abort_all();
                debug!(
                    total_timeout_ms = total_timeout.as_millis(),
                    elapsed_ms = race_started.elapsed().as_millis(),
                    "mux dns upstream race total timeout"
                );
                return Err(DnsError::Timeout);
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

#[cfg(test)]
#[path = "../../tests/unit/dns/mux_upstream.rs"]
mod tests;
