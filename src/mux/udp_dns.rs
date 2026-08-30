use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::dns::packet::dns_query_id;
use crate::dns::{DnsEngine, DnsEngineOptions, DnsError, DnsQueryResponse, DnsQueryTrace};
use crate::mux::encoder::{
    append_mux_udp_dns_close, encode_mux_end, encode_mux_udp_packet,
    mux_udp_send_close_after_response_enabled,
};
use crate::mux::frame::{
    MuxSessionTrace, MuxUdpDnsLatencyTrace, ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE,
};
use crate::mux::state::{mux_actions, mux_dns_actions, MuxFrameActions, MuxOutTx};
use crate::outbound::freedom::format_vless_destination;
use crate::vless::protocol::VlessDestination;

pub(crate) fn is_mux_udp_dns_request(destination: &VlessDestination, data: &[u8]) -> bool {
    if destination_port(destination) == 53 {
        return true;
    }
    is_test_mux_dns_request(data)
}

pub(crate) async fn handle_udp_mux_dns_new(
    id: u16,
    destination: VlessDestination,
    data: Vec<u8>,
    dns: &Arc<DnsEngine>,
    trace: Option<MuxSessionTrace>,
    udp_tx: MuxOutTx,
) -> std::io::Result<MuxFrameActions> {
    let received_at = Instant::now();
    let destination_label = format_vless_destination(&destination);
    let target = udp_socket_addr_without_dns(&destination);
    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %destination_label,
        destination = ?target,
        payload_len = data.len(),
        dns_id = dns_query_id(&data),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux udp dns received"
    );

    let Some(target) = target else {
        warn!(
            mux_id = id,
            network = "udp",
            destination = %destination_label,
            payload_len = data.len(),
            "UDP mux DNS domain destination requires resolver support; closing substream"
        );
        return Ok(mux_actions(vec![append_mux_udp_dns_close(id, None)]));
    };

    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %target,
        destination = %destination_label,
        payload_len = data.len(),
        engine_elapsed_ms = received_at.elapsed().as_millis(),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux udp dns engine query started"
    );
    let dns_trace = trace.map(|trace| DnsQueryTrace {
        conn_id: trace.conn_id,
        mux_id: Some(id),
        conn_started: trace.conn_started,
        dns_started: received_at,
    });
    match resolve_mux_udp_dns_packet(dns, id, target, &data, dns_trace).await {
        Ok(response) => {
            let encode_started = Instant::now();
            let frame = encode_mux_udp_packet(id, &destination, &response.raw_response)?;
            debug!(
                conn_id = trace.map(|trace| trace.conn_id),
                mux_id = id,
                destination = %destination_label,
                response_len = response.raw_response.len(),
                cache_hit = response.cached,
                encode_ms = encode_started.elapsed().as_millis(),
                engine_latency_ms = response.latency.as_millis(),
                elapsed_ms = received_at.elapsed().as_millis(),
                elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                "mux udp dns response frame encoded"
            );
            debug!(
                conn_id = trace.map(|trace| trace.conn_id),
                mux_id = id,
                destination = %destination_label,
                response_len = response.raw_response.len(),
                cache_hit = response.cached,
                latency_ms = received_at.elapsed().as_millis(),
                elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                "mux udp dns engine response sent"
            );
            let close_frame = mux_udp_send_close_after_response_enabled().then(|| {
                debug!(
                    conn_id = trace.map(|trace| trace.conn_id),
                    mux_id = id,
                    destination = %destination_label,
                    env = ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE,
                    "mux udp dns close after response enabled"
                );
                encode_mux_end(id)
            });
            Ok(mux_dns_actions(
                frame,
                close_frame,
                MuxUdpDnsLatencyTrace {
                    conn_id: trace.map(|trace| trace.conn_id),
                    conn_started: trace.map(|trace| trace.conn_started),
                    mux_id: id,
                    received_at,
                },
            ))
        }
        Err(err) if mux_dns_non_fatal_error(&err) => {
            if matches!(err, DnsError::Timeout) {
                debug!(
                    conn_id = trace.map(|trace| trace.conn_id),
                    mux_id = id,
                    destination = %destination_label,
                    error = %err,
                    total_latency_ms = received_at.elapsed().as_millis(),
                    elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                    "mux udp dns engine timeout"
                );
            } else {
                warn!(
                    mux_id = id,
                    destination = %destination_label,
                    error = %err,
                    total_latency_ms = received_at.elapsed().as_millis(),
                    "mux udp dns engine error"
                );
            }
            Ok(mux_actions(vec![append_mux_udp_dns_close(id, None)]))
        }
        Err(err) => Err(err.into()),
    }
}

fn destination_port(destination: &VlessDestination) -> u16 {
    match destination {
        VlessDestination::Ip(_, port) | VlessDestination::Domain(_, port) => *port,
    }
}

pub(crate) fn mux_dns_legacy_direct_enabled() -> bool {
    crate::dns::options::mux_dns_legacy_direct_enabled()
}

fn mux_dns_non_fatal_error(err: &DnsError) -> bool {
    matches!(
        err,
        DnsError::Timeout
            | DnsError::MalformedQuery
            | DnsError::Upstream
            | DnsError::ServerFailed
            | DnsError::UnsupportedTransport(_)
            | DnsError::Io(_, _)
    )
}

async fn resolve_mux_udp_dns_packet(
    dns: &Arc<DnsEngine>,
    mux_id: u16,
    target: SocketAddr,
    data: &[u8],
    trace: Option<DnsQueryTrace>,
) -> Result<DnsQueryResponse, DnsError> {
    if mux_dns_legacy_direct_enabled() {
        warn!(
            mux_id,
            %target,
            payload_len = data.len(),
            "legacy mux direct DNS path enabled; DNS engine bypassed"
        );
        let timeout = DnsEngineOptions::from_env().mux_udp_dns_timeout;
        let raw = relay_mux_udp_dns_legacy_direct(target, data, timeout).await?;
        return Ok(DnsQueryResponse {
            raw_response: raw,
            server: target,
            cached: false,
            latency: Duration::ZERO,
        });
    }
    dns.resolve_mux_udp_dns_with_trace(mux_id, target, data, trace)
        .await
}

async fn relay_mux_udp_dns_legacy_direct(
    target: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, DnsError> {
    let expected_id = dns_query_id(query).ok_or(DnsError::MalformedQuery)?;
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|err| DnsError::Io(err.kind(), err.to_string()))?;
    socket
        .send_to(query, target)
        .await
        .map_err(|err| DnsError::Io(err.kind(), err.to_string()))?;
    let mut buf = vec![0u8; 512];
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DnsError::Timeout);
        }
        let recv = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|err| DnsError::Io(err.kind(), err.to_string()))?;
        let (len, _) = recv;
        if dns_query_id(&buf[..len]) == Some(expected_id) {
            return Ok(buf[..len].to_vec());
        }
    }
}

#[cfg(test)]
fn is_test_mux_dns_request(data: &[u8]) -> bool {
    crate::dns::packet::parse_dns_question_key(data, "mux-test").is_ok()
}

#[cfg(not(test))]
fn is_test_mux_dns_request(_data: &[u8]) -> bool {
    false
}

pub(crate) fn udp_socket_addr_without_dns(destination: &VlessDestination) -> Option<SocketAddr> {
    match destination {
        VlessDestination::Ip(ip, port) => Some(SocketAddr::new(*ip, *port)),
        VlessDestination::Domain(_, _) => None,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/mux/udp_dns.rs"]
mod tests;
