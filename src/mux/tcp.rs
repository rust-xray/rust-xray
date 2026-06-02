use std::io::{Error, ErrorKind};
use std::time::Instant;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, warn};

use crate::dns::DnsEngineOptions;
use crate::mux::encoder::mux_udp_send_close_after_response_enabled;
use crate::mux::encoder::{encode_mux_end, encode_mux_udp_packet};
use crate::mux::frame::{MuxCommand, MuxFrame, MuxSessionTrace, MAX_MUX_DATA_LEN};
use crate::mux::state::{mux_actions, MuxFrameActions, MuxOutTx};
use crate::mux::udp_dns::udp_socket_addr_without_dns;
use crate::outbound::freedom::{connect_tcp_destination, format_vless_destination};

pub(crate) async fn handle_mux_tcp_command(
    active: &mut Option<(u16, TcpStream)>,
    frame: MuxFrame,
) -> std::io::Result<MuxFrameActions> {
    let id = frame.mux_id;
    match frame.command {
        MuxCommand::Tcp {
            destination,
            initial_payload,
        } => {
            if active.is_some() {
                warn!(
                    mux_id = id,
                    "parallel mux substreams are not implemented yet"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            let destination_label = format_vless_destination(&destination.destination);
            debug!(
                mux_id = id,
                network = destination.network.as_str(),
                destination = %destination_label,
                "mux substream destination parsed"
            );
            let mut outbound = connect_tcp_destination(&destination.destination).await?;
            if !initial_payload.is_empty() {
                outbound.write_all(&initial_payload).await?;
            }
            debug!(mux_id = id, destination = %destination_label, "mux substream opened");
            *active = Some((id, outbound));
        }
        MuxCommand::Data { payload } => {
            let Some((active_id, outbound)) = active.as_mut() else {
                warn!(mux_id = id, "mux keep frame without active substream");
                return Ok(mux_actions(Vec::new()));
            };
            if *active_id != id {
                warn!(
                    mux_id = id,
                    active_mux_id = *active_id,
                    "mux frame for inactive substream"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            if !payload.is_empty() {
                outbound.write_all(&payload).await?;
            }
        }
        MuxCommand::Close { payload } => {
            let Some((active_id, mut outbound)) = active.take() else {
                debug!(mux_id = id, "mux end frame without active substream");
                return Ok(mux_actions(Vec::new()));
            };
            if active_id != id {
                warn!(
                    mux_id = id,
                    active_mux_id = active_id,
                    "mux end for inactive substream"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            if !payload.is_empty() {
                outbound.write_all(&payload).await?;
            }
            let _ = outbound.shutdown().await;
            debug!(mux_id = id, "mux substream close");
        }
        MuxCommand::KeepAlive => {
            debug!(mux_id = id, "mux keepalive");
        }
        MuxCommand::Udp { .. } => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "udp mux command must be handled by udp_dns module",
            ));
        }
    }
    Ok(mux_actions(Vec::new()))
}

pub(crate) fn spawn_generic_udp_relay(
    id: u16,
    destination: crate::vless::protocol::VlessDestination,
    data: Vec<u8>,
    trace: Option<MuxSessionTrace>,
    received_at: Instant,
    udp_tx: MuxOutTx,
) {
    tokio::spawn(async move {
        let destination_label = format_vless_destination(&destination);
        let actions =
            match relay_generic_udp_packet(id, &destination, &data, trace, received_at).await {
                Ok(actions) => actions,
                Err(err) => {
                    warn!(
                        mux_id = id,
                        destination = %destination_label,
                        error = %err,
                        "mux generic udp relay error; closing substream"
                    );
                    mux_actions(vec![encode_mux_end(id)])
                }
            };
        if udp_tx.send(actions).is_err() {
            debug!(
                mux_id = id,
                destination = %destination_label,
                "mux generic udp response dropped because session writer is closed"
            );
        }
    });
}

async fn relay_generic_udp_packet(
    id: u16,
    destination: &crate::vless::protocol::VlessDestination,
    data: &[u8],
    trace: Option<MuxSessionTrace>,
    received_at: Instant,
) -> std::io::Result<MuxFrameActions> {
    let destination_label = format_vless_destination(destination);
    let Some(target) = udp_socket_addr_without_dns(destination) else {
        warn!(
            mux_id = id,
            network = "udp",
            destination = %destination_label,
            payload_len = data.len(),
            "UDP mux domain destination requires resolver support; closing substream"
        );
        return Ok(mux_actions(vec![encode_mux_end(id)]));
    };

    let timeout = DnsEngineOptions::from_env().mux_udp_dns_timeout;
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(target).await?;
    socket.send(data).await?;
    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %target,
        destination = %destination_label,
        payload_len = data.len(),
        timeout_ms = timeout.as_millis(),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux generic udp packet sent"
    );

    let mut buf = vec![0u8; MAX_MUX_DATA_LEN];
    let read = match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(read)) => read,
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            debug!(
                conn_id = trace.map(|trace| trace.conn_id),
                mux_id = id,
                %target,
                destination = %destination_label,
                timeout_ms = timeout.as_millis(),
                total_latency_ms = received_at.elapsed().as_millis(),
                elapsed_ms_since_conn_start =
                    trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                "mux generic udp response timeout"
            );
            return Ok(mux_actions(vec![encode_mux_end(id)]));
        }
    };
    buf.truncate(read);
    let frame = encode_mux_udp_packet(id, destination, &buf)?;
    let close_frame = mux_udp_send_close_after_response_enabled().then(|| encode_mux_end(id));
    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %target,
        destination = %destination_label,
        response_len = buf.len(),
        total_latency_ms = received_at.elapsed().as_millis(),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux generic udp response frame encoded"
    );
    let mut frames = vec![frame];
    if let Some(close_frame) = close_frame {
        frames.push(close_frame);
    }
    Ok(mux_actions(frames))
}

#[cfg(test)]
#[path = "../../tests/unit/mux/tcp.rs"]
mod tests;
