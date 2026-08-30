use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::dns::DnsEngine;
use crate::mux::encoder::encode_mux_end;
use crate::mux::frame::{is_xudp_global_id, MuxCommand, MuxFrame, MuxSessionTrace, MuxStatus};
use crate::mux::packet_udp::MuxUdpSessionManager;
use crate::mux::parser::read_mux_frame;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::state::{mux_actions, write_mux_out_frames, MuxFrameActions, MuxOutTx};
use crate::mux::tcp;
use crate::mux::udp_dns;
use crate::mux::xudp::XudpMuxSessions;

pub async fn handle_mux_cool_inbound<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns_and_trace(stream, DnsEngine::shared(), None, None).await
}

pub async fn handle_mux_cool_inbound_traced<S>(
    stream: &mut S,
    trace: MuxSessionTrace,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns_and_trace(stream, DnsEngine::shared(), Some(trace), None).await
}

pub async fn handle_mux_cool_inbound_with_dns<S>(
    stream: &mut S,
    dns: Arc<DnsEngine>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns_and_trace(stream, dns, None, None).await
}

pub async fn handle_mux_cool_inbound_with_env<S>(
    stream: &mut S,
    dns: Arc<DnsEngine>,
    trace: Option<MuxSessionTrace>,
    route_env: Option<MuxRouteEnv>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns_and_trace(stream, dns, trace, route_env).await
}

pub async fn handle_mux_cool_inbound_with_dns_and_trace<S>(
    mut stream: &mut S,
    dns: Arc<DnsEngine>,
    trace: Option<MuxSessionTrace>,
    route_env: Option<MuxRouteEnv>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session_started = Instant::now();
    info!(
        conn_id = trace.map(|trace| trace.conn_id),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux session started"
    );
    let mut active: Option<(u16, TcpStream)> = None;
    let mut buf = [0u8; 8192];
    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<MuxFrameActions>();
    let xudp_sessions = Arc::new(XudpMuxSessions::new());
    let packet_sessions = Arc::new(MuxUdpSessionManager::new());

    let packet_sessions = Arc::new(MuxUdpSessionManager::new());

    loop {
        if let Some((id, outbound)) = active.as_mut() {
            tokio::select! {
                frame = read_mux_frame(&mut stream) => {
                    let frame = frame?;
                    debug!(
                        conn_id = trace.map(|trace| trace.conn_id),
                        mux_id = frame.id(),
                        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                        "first/next mux frame received"
                    );
                    let actions = handle_client_frame(
                        &mut active,
                        &dns,
                        frame,
                        trace,
                        udp_tx.clone(),
                        route_env.as_ref(),
                        Arc::clone(&xudp_sessions),
                        Arc::clone(&packet_sessions),
                    )
                    .await?;
                    write_mux_out_frames(&mut stream, &actions).await?;
                }
                Some(actions) = udp_rx.recv() => {
                    write_mux_out_frames(&mut stream, &actions).await?;
                }
                read = outbound.read(&mut buf) => {
                    let read = read?;
                    if read == 0 {
                        write_mux_out_frames(
                            &mut stream,
                            &mux_actions(vec![encode_mux_end(*id)]),
                        )
                        .await?;
                        debug!(mux_id = *id, "mux substream relay completed");
                        active = None;
                    } else {
                        let frame = crate::mux::encoder::encode_mux_keep_data(*id, &buf[..read])?;
                        write_mux_out_frames(&mut stream, &mux_actions(vec![frame])).await?;
                    }
                }
            }
        } else {
            debug!(
                conn_id = trace.map(|trace| trace.conn_id),
                elapsed_ms_since_conn_start =
                    trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                "waiting next mux frame"
            );
            tokio::select! {
                frame = read_mux_frame(&mut stream) => {
                    match frame {
                        Ok(frame) => {
                            debug!(
                                conn_id = trace.map(|trace| trace.conn_id),
                                mux_id = frame.id(),
                                elapsed_ms_since_conn_start =
                                    trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                                "first/next mux frame received"
                            );
                            let actions = handle_client_frame(
                                &mut active,
                                &dns,
                                frame,
                                trace,
                                udp_tx.clone(),
                                route_env.as_ref(),
                                Arc::clone(&xudp_sessions),
                                Arc::clone(&packet_sessions),
                            )
                            .await?;
                            write_mux_out_frames(&mut stream, &actions).await?;
                        }
                        Err(err) if err.kind() == ErrorKind::UnexpectedEof => break,
                        Err(err) => return Err(err),
                    }
                }
                Some(actions) = udp_rx.recv() => {
                    write_mux_out_frames(&mut stream, &actions).await?;
                }
            }
        }
    }

    packet_sessions.shutdown_all().await;

    debug!(
        duration_ms = session_started.elapsed().as_millis(),
        conn_id = trace.map(|trace| trace.conn_id),
        "mux session completed"
    );
    info!("mux session completed");
    Ok(())
}

async fn handle_client_frame(
    active: &mut Option<(u16, TcpStream)>,
    dns: &Arc<DnsEngine>,
    frame: MuxFrame,
    trace: Option<MuxSessionTrace>,
    udp_tx: MuxOutTx,
    route_env: Option<&MuxRouteEnv>,
    xudp_sessions: Arc<XudpMuxSessions>,
    packet_sessions: Arc<MuxUdpSessionManager>,
) -> std::io::Result<MuxFrameActions> {
    let id = frame.mux_id;
    match frame.command {
        MuxCommand::Udp {
            destination,
            packet,
            global_id,
        } => {
            if let Some(global_id) = global_id.filter(|id| is_xudp_global_id(id)) {
                let Some(route_env) = route_env else {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "xudp requires routed mux environment",
                    ));
                };
                debug!(mux_id = id, global_id = ?global_id, "mux xudp substream opened");
                let actions = route_env
                    .xudp
                    .handle_new(
                        global_id,
                        id,
                        destination.destination,
                        packet,
                        route_env,
                        udp_tx.clone(),
                    )
                    .await?;
                xudp_sessions.register(id, global_id).await;
                return Ok(actions);
            }
            if let Some(global_id) = xudp_sessions.global_id(id).await {
                if let Some(route_env) = route_env {
                    route_env
                        .xudp
                        .handle_keep(id, global_id, destination.destination, packet)
                        .await?;
                }
                return Ok(mux_actions(Vec::new()));
            }

            match frame.status {
                MuxStatus::New => {
                    if udp_dns::is_mux_udp_dns_request(&destination.destination, &packet) {
                        debug!(mux_id = id, "mux udp dns substream opened");
                        return udp_dns::handle_udp_mux_dns_new(
                            id,
                            destination.destination,
                            packet,
                            dns,
                            trace,
                            udp_tx,
                        )
                        .await;
                    }
                    debug!(mux_id = id, "generic mux udp session opened");
                    packet_sessions
                        .handle_new(
                            id,
                            destination.destination,
                            packet,
                            route_env,
                            udp_tx.clone(),
                        )
                        .await
                }
                MuxStatus::Keep => {
                    if udp_dns::is_mux_udp_dns_request(&destination.destination, &packet) {
                        return udp_dns::handle_udp_mux_dns_new(
                            id,
                            destination.destination,
                            packet,
                            dns,
                            trace,
                            udp_tx,
                        )
                        .await;
                    }
                    if packet_sessions
                        .handle_keep(id, destination.destination, packet)
                        .await?
                    {
                        Ok(mux_actions(Vec::new()))
                    } else {
                        Ok(mux_actions(vec![encode_mux_end(id)]))
                    }
                }
                _ => Ok(mux_actions(Vec::new())),
            }
        }
        MuxCommand::Close { .. } => {
            if let Some(global_id) = xudp_sessions.remove(id).await {
                if let Some(route_env) = route_env {
                    route_env.xudp.detach(global_id, id).await;
                }
                return Ok(mux_actions(Vec::new()));
            }
            if packet_sessions.handle_end(id).await {
                return Ok(mux_actions(Vec::new()));
            }
            tcp::handle_mux_tcp_command(active, frame, route_env).await
        }
        _ => tcp::handle_mux_tcp_command(active, frame, route_env).await,
    }
}
