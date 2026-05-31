use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::dns::DnsEngine;
use crate::mux::encoder::encode_mux_end;
use crate::mux::frame::{MuxCommand, MuxFrame, MuxSessionTrace};
use crate::mux::parser::read_mux_frame;
use crate::mux::state::{mux_actions, write_mux_out_frames, MuxFrameActions, MuxOutTx};
use crate::mux::tcp;
use crate::mux::udp_dns;

pub async fn handle_mux_cool_inbound<S>(stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns(stream, DnsEngine::shared()).await
}

pub async fn handle_mux_cool_inbound_traced<S>(
    stream: S,
    trace: MuxSessionTrace,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns_and_trace(stream, DnsEngine::shared(), Some(trace)).await
}

pub async fn handle_mux_cool_inbound_with_dns<S>(
    stream: S,
    dns: Arc<DnsEngine>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns_and_trace(stream, dns, None).await
}

pub async fn handle_mux_cool_inbound_with_dns_and_trace<S>(
    mut stream: S,
    dns: Arc<DnsEngine>,
    trace: Option<MuxSessionTrace>,
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
                    let actions = handle_client_frame(&mut active, &dns, frame, trace, udp_tx.clone()).await?;
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
                            let actions = handle_client_frame(&mut active, &dns, frame, trace, udp_tx.clone()).await?;
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
) -> std::io::Result<MuxFrameActions> {
    let id = frame.mux_id;
    match frame.command {
        MuxCommand::Udp {
            destination,
            packet,
        } => {
            debug!(mux_id = id, "mux udp substream opened");
            udp_dns::handle_udp_mux_packet(id, destination.destination, packet, dns, trace, udp_tx)
                .await
        }
        _ => tcp::handle_mux_tcp_command(active, frame).await,
    }
}
