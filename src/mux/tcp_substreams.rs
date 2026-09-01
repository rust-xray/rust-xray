use std::collections::HashMap;
use std::io::{Error, ErrorKind};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::mux::encoder::encode_mux_end;
use crate::mux::frame::{MuxCommand, MuxFrame};
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::state::{mux_actions, MuxFrameActions};
use crate::outbound::freedom::{connect_tcp_destination, format_vless_destination};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::{
    connect_routed_outbound, route_context_from_vless, NetworkKind, RoutedOutbound,
};

const TCP_DOWNLINK_QUEUE: usize = 32;

/// Downlink event from a mux TCP child reader task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpDownlinkEvent {
    Data(Vec<u8>),
    Eof,
}

struct MuxTcpEntry {
    writer: OwnedWriteHalf,
}

/// Parallel mux TCP substreams keyed by mux session id.
pub struct MuxTcpSubstreams {
    streams: HashMap<u16, MuxTcpEntry>,
    downlink_tx: mpsc::Sender<(u16, TcpDownlinkEvent)>,
}

impl MuxTcpSubstreams {
    pub fn new(downlink_tx: mpsc::Sender<(u16, TcpDownlinkEvent)>) -> Self {
        Self {
            streams: HashMap::new(),
            downlink_tx,
        }
    }

    pub fn downlink_channel() -> (
        mpsc::Sender<(u16, TcpDownlinkEvent)>,
        mpsc::Receiver<(u16, TcpDownlinkEvent)>,
    ) {
        mpsc::channel(TCP_DOWNLINK_QUEUE)
    }

    pub fn contains(&self, mux_id: u16) -> bool {
        self.streams.contains_key(&mux_id)
    }

    pub fn remove(&mut self, mux_id: u16) {
        self.streams.remove(&mux_id);
    }
}

fn spawn_tcp_downlink_reader(
    mux_id: u16,
    mut reader: OwnedReadHalf,
    downlink_tx: mpsc::Sender<(u16, TcpDownlinkEvent)>,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = downlink_tx.send((mux_id, TcpDownlinkEvent::Eof)).await;
                    break;
                }
                Ok(n) => {
                    if downlink_tx
                        .send((mux_id, TcpDownlinkEvent::Data(buf[..n].to_vec())))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

pub(crate) async fn handle_mux_tcp_command(
    active: &mut MuxTcpSubstreams,
    frame: MuxFrame,
    route_env: Option<&MuxRouteEnv>,
) -> std::io::Result<MuxFrameActions> {
    let id = frame.mux_id;
    match frame.command {
        MuxCommand::Tcp {
            destination,
            initial_payload,
        } => {
            if route_env.is_some_and(|env| env.vision_mux_udp_only) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "vision mux accepts only udp child substreams",
                ));
            }
            if active.streams.contains_key(&id) {
                debug!(mux_id = id, "replacing existing mux tcp substream");
                active.streams.remove(&id);
            }
            let destination_label = format_vless_destination(&destination.destination);
            debug!(
                mux_id = id,
                network = destination.network.as_str(),
                destination = %destination_label,
                "mux substream destination parsed"
            );
            let outbound = if let Some(env) = route_env {
                let route_ctx = route_context_from_vless(
                    &env.inbound_tag,
                    &env.auth,
                    &destination.destination,
                    &initial_payload,
                    &env.socket_meta,
                    env.sniffing_enabled,
                    NetworkKind::Tcp,
                );
                let decision = env
                    .router
                    .pick_route_with_default(route_ctx)
                    .await
                    .map_err(|err| Error::other(err.to_string()))?;
                env.router.publish_route(&decision);
                match connect_routed_outbound(
                    &decision.outbound_tag,
                    &destination.destination,
                    env.router.outbound_manager(),
                    OutboundConnectRuntime::shared(),
                    NetworkKind::Tcp,
                )
                .await?
                {
                    RoutedOutbound::Tcp(stream) => stream,
                    RoutedOutbound::Blackhole => {
                        debug!(
                            mux_id = id,
                            destination = %destination_label,
                            "mux substream routed to blackhole outbound"
                        );
                        return Ok(mux_actions(vec![encode_mux_end(id)]));
                    }
                    RoutedOutbound::Udp { .. } => {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "mux TCP substream cannot use freedom UDP outbound",
                        ));
                    }
                }
            } else {
                connect_tcp_destination(&destination.destination).await?
            };
            let (reader, mut writer) = outbound.into_split();
            if !initial_payload.is_empty() {
                writer.write_all(&initial_payload).await?;
            }
            spawn_tcp_downlink_reader(id, reader, active.downlink_tx.clone());
            active.streams.insert(id, MuxTcpEntry { writer });
            debug!(mux_id = id, destination = %destination_label, "mux substream opened");
        }
        MuxCommand::Data { payload } => {
            let Some(entry) = active.streams.get_mut(&id) else {
                warn!(mux_id = id, "mux keep frame without active substream");
                return Ok(mux_actions(Vec::new()));
            };
            if !payload.is_empty() {
                entry.writer.write_all(&payload).await?;
            }
        }
        MuxCommand::Close { payload } => {
            let Some(mut entry) = active.streams.remove(&id) else {
                debug!(mux_id = id, "mux end frame without active substream");
                return Ok(mux_actions(Vec::new()));
            };
            if !payload.is_empty() {
                entry.writer.write_all(&payload).await?;
            }
            let _ = entry.writer.shutdown().await;
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
