use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::mux::encoder::encode_mux_udp_packet;
use crate::mux::frame::XUDP_MAX_PACKET_LEN;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::state::{mux_actions, MuxFrameActions, MuxOutTx};
use crate::outbound::freedom::resolve_udp_target;
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::{
    connect_routed_outbound, route_context_from_vless, NetworkKind, RoutedOutbound,
};
use crate::stats::StatsSession;
use crate::vless::protocol::VlessDestination;

const UPLINK_QUEUE: usize = 64;
const DOWNLINK_QUEUE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MuxUdpSessionStatus {
    Active,
    Closing,
}

struct UdpPacket {
    destination: VlessDestination,
    payload: Vec<u8>,
}

enum PacketOutbound {
    Freedom {
        socket: Arc<UdpSocket>,
        runtime: Arc<OutboundConnectRuntime>,
    },
    Blackhole,
}

struct MuxUdpSession {
    mux_id: u16,
    status: Mutex<MuxUdpSessionStatus>,
    outbound: Mutex<Option<PacketOutbound>>,
    uplink_tx: Mutex<mpsc::Sender<UdpPacket>>,
    downlink_tx: Mutex<mpsc::Sender<(VlessDestination, Vec<u8>)>>,
    tasks: Mutex<SessionTaskHandles>,
    stats: Option<StatsSession>,
}

struct SessionTaskHandles {
    uplink: Option<JoinHandle<()>>,
    downlink: Option<JoinHandle<()>>,
    response: Option<JoinHandle<()>>,
}

pub struct MuxUdpSessionManager {
    sessions: Mutex<HashMap<u16, Arc<MuxUdpSession>>>,
}

impl MuxUdpSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub async fn contains(&self, mux_id: u16) -> bool {
        self.sessions.lock().await.contains_key(&mux_id)
    }

    pub async fn handle_new(
        &self,
        mux_id: u16,
        destination: VlessDestination,
        packet: Vec<u8>,
        route_env: Option<&MuxRouteEnv>,
        udp_tx: MuxOutTx,
    ) -> std::io::Result<MuxFrameActions> {
        if packet.len() > XUDP_MAX_PACKET_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("mux udp packet too large: {}", packet.len()),
            ));
        }

        if self.sessions.lock().await.contains_key(&mux_id) {
            self.close_session(mux_id).await;
        }

        let (uplink_tx, uplink_rx) = mpsc::channel(UPLINK_QUEUE);
        let (downlink_tx, downlink_rx) = mpsc::channel(DOWNLINK_QUEUE);
        let session = Arc::new(MuxUdpSession {
            mux_id,
            status: Mutex::new(MuxUdpSessionStatus::Active),
            outbound: Mutex::new(None),
            uplink_tx: Mutex::new(uplink_tx),
            downlink_tx: Mutex::new(downlink_tx),
            tasks: Mutex::new(SessionTaskHandles {
                uplink: None,
                downlink: None,
                response: None,
            }),
            stats: route_env.and_then(|env| env.stats.clone()),
        });
        start_session_workers(&session, uplink_rx, downlink_rx, udp_tx).await;
        self.create_outbound(&session, &destination, route_env)
            .await?;
        if !packet.is_empty() {
            forward_packet(&session, &destination, &packet).await;
        }
        self.sessions.lock().await.insert(mux_id, session);
        debug!(mux_id, "generic mux udp session active");
        Ok(mux_actions(Vec::new()))
    }

    pub async fn handle_keep(
        &self,
        mux_id: u16,
        destination: VlessDestination,
        packet: Vec<u8>,
    ) -> std::io::Result<bool> {
        if packet.len() > XUDP_MAX_PACKET_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("mux udp packet too large: {}", packet.len()),
            ));
        }
        let session = {
            let map = self.sessions.lock().await;
            map.get(&mux_id).cloned()
        };
        let Some(session) = session else {
            return Ok(false);
        };
        if *session.status.lock().await != MuxUdpSessionStatus::Active {
            return Ok(false);
        }
        if !packet.is_empty() {
            forward_packet(&session, &destination, &packet).await;
        }
        Ok(true)
    }

    pub async fn handle_end(&self, mux_id: u16) -> bool {
        self.close_session(mux_id).await
    }

    pub async fn shutdown_all(&self) {
        let ids: Vec<u16> = self.sessions.lock().await.keys().copied().collect();
        for mux_id in ids {
            self.close_session(mux_id).await;
        }
    }

    #[cfg(test)]
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    async fn close_session(&self, mux_id: u16) -> bool {
        let session = {
            let mut map = self.sessions.lock().await;
            map.remove(&mux_id)
        };
        let Some(session) = session else {
            return false;
        };
        *session.status.lock().await = MuxUdpSessionStatus::Closing;
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        *session.downlink_tx.lock().await = tx;
        abort_session_tasks(&session).await;
        debug!(mux_id, "generic mux udp session closed");
        true
    }

    async fn create_outbound(
        &self,
        session: &Arc<MuxUdpSession>,
        destination: &VlessDestination,
        route_env: Option<&MuxRouteEnv>,
    ) -> std::io::Result<()> {
        let outbound = if let Some(route_env) = route_env {
            let route_ctx = route_context_from_vless(
                &route_env.inbound_tag,
                &route_env.auth,
                destination,
                &[],
                &route_env.socket_meta,
                route_env.sniffing_enabled,
                NetworkKind::Udp,
            );
            let decision = route_env
                .router
                .pick_route_with_default(route_ctx)
                .await
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            route_env.router.publish_route(&decision);

            if let Some(counter) = &route_env.test_dispatch_counter {
                counter.fetch_add(1, Ordering::SeqCst);
            }

            let runtime = OutboundConnectRuntime::shared();
            match connect_routed_outbound(
                &decision.outbound_tag,
                destination,
                route_env.router.outbound_manager(),
                Arc::clone(&runtime),
                NetworkKind::Udp,
            )
            .await?
            {
                RoutedOutbound::Udp { socket, .. } => PacketOutbound::Freedom {
                    socket: Arc::new(socket),
                    runtime,
                },
                RoutedOutbound::Blackhole => PacketOutbound::Blackhole,
                RoutedOutbound::Tcp(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "mux udp session cannot use freedom TCP outbound",
                    ));
                }
            }
        } else {
            let runtime = OutboundConnectRuntime::shared();
            let (socket, _) = crate::outbound::freedom::connect_udp_destination_with_runtime(
                destination,
                runtime.clone(),
            )
            .await?;
            PacketOutbound::Freedom {
                socket: Arc::new(socket),
                runtime,
            }
        };

        let spawn_downlink = matches!(outbound, PacketOutbound::Freedom { .. });
        *session.outbound.lock().await = Some(outbound);
        if spawn_downlink {
            ensure_downlink_task(session).await;
        }
        Ok(())
    }
}

async fn forward_packet(
    session: &Arc<MuxUdpSession>,
    destination: &VlessDestination,
    packet: &[u8],
) {
    session
        .uplink_tx
        .lock()
        .await
        .send(UdpPacket {
            destination: destination.clone(),
            payload: packet.to_vec(),
        })
        .await
        .ok();
}

async fn start_session_workers(
    session: &Arc<MuxUdpSession>,
    mut uplink_rx: mpsc::Receiver<UdpPacket>,
    mut downlink_rx: mpsc::Receiver<(VlessDestination, Vec<u8>)>,
    udp_tx: MuxOutTx,
) {
    let uplink_session = Arc::clone(session);
    let uplink = tokio::spawn(async move {
        while let Some(packet) = uplink_rx.recv().await {
            if *uplink_session.status.lock().await != MuxUdpSessionStatus::Active {
                break;
            }
            let outbound = uplink_session.outbound.lock().await.clone();
            let Some(outbound) = outbound else {
                continue;
            };
            match outbound {
                PacketOutbound::Blackhole => {
                    if let Some(stats) = uplink_session.stats.as_ref() {
                        stats.record_uplink(packet.payload.len() as u64);
                    }
                }
                PacketOutbound::Freedom { socket, runtime } => {
                    match resolve_udp_target(&packet.destination, Arc::clone(&runtime)).await {
                        Ok(target) => {
                            if socket.send_to(&packet.payload, target).await.is_ok() {
                                if let Some(stats) = uplink_session.stats.as_ref() {
                                    stats.record_uplink(packet.payload.len() as u64);
                                }
                            }
                        }
                        Err(err) => {
                            warn!(
                                mux_id = uplink_session.mux_id,
                                error = %err,
                                "generic mux udp uplink resolve failed"
                            );
                        }
                    }
                }
            }
        }
    });

    let response_session = Arc::clone(session);
    let response = tokio::spawn(async move {
        while let Some((destination, payload)) = downlink_rx.recv().await {
            if *response_session.status.lock().await != MuxUdpSessionStatus::Active {
                break;
            }
            let frame = match encode_mux_udp_packet(response_session.mux_id, &destination, &payload)
            {
                Ok(frame) => frame,
                Err(err) => {
                    warn!(
                        mux_id = response_session.mux_id,
                        error = %err,
                        "generic mux udp response encode failed"
                    );
                    continue;
                }
            };
            if let Some(stats) = response_session.stats.as_ref() {
                stats.record_downlink(payload.len() as u64);
            }
            let _ = udp_tx.send(mux_actions(vec![frame]));
        }
    });

    let mut tasks = session.tasks.lock().await;
    tasks.uplink = Some(uplink);
    tasks.response = Some(response);
}

async fn ensure_downlink_task(session: &Arc<MuxUdpSession>) {
    let mut tasks = session.tasks.lock().await;
    if tasks.downlink.is_some() {
        return;
    }
    let outbound = session.outbound.lock().await.clone();
    let Some(PacketOutbound::Freedom { socket, .. }) = outbound else {
        return;
    };
    let downlink_tx = session.downlink_tx.lock().await.clone();
    let mux_id = session.mux_id;
    let status = Arc::clone(session);
    let downlink = tokio::spawn(async move {
        let mut buf = vec![0u8; XUDP_MAX_PACKET_LEN];
        loop {
            if *status.status.lock().await != MuxUdpSessionStatus::Active {
                break;
            }
            match socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let destination = socket_addr_to_vless(peer);
                    let payload = buf[..len].to_vec();
                    if downlink_tx.try_send((destination, payload)).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    warn!(mux_id, error = %err, "generic mux udp downlink recv failed");
                    break;
                }
            }
        }
    });
    tasks.downlink = Some(downlink);
}

async fn abort_session_tasks(session: &Arc<MuxUdpSession>) {
    let mut tasks = session.tasks.lock().await;
    if let Some(task) = tasks.uplink.take() {
        task.abort();
    }
    if let Some(task) = tasks.downlink.take() {
        task.abort();
    }
    if let Some(task) = tasks.response.take() {
        task.abort();
    }
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    *session.uplink_tx.lock().await = tx;
}

fn socket_addr_to_vless(addr: SocketAddr) -> VlessDestination {
    VlessDestination::Ip(addr.ip(), addr.port())
}

impl Clone for PacketOutbound {
    fn clone(&self) -> Self {
        match self {
            Self::Freedom { socket, runtime } => Self::Freedom {
                socket: Arc::clone(socket),
                runtime: Arc::clone(runtime),
            },
            Self::Blackhole => Self::Blackhole,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/mux/packet_udp.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/mux/packet_udp_reality_overflow.rs"]
mod reality_overflow_tests;
