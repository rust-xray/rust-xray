use std::collections::HashMap;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::mux::encoder::encode_mux_udp_packet;
use crate::mux::frame::XUDP_MAX_PACKET_LEN;
use crate::mux::payload::UdpPacket;
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::routed_udp::{RoutedUdpAssociation, MUX_UDP_ASSOCIATION_QUEUE_CAPACITY};
use crate::mux::state::{mux_actions, MuxFrameActions, MuxOutTx};
use crate::stats::StatsSession;
use crate::vless::protocol::VlessDestination;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MuxUdpSessionStatus {
    Active,
    Closing,
}

struct MuxUdpSession {
    mux_id: u16,
    status: Mutex<MuxUdpSessionStatus>,
    outbound: Mutex<Option<RoutedUdpAssociation>>,
    uplink_tx: Mutex<mpsc::Sender<UdpPacket>>,
    downlink_tx: Mutex<mpsc::Sender<(VlessDestination, Bytes)>>,
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

    pub async fn handle_new(
        &self,
        mux_id: u16,
        destination: VlessDestination,
        packet: Bytes,
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

        let (uplink_tx, uplink_rx) = mpsc::channel(MUX_UDP_ASSOCIATION_QUEUE_CAPACITY);
        let (downlink_tx, downlink_rx) = mpsc::channel(MUX_UDP_ASSOCIATION_QUEUE_CAPACITY);
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
        self.create_outbound(&session, &destination, route_env)
            .await?;
        start_session_workers(&session, uplink_rx, downlink_rx, udp_tx).await;
        if !packet.is_empty() {
            forward_packet(&session, Some(&destination), packet).await;
        }
        self.sessions.lock().await.insert(mux_id, session);
        debug!(mux_id, "generic mux udp session active");
        Ok(mux_actions(Vec::new()))
    }

    pub async fn handle_keep(
        &self,
        mux_id: u16,
        destination: Option<&VlessDestination>,
        packet: Bytes,
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
            debug!(
                path = "mux_udp",
                mux_id,
                destination_override = destination.is_some(),
                packet_len = packet.len(),
                "mux keep routed to existing generic udp association"
            );
            forward_packet(&session, destination, packet).await;
        }
        Ok(true)
    }

    pub(crate) async fn contains_session(&self, mux_id: u16) -> bool {
        self.sessions.lock().await.contains_key(&mux_id)
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
        let outbound = RoutedUdpAssociation::connect(destination, route_env).await?;
        let spawn_downlink = outbound.has_downlink();
        *session.outbound.lock().await = Some(outbound);
        if spawn_downlink {
            ensure_downlink_task(session).await;
        }
        Ok(())
    }
}

async fn forward_packet(
    session: &Arc<MuxUdpSession>,
    destination: Option<&VlessDestination>,
    packet: Bytes,
) {
    session
        .uplink_tx
        .lock()
        .await
        .send(UdpPacket {
            destination: destination.cloned(),
            payload: packet,
        })
        .await
        .ok();
}

async fn start_session_workers(
    session: &Arc<MuxUdpSession>,
    mut uplink_rx: mpsc::Receiver<UdpPacket>,
    mut downlink_rx: mpsc::Receiver<(VlessDestination, Bytes)>,
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
            match outbound
                .send_to(packet.destination.as_ref(), &packet.payload)
                .await
            {
                Ok(()) => {
                    if let Some(stats) = uplink_session.stats.as_ref() {
                        stats.record_uplink(packet.payload.len() as u64);
                    }
                }
                Err(err) => {
                    *uplink_session.status.lock().await = MuxUdpSessionStatus::Closing;
                    warn!(
                        mux_id = uplink_session.mux_id,
                        destination_override = packet.destination.is_some(),
                        error = %err,
                        "generic mux udp uplink send failed"
                    );
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
            match udp_tx.send(mux_actions(vec![frame])).await {
                Ok(()) => {
                    if let Some(stats) = response_session.stats.as_ref() {
                        stats.record_downlink(payload.len() as u64);
                    }
                }
                Err(err) => {
                    warn!(
                        mux_id = response_session.mux_id,
                        error = %err,
                        "generic mux udp response queue unavailable"
                    );
                    break;
                }
            }
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
    let Some(outbound) = outbound.filter(RoutedUdpAssociation::has_downlink) else {
        return;
    };
    let downlink_tx = session.downlink_tx.lock().await.clone();
    let mux_id = session.mux_id;
    let status = Arc::clone(session);
    let downlink = tokio::spawn(async move {
        let mut recv_buf = BytesMut::with_capacity(512);
        loop {
            if *status.status.lock().await != MuxUdpSessionStatus::Active {
                break;
            }
            recv_buf.clear();
            recv_buf.resize(XUDP_MAX_PACKET_LEN, 0);
            match outbound.recv_from(&mut recv_buf).await {
                Ok(Some((len, destination))) => {
                    let payload = recv_buf.split_to(len).freeze();
                    if downlink_tx.send((destination, payload)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    warn!(mux_id, error = %err, "generic mux udp downlink recv failed");
                    *status.status.lock().await = MuxUdpSessionStatus::Closing;
                    break;
                }
            }
        }
    });
    tasks.downlink = Some(downlink);
}

async fn abort_session_tasks(session: &Arc<MuxUdpSession>) {
    let handles = {
        let mut tasks = session.tasks.lock().await;
        [
            tasks.uplink.take(),
            tasks.downlink.take(),
            tasks.response.take(),
        ]
    };
    for task in handles.iter().flatten() {
        task.abort();
    }
    for task in handles.into_iter().flatten() {
        let _ = task.await;
    }
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    *session.uplink_tx.lock().await = tx;
}

#[cfg(test)]
#[path = "../../tests/unit/mux/packet_udp.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/mux/packet_udp_reality_overflow.rs"]
mod reality_overflow_tests;
