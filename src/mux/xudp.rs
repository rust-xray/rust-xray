use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::mux::encoder::encode_mux_udp_packet;
use crate::mux::frame::{MuxGlobalId, XUDP_MAX_PACKET_LEN};
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
pub(crate) enum XudpStatus {
    Initializing,
    Active,
    Expiring,
}

struct XudpPacket {
    destination: VlessDestination,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct AttachedMux {
    mux_id: u16,
    tx: MuxOutTx,
}

enum XudpOutbound {
    Freedom {
        socket: Arc<UdpSocket>,
        runtime: Arc<OutboundConnectRuntime>,
    },
    Blackhole,
}

struct XudpAssociation {
    global_id: MuxGlobalId,
    status: Mutex<XudpStatus>,
    outbound: Mutex<Option<XudpOutbound>>,
    uplink_tx: Mutex<mpsc::Sender<XudpPacket>>,
    attached: Mutex<Option<AttachedMux>>,
    expire_at: Mutex<Option<Instant>>,
    init_ready: Notify,
    downlink_tx: Mutex<mpsc::Sender<(VlessDestination, Vec<u8>)>>,
    tasks: Mutex<XudpTaskHandles>,
    stats: Option<StatsSession>,
}

struct XudpTaskHandles {
    uplink: Option<JoinHandle<()>>,
    downlink: Option<JoinHandle<()>>,
    response: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct XudpManagerConfig {
    pub expiry: Duration,
    pub sweep_interval: Duration,
}

impl Default for XudpManagerConfig {
    fn default() -> Self {
        Self {
            expiry: Duration::from_secs(60),
            sweep_interval: Duration::from_secs(60),
        }
    }
}

pub struct XudpManager {
    inner: Mutex<HashMap<MuxGlobalId, Arc<XudpAssociation>>>,
    config: XudpManagerConfig,
}

impl XudpManager {
    pub fn new(config: XudpManagerConfig) -> Arc<Self> {
        let manager = Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            config,
        });
        let sweeper = Arc::clone(&manager);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(sweeper.config.sweep_interval);
            loop {
                tick.tick().await;
                Arc::clone(&sweeper).sweep_expired().await;
            }
        });
        manager
    }

    pub fn shared() -> Arc<Self> {
        static MANAGER: OnceLock<Arc<XudpManager>> = OnceLock::new();
        Arc::clone(MANAGER.get_or_init(|| XudpManager::new(XudpManagerConfig::default())))
    }

    pub fn new_for_test(config: XudpManagerConfig) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            config,
        })
    }

    pub async fn sweep_expired_now(self: &Arc<Self>) {
        Arc::clone(self).sweep_expired().await;
    }

    pub(crate) async fn handle_new(
        self: &Arc<Self>,
        global_id: MuxGlobalId,
        mux_id: u16,
        destination: VlessDestination,
        packet: Vec<u8>,
        route_env: &MuxRouteEnv,
        udp_tx: MuxOutTx,
    ) -> std::io::Result<MuxFrameActions> {
        if packet.len() > XUDP_MAX_PACKET_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("xudp packet too large: {}", packet.len()),
            ));
        }

        let association = {
            let mut map = self.inner.lock().await;
            if let Some(existing) = map.get(&global_id) {
                let status = *existing.status.lock().await;
                if status == XudpStatus::Initializing {
                    return Ok(mux_actions(Vec::new()));
                }
                *existing.status.lock().await = XudpStatus::Initializing;
                existing.expire_at.lock().await.take();
                Arc::clone(existing)
            } else {
                let (uplink_tx, uplink_rx) = mpsc::channel(UPLINK_QUEUE);
                let (downlink_tx, downlink_rx) = mpsc::channel(DOWNLINK_QUEUE);
                let association = Arc::new(XudpAssociation {
                    global_id,
                    status: Mutex::new(XudpStatus::Initializing),
                    outbound: Mutex::new(None),
                    uplink_tx: Mutex::new(uplink_tx),
                    attached: Mutex::new(None),
                    expire_at: Mutex::new(None),
                    init_ready: Notify::new(),
                    downlink_tx: Mutex::new(downlink_tx),
                    tasks: Mutex::new(XudpTaskHandles {
                        uplink: None,
                        downlink: None,
                        response: None,
                    }),
                    stats: route_env.stats.clone(),
                });
                start_association_workers(&association, uplink_rx, downlink_rx).await;
                map.insert(global_id, Arc::clone(&association));
                association
            }
        };

        let first_open = association.outbound.lock().await.is_none();

        if !first_open {
            Self::detach_response_target(&association).await;
            let mut forward_ok = Self::forward_packet(&association, &destination, &packet).await;
            if !forward_ok {
                self.rebuild_outbound(&association, &destination, route_env)
                    .await?;
                forward_ok = Self::forward_packet(&association, &destination, &packet).await;
            }
            let _ = forward_ok;
        } else {
            self.create_routed_outbound(&association, &destination, route_env)
                .await?;
            Self::forward_packet(&association, &destination, &packet).await;
        }

        Self::attach_response_target(&association, mux_id, udp_tx).await;
        *association.status.lock().await = XudpStatus::Active;
        association.init_ready.notify_waiters();

        debug!(mux_id, global_id = ?global_id, first_open, "xudp association active");
        Ok(mux_actions(Vec::new()))
    }

    pub async fn handle_keep(
        &self,
        mux_id: u16,
        global_id: MuxGlobalId,
        destination: VlessDestination,
        packet: Vec<u8>,
    ) -> std::io::Result<()> {
        if packet.len() > XUDP_MAX_PACKET_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("xudp packet too large: {}", packet.len()),
            ));
        }
        let association = {
            let map = self.inner.lock().await;
            map.get(&global_id).cloned()
        };
        let Some(association) = association else {
            return Ok(());
        };
        if association
            .attached
            .lock()
            .await
            .as_ref()
            .is_some_and(|attached| attached.mux_id == mux_id)
        {
            Self::forward_packet(&association, &destination, &packet).await;
        }
        Ok(())
    }

    pub async fn detach(&self, global_id: MuxGlobalId, mux_id: u16) {
        let association = {
            let map = self.inner.lock().await;
            map.get(&global_id).cloned()
        };
        let Some(association) = association else {
            return;
        };
        let should_expire = {
            let mut attached = association.attached.lock().await;
            if attached
                .as_ref()
                .is_some_and(|target| target.mux_id == mux_id)
            {
                *attached = None;
                true
            } else {
                false
            }
        };
        if !should_expire {
            return;
        }
        let mut status = association.status.lock().await;
        if *status == XudpStatus::Active {
            *status = XudpStatus::Expiring;
            *association.expire_at.lock().await = Some(Instant::now() + self.config.expiry);
            debug!(global_id = ?global_id, mux_id, "xudp association expiring");
        }
    }

    async fn sweep_expired(self: Arc<Self>) {
        let now = Instant::now();
        let expired: Vec<MuxGlobalId> = {
            let map = self.inner.lock().await;
            let mut ids = Vec::new();
            for (id, association) in map.iter() {
                let status = *association.status.lock().await;
                if status != XudpStatus::Expiring {
                    continue;
                }
                let expire_at = *association.expire_at.lock().await;
                if expire_at.is_some_and(|deadline| now >= deadline) {
                    ids.push(*id);
                }
            }
            ids
        };
        for global_id in expired {
            self.remove_association(global_id).await;
        }
    }

    async fn remove_association(&self, global_id: MuxGlobalId) {
        let association = {
            let mut map = self.inner.lock().await;
            map.remove(&global_id)
        };
        let Some(association) = association else {
            return;
        };
        abort_association_tasks(&association).await;
        debug!(global_id = ?global_id, "xudp association removed");
    }

    async fn rebuild_outbound(
        &self,
        association: &Arc<XudpAssociation>,
        destination: &VlessDestination,
        route_env: &MuxRouteEnv,
    ) -> std::io::Result<()> {
        abort_association_tasks(association).await;
        *association.outbound.lock().await = None;
        let (uplink_tx, uplink_rx) = mpsc::channel(UPLINK_QUEUE);
        let (downlink_tx, downlink_rx) = mpsc::channel(DOWNLINK_QUEUE);
        *association.uplink_tx.lock().await = uplink_tx;
        *association.downlink_tx.lock().await = downlink_tx;
        start_association_workers(association, uplink_rx, downlink_rx).await;
        self.create_routed_outbound(association, destination, route_env)
            .await
    }

    async fn create_routed_outbound(
        &self,
        association: &Arc<XudpAssociation>,
        destination: &VlessDestination,
        route_env: &MuxRouteEnv,
    ) -> std::io::Result<()> {
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
        let outbound = match connect_routed_outbound(
            &decision.outbound_tag,
            destination,
            route_env.router.outbound_manager(),
            Arc::clone(&runtime),
            NetworkKind::Udp,
        )
        .await?
        {
            RoutedOutbound::Udp { socket, .. } => XudpOutbound::Freedom {
                socket: Arc::new(socket),
                runtime,
            },
            RoutedOutbound::Blackhole => XudpOutbound::Blackhole,
            RoutedOutbound::Tcp(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "xudp association cannot use freedom TCP outbound",
                ));
            }
        };
        let spawn_downlink = matches!(outbound, XudpOutbound::Freedom { .. });
        *association.outbound.lock().await = Some(outbound);
        if spawn_downlink {
            ensure_downlink_task(association).await;
        }
        Ok(())
    }

    async fn forward_packet(
        association: &Arc<XudpAssociation>,
        destination: &VlessDestination,
        packet: &[u8],
    ) -> bool {
        association
            .uplink_tx
            .lock()
            .await
            .send(XudpPacket {
                destination: destination.clone(),
                payload: packet.to_vec(),
            })
            .await
            .is_ok()
    }

    async fn attach_response_target(association: &Arc<XudpAssociation>, mux_id: u16, tx: MuxOutTx) {
        *association.attached.lock().await = Some(AttachedMux { mux_id, tx });
        association.expire_at.lock().await.take();
    }

    async fn detach_response_target(association: &Arc<XudpAssociation>) {
        association.attached.lock().await.take();
    }

    #[cfg(test)]
    pub async fn break_uplink_for_test(&self, global_id: MuxGlobalId) {
        let association = {
            let map = self.inner.lock().await;
            map.get(&global_id).cloned()
        };
        let Some(association) = association else {
            return;
        };
        abort_association_tasks(&association).await;
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        *association.uplink_tx.lock().await = tx;
    }

    #[cfg(test)]
    pub async fn force_status_for_test(&self, global_id: MuxGlobalId, status: XudpStatus) {
        if let Some(association) = self.inner.lock().await.get(&global_id) {
            *association.status.lock().await = status;
        }
    }

    #[cfg(test)]
    pub async fn association_count(&self) -> usize {
        self.inner.lock().await.len()
    }

    #[cfg(test)]
    pub async fn status_of(&self, global_id: MuxGlobalId) -> Option<XudpStatus> {
        let association = {
            let map = self.inner.lock().await;
            map.get(&global_id).cloned()
        };
        match association {
            Some(association) => Some(*association.status.lock().await),
            None => None,
        }
    }
}

async fn start_association_workers(
    association: &Arc<XudpAssociation>,
    mut uplink_rx: mpsc::Receiver<XudpPacket>,
    mut downlink_rx: mpsc::Receiver<(VlessDestination, Vec<u8>)>,
) {
    let uplink_association = Arc::clone(association);
    let uplink = tokio::spawn(async move {
        while let Some(packet) = uplink_rx.recv().await {
            let outbound = uplink_association.outbound.lock().await.clone();
            let Some(outbound) = outbound else {
                continue;
            };
            match outbound {
                XudpOutbound::Blackhole => {
                    if let Some(stats) = uplink_association.stats.as_ref() {
                        stats.record_uplink(packet.payload.len() as u64);
                    }
                }
                XudpOutbound::Freedom { socket, runtime } => {
                    match resolve_udp_target(&packet.destination, Arc::clone(&runtime)).await {
                        Ok(target) => {
                            if let Err(err) = socket.send_to(&packet.payload, target).await {
                                warn!(
                                    global_id = ?uplink_association.global_id,
                                    error = %err,
                                    "xudp uplink send failed"
                                );
                            } else if let Some(stats) = uplink_association.stats.as_ref() {
                                stats.record_uplink(packet.payload.len() as u64);
                            }
                        }
                        Err(err) => {
                            warn!(
                                global_id = ?uplink_association.global_id,
                                error = %err,
                                "xudp uplink resolve failed"
                            );
                        }
                    }
                }
            }
        }
    });

    let response_association = Arc::clone(association);
    let response = tokio::spawn(async move {
        while let Some((destination, payload)) = downlink_rx.recv().await {
            let attached = response_association.attached.lock().await.clone();
            let Some(attached) = attached else {
                continue;
            };
            let frame = match encode_mux_udp_packet(attached.mux_id, &destination, &payload) {
                Ok(frame) => frame,
                Err(err) => {
                    warn!(
                        global_id = ?response_association.global_id,
                        error = %err,
                        "xudp response encode failed"
                    );
                    continue;
                }
            };
            if let Some(stats) = response_association.stats.as_ref() {
                stats.record_downlink(payload.len() as u64);
            }
            let _ = attached.tx.send(mux_actions(vec![frame]));
        }
    });

    let mut tasks = association.tasks.lock().await;
    tasks.uplink = Some(uplink);
    tasks.response = Some(response);
}

async fn ensure_downlink_task(association: &Arc<XudpAssociation>) {
    let mut tasks = association.tasks.lock().await;
    if tasks.downlink.is_some() {
        return;
    }
    let outbound = association.outbound.lock().await.clone();
    let Some(XudpOutbound::Freedom { socket, .. }) = outbound else {
        return;
    };
    let downlink_tx = association.downlink_tx.lock().await.clone();
    let global_id = association.global_id;
    let downlink = tokio::spawn(async move {
        let mut buf = vec![0u8; XUDP_MAX_PACKET_LEN];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let destination = socket_addr_to_vless(peer);
                    let payload = buf[..len].to_vec();
                    if downlink_tx.try_send((destination, payload)).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    warn!(global_id = ?global_id, error = %err, "xudp downlink recv failed");
                    break;
                }
            }
        }
    });
    tasks.downlink = Some(downlink);
}

async fn abort_association_tasks(association: &Arc<XudpAssociation>) {
    let mut tasks = association.tasks.lock().await;
    if let Some(task) = tasks.uplink.take() {
        task.abort();
    }
    if let Some(task) = tasks.downlink.take() {
        task.abort();
    }
    if let Some(task) = tasks.response.take() {
        task.abort();
    }
}

fn socket_addr_to_vless(addr: SocketAddr) -> VlessDestination {
    VlessDestination::Ip(addr.ip(), addr.port())
}

impl Clone for XudpOutbound {
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

/// Per-parent-mux session map from mux substream id to GlobalID.
pub struct XudpMuxSessions {
    by_mux_id: Mutex<HashMap<u16, MuxGlobalId>>,
}

impl Default for XudpMuxSessions {
    fn default() -> Self {
        Self {
            by_mux_id: Mutex::new(HashMap::new()),
        }
    }
}

impl XudpMuxSessions {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, mux_id: u16, global_id: MuxGlobalId) {
        self.by_mux_id.lock().await.insert(mux_id, global_id);
    }

    pub async fn global_id(&self, mux_id: u16) -> Option<MuxGlobalId> {
        self.by_mux_id.lock().await.get(&mux_id).copied()
    }

    pub async fn remove(&self, mux_id: u16) -> Option<MuxGlobalId> {
        self.by_mux_id.lock().await.remove(&mux_id)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/mux/xudp.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/mux/xudp_reality_overflow.rs"]
mod reality_overflow_tests;
