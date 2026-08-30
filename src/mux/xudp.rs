use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::mux::encoder::encode_mux_udp_packet;
use crate::mux::frame::{MuxGlobalId, XUDP_MAX_PACKET_LEN};
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::routed_udp::{RoutedUdpAssociation, MUX_UDP_ASSOCIATION_QUEUE_CAPACITY};
use crate::mux::state::{mux_actions, MuxFrameActions, MuxOutTx};
use crate::stats::StatsSession;
use crate::vless::protocol::VlessDestination;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XudpStatus {
    Initializing,
    Active,
    Expiring,
}

struct XudpPacket {
    destination: Option<VlessDestination>,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct AttachedMux {
    mux_id: u16,
    tx: MuxOutTx,
}

struct XudpAssociation {
    global_id: MuxGlobalId,
    status: Mutex<XudpStatus>,
    outbound: Mutex<Option<RoutedUdpAssociation>>,
    uplink_tx: Mutex<mpsc::Sender<XudpPacket>>,
    attached: Mutex<Option<AttachedMux>>,
    expire_at: Mutex<Option<Instant>>,
    downlink_tx: Mutex<mpsc::Sender<(VlessDestination, Vec<u8>)>>,
    tasks: Mutex<XudpTaskHandles>,
    stats: Option<StatsSession>,
    healthy: AtomicBool,
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
    sweeper: StdMutex<Option<JoinHandle<()>>>,
}

impl XudpManager {
    pub fn new(config: XudpManagerConfig) -> Arc<Self> {
        let manager = Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            config,
            sweeper: StdMutex::new(None),
        });
        let weak = Arc::downgrade(&manager);
        let sweep_interval = manager.config.sweep_interval;
        let sweeper = tokio::spawn(async move {
            let mut tick = tokio::time::interval(sweep_interval);
            loop {
                tick.tick().await;
                let Some(manager) = weak.upgrade() else {
                    break;
                };
                manager.sweep_expired().await;
            }
        });
        *manager.sweeper.lock().expect("xudp sweeper lock") = Some(sweeper);
        manager
    }

    pub fn shared() -> Arc<Self> {
        static MANAGER: OnceLock<Arc<XudpManager>> = OnceLock::new();
        Arc::clone(MANAGER.get_or_init(|| XudpManager::new(XudpManagerConfig::default())))
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(config: XudpManagerConfig) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            config,
            sweeper: StdMutex::new(None),
        })
    }

    #[cfg(test)]
    pub(crate) async fn sweep_expired_now(self: &Arc<Self>) {
        self.sweep_expired().await;
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
                let (uplink_tx, uplink_rx) = mpsc::channel(MUX_UDP_ASSOCIATION_QUEUE_CAPACITY);
                let (downlink_tx, downlink_rx) = mpsc::channel(MUX_UDP_ASSOCIATION_QUEUE_CAPACITY);
                let association = Arc::new(XudpAssociation {
                    global_id,
                    status: Mutex::new(XudpStatus::Initializing),
                    outbound: Mutex::new(None),
                    uplink_tx: Mutex::new(uplink_tx),
                    attached: Mutex::new(None),
                    expire_at: Mutex::new(None),
                    downlink_tx: Mutex::new(downlink_tx),
                    tasks: Mutex::new(XudpTaskHandles {
                        uplink: None,
                        downlink: None,
                        response: None,
                    }),
                    stats: route_env.stats.clone(),
                    healthy: AtomicBool::new(true),
                });
                start_association_workers(&association, uplink_rx, downlink_rx).await;
                map.insert(global_id, Arc::clone(&association));
                association
            }
        };

        let first_open = association.outbound.lock().await.is_none();

        let initialize = async {
            if !first_open {
                Self::detach_response_target(&association).await;
                if !Self::forward_packet(&association, Some(&destination), &packet).await {
                    self.rebuild_outbound(&association, &destination, route_env)
                        .await?;
                    if !Self::forward_packet(&association, Some(&destination), &packet).await {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "rebuilt xudp association rejected first packet",
                        ));
                    }
                }
            } else {
                self.create_routed_outbound(&association, &destination, route_env)
                    .await?;
                if !Self::forward_packet(&association, Some(&destination), &packet).await {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "new xudp association rejected first packet",
                    ));
                }
            }
            Ok(())
        }
        .await;

        if let Err(err) = initialize {
            self.remove_association_if_same(global_id, &association)
                .await;
            return Err(err);
        }

        Self::attach_response_target(&association, mux_id, udp_tx).await;
        *association.status.lock().await = XudpStatus::Active;

        debug!(mux_id, global_id = ?global_id, first_open, "xudp association active");
        Ok(mux_actions(Vec::new()))
    }

    pub async fn handle_keep(
        &self,
        mux_id: u16,
        global_id: MuxGlobalId,
        destination: Option<&VlessDestination>,
        packet: &[u8],
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
            debug!(
                path = "xudp",
                mux_id,
                global_id = ?global_id,
                destination_override = destination.is_some(),
                packet_len = packet.len(),
                "mux keep routed to existing xudp association"
            );
            Self::forward_packet(&association, destination, packet).await;
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

    async fn sweep_expired(&self) {
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
            self.remove_association_if_expired(global_id, now).await;
        }
    }

    async fn remove_association_if_expired(&self, global_id: MuxGlobalId, now: Instant) {
        let association = {
            let mut map = self.inner.lock().await;
            let Some(association) = map.get(&global_id).cloned() else {
                return;
            };
            let status = *association.status.lock().await;
            let expire_at = *association.expire_at.lock().await;
            if status != XudpStatus::Expiring || !expire_at.is_some_and(|deadline| now >= deadline)
            {
                return;
            }
            map.remove(&global_id)
        };
        if let Some(association) = association {
            abort_association_tasks(&association).await;
            debug!(global_id = ?global_id, "xudp association expired");
        }
    }

    async fn remove_association_if_same(
        &self,
        global_id: MuxGlobalId,
        expected: &Arc<XudpAssociation>,
    ) {
        let association = {
            let mut map = self.inner.lock().await;
            match map.get(&global_id) {
                Some(current) if Arc::ptr_eq(current, expected) => map.remove(&global_id),
                _ => None,
            }
        };
        if let Some(association) = association {
            abort_association_tasks(&association).await;
        }
    }

    async fn rebuild_outbound(
        &self,
        association: &Arc<XudpAssociation>,
        destination: &VlessDestination,
        route_env: &MuxRouteEnv,
    ) -> std::io::Result<()> {
        abort_association_tasks(association).await;
        *association.outbound.lock().await = None;
        let (uplink_tx, uplink_rx) = mpsc::channel(MUX_UDP_ASSOCIATION_QUEUE_CAPACITY);
        let (downlink_tx, downlink_rx) = mpsc::channel(MUX_UDP_ASSOCIATION_QUEUE_CAPACITY);
        *association.uplink_tx.lock().await = uplink_tx;
        *association.downlink_tx.lock().await = downlink_tx;
        association.healthy.store(true, Ordering::Release);
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
        let outbound = RoutedUdpAssociation::connect(destination, Some(route_env)).await?;
        let spawn_downlink = outbound.has_downlink();
        *association.outbound.lock().await = Some(outbound);
        if spawn_downlink {
            ensure_downlink_task(association).await;
        }
        Ok(())
    }

    async fn forward_packet(
        association: &Arc<XudpAssociation>,
        destination: Option<&VlessDestination>,
        packet: &[u8],
    ) -> bool {
        if !association.healthy.load(Ordering::Acquire) {
            return false;
        }
        association
            .uplink_tx
            .lock()
            .await
            .send(XudpPacket {
                destination: destination.cloned(),
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
    pub(crate) async fn break_uplink_for_test(&self, global_id: MuxGlobalId) {
        let association = {
            let map = self.inner.lock().await;
            map.get(&global_id).cloned()
        };
        let Some(association) = association else {
            return;
        };
        abort_association_tasks(&association).await;
        association.healthy.store(false, Ordering::Release);
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        *association.uplink_tx.lock().await = tx;
    }

    #[cfg(test)]
    pub(crate) async fn force_status_for_test(&self, global_id: MuxGlobalId, status: XudpStatus) {
        if let Some(association) = self.inner.lock().await.get(&global_id) {
            *association.status.lock().await = status;
        }
    }

    #[cfg(test)]
    pub(crate) async fn association_count(&self) -> usize {
        self.inner.lock().await.len()
    }

    #[cfg(test)]
    pub(crate) async fn status_of(&self, global_id: MuxGlobalId) -> Option<XudpStatus> {
        let association = {
            let map = self.inner.lock().await;
            map.get(&global_id).cloned()
        };
        match association {
            Some(association) => Some(*association.status.lock().await),
            None => None,
        }
    }

    #[cfg(test)]
    pub(crate) async fn remove_expired_candidate_for_test(&self, global_id: MuxGlobalId) {
        self.remove_association_if_expired(global_id, Instant::now())
            .await;
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
            match outbound
                .send_to(packet.destination.as_ref(), &packet.payload)
                .await
            {
                Ok(()) => {
                    if let Some(stats) = uplink_association.stats.as_ref() {
                        stats.record_uplink(packet.payload.len() as u64);
                    }
                }
                Err(err) => {
                    uplink_association.healthy.store(false, Ordering::Release);
                    warn!(
                        global_id = ?uplink_association.global_id,
                        destination_override = packet.destination.is_some(),
                        error = %err,
                        "xudp uplink send failed"
                    );
                    break;
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
            match attached.tx.try_send(mux_actions(vec![frame])) {
                Ok(()) => {
                    if let Some(stats) = response_association.stats.as_ref() {
                        stats.record_downlink(payload.len() as u64);
                    }
                }
                Err(err) => warn!(
                    global_id = ?response_association.global_id,
                    mux_id = attached.mux_id,
                    error = %err,
                    "xudp parent response queue unavailable"
                ),
            }
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
    let Some(outbound) = outbound.filter(RoutedUdpAssociation::has_downlink) else {
        return;
    };
    let downlink_tx = association.downlink_tx.lock().await.clone();
    let global_id = association.global_id;
    let association_health = Arc::clone(association);
    let downlink = tokio::spawn(async move {
        let mut buf = vec![0u8; XUDP_MAX_PACKET_LEN];
        loop {
            match outbound.recv_from(&mut buf).await {
                Ok(Some((len, destination))) => {
                    let payload = buf[..len].to_vec();
                    if downlink_tx.send((destination, payload)).await.is_err() {
                        association_health.healthy.store(false, Ordering::Release);
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    association_health.healthy.store(false, Ordering::Release);
                    warn!(global_id = ?global_id, error = %err, "xudp downlink recv failed");
                    break;
                }
            }
        }
    });
    tasks.downlink = Some(downlink);
}

async fn abort_association_tasks(association: &Arc<XudpAssociation>) {
    let handles = {
        let mut tasks = association.tasks.lock().await;
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
}

impl Drop for XudpManager {
    fn drop(&mut self) {
        if let Some(task) = self.sweeper.lock().expect("xudp sweeper lock").take() {
            task.abort();
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

    pub async fn register(&self, mux_id: u16, global_id: MuxGlobalId) -> Option<MuxGlobalId> {
        self.by_mux_id.lock().await.insert(mux_id, global_id)
    }

    pub async fn global_id(&self, mux_id: u16) -> Option<MuxGlobalId> {
        self.by_mux_id.lock().await.get(&mux_id).copied()
    }

    pub async fn remove(&self, mux_id: u16) -> Option<MuxGlobalId> {
        self.by_mux_id.lock().await.remove(&mux_id)
    }

    pub(crate) async fn drain(&self) -> Vec<(u16, MuxGlobalId)> {
        self.by_mux_id.lock().await.drain().collect()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/mux/xudp.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/mux/xudp_reality_overflow.rs"]
mod reality_overflow_tests;
