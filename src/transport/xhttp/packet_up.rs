//! Packet-up upload/session runtime with download-side streaming.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::bridge::run_packet_up_bridge;
use super::mode::EffectiveXHttpMode;
use super::packet_up_input::{
    PacketUpBoundedInput, PacketUpInputError, PacketUpSessionInputReader,
};
use super::session::{XHttpSessionEnsureOutcome, XHttpSessionError, XHttpSessionManager};
use crate::stats::StatsState;
use crate::vless::VlessUserManager;

const PACKET_UP_DOWNLOAD_CHANNEL: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketUpLimits {
    pub max_each_post_bytes: u64,
    pub max_buffered_posts: usize,
}

impl PacketUpLimits {
    pub fn from_settings(settings: &crate::config::XHttpSettings) -> Self {
        Self {
            max_each_post_bytes: settings.sc_max_each_post_bytes(),
            max_buffered_posts: settings.sc_max_buffered_posts(),
        }
    }
}

pub struct XHttpPacketUpManager {
    sessions: Mutex<HashMap<String, Arc<PacketUpSessionRuntime>>>,
    meta: XHttpSessionManager,
    test_input_override: Mutex<Option<(usize, usize)>>,
}

pub struct PacketUpBridgeLaunch {
    pub session_id: String,
    pub reader: PacketUpSessionInputReader,
    pub runtime: Arc<PacketUpSessionRuntime>,
}

#[derive(Debug)]
pub struct PacketUpUploadHandle {
    pub session_id: String,
    pub seq: u64,
    pub session_outcome: XHttpSessionEnsureOutcome,
    limits: PacketUpLimits,
    post_bytes: u64,
}

pub struct PacketUpCommitOutcome {
    pub session_outcome: XHttpSessionEnsureOutcome,
    pub bridge_launch: Option<PacketUpBridgeLaunch>,
    pub bytes_appended: usize,
}

struct SeqPacketBuffer {
    chunks: Vec<Bytes>,
    request_complete: bool,
}

pub struct PacketUpSessionRuntime {
    session_id: String,
    input: PacketUpBoundedInput,
    seq_buffers: Mutex<BTreeMap<u64, SeqPacketBuffer>>,
    next_expected_seq: AtomicU64,
    next_arrival_seq: AtomicU64,
    bridge_started: AtomicBool,
    active_uploads: AtomicU32,
    out_of_order_posts: AtomicU32,
    bytes_streamed: AtomicU64,
    download_listeners: Mutex<Vec<mpsc::Sender<Bytes>>>,
}

impl XHttpPacketUpManager {
    pub fn from_env() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            meta: XHttpSessionManager::from_env(),
            test_input_override: Mutex::new(None),
        }
    }

    pub fn for_test(idle_timeout: std::time::Duration, max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            meta: XHttpSessionManager::for_test(idle_timeout, max_sessions),
            test_input_override: Mutex::new(None),
        }
    }

    pub fn for_test_with_input(
        idle_timeout: std::time::Duration,
        max_sessions: usize,
        max_queued_bytes: usize,
        channel_slots: usize,
    ) -> Self {
        let manager = Self::for_test(idle_timeout, max_sessions);
        *manager
            .test_input_override
            .lock()
            .expect("packet-up test input override lock poisoned") =
            Some((max_queued_bytes, channel_slots));
        manager
    }

    pub fn meta_session_count(&self) -> usize {
        self.meta.session_count()
    }

    pub fn bridge_started_for(&self, session_id: &str) -> bool {
        self.get_or_create_runtime(session_id)
            .bridge_started
            .load(Ordering::SeqCst)
    }

    pub fn session_input_closed(&self, session_id: &str) -> bool {
        self.get_or_create_runtime(session_id).input.is_closed()
    }

    pub fn begin_upload_packet(
        &self,
        session_id: &str,
        seq: Option<u64>,
        limits: PacketUpLimits,
    ) -> Result<PacketUpUploadHandle, XHttpSessionError> {
        let session_outcome = self
            .meta
            .ensure_session(session_id, EffectiveXHttpMode::PacketUp)?;
        match session_outcome {
            XHttpSessionEnsureOutcome::Created => {
                debug!(session_id = %session_id, "xhttp packet-up session created");
            }
            XHttpSessionEnsureOutcome::Reused => {
                debug!(session_id = %session_id, "xhttp packet-up session reused");
            }
        }

        let runtime = self.get_or_create_runtime(session_id);
        runtime.active_uploads.fetch_add(1, Ordering::SeqCst);
        let expected = runtime.next_expected_seq.load(Ordering::SeqCst);
        let resolved_seq =
            seq.unwrap_or_else(|| runtime.next_arrival_seq.fetch_add(1, Ordering::SeqCst));
        if resolved_seq > expected {
            let buffered = runtime
                .seq_buffers
                .lock()
                .expect("packet-up seq buffers lock poisoned")
                .len()
                + runtime.out_of_order_posts.load(Ordering::SeqCst) as usize;
            if buffered >= limits.max_buffered_posts {
                runtime.active_uploads.fetch_sub(1, Ordering::SeqCst);
                return Err(XHttpSessionError::MaxSessionsReached);
            }
            runtime.out_of_order_posts.fetch_add(1, Ordering::SeqCst);
        }

        Ok(PacketUpUploadHandle {
            session_id: session_id.to_string(),
            seq: resolved_seq,
            session_outcome,
            limits,
            post_bytes: 0,
        })
    }

    pub fn append_upload_chunk(
        &self,
        handle: &mut PacketUpUploadHandle,
        chunk: Bytes,
    ) -> Result<Option<PacketUpBridgeLaunch>, PacketUpUploadError> {
        if chunk.is_empty() {
            return Ok(None);
        }
        let new_total = handle.post_bytes.saturating_add(chunk.len() as u64);
        if new_total > handle.limits.max_each_post_bytes {
            return Err(PacketUpUploadError::PostTooLarge {
                max_bytes: handle.limits.max_each_post_bytes,
                received: new_total,
            });
        }
        handle.post_bytes = new_total;
        let runtime = self.get_or_create_runtime(&handle.session_id);
        self.touch_session(&handle.session_id);
        let expected = runtime.next_expected_seq.load(Ordering::SeqCst);
        if handle.seq == expected {
            self.write_input(runtime.as_ref(), chunk)?;
            Ok(self.try_launch_bridge(runtime.as_ref())?)
        } else if handle.seq > expected {
            runtime
                .seq_buffers
                .lock()
                .expect("packet-up seq buffers lock poisoned")
                .entry(handle.seq)
                .or_insert_with(|| SeqPacketBuffer {
                    chunks: Vec::new(),
                    request_complete: false,
                })
                .chunks
                .push(chunk);
            Ok(None)
        } else {
            Err(PacketUpUploadError::StaleSeq {
                expected,
                received: handle.seq,
            })
        }
    }

    pub fn commit_upload_packet(
        &self,
        handle: &PacketUpUploadHandle,
    ) -> Result<PacketUpCommitOutcome, PacketUpUploadError> {
        let runtime = self.get_or_create_runtime(&handle.session_id);
        self.touch_session(&handle.session_id);
        let expected = runtime.next_expected_seq.load(Ordering::SeqCst);

        if handle.seq == expected {
            runtime
                .next_expected_seq
                .store(expected + 1, Ordering::SeqCst);
        } else if handle.seq > expected {
            runtime
                .seq_buffers
                .lock()
                .expect("packet-up seq buffers lock poisoned")
                .entry(handle.seq)
                .or_insert_with(|| SeqPacketBuffer {
                    chunks: Vec::new(),
                    request_complete: false,
                })
                .request_complete = true;
            runtime.out_of_order_posts.fetch_sub(1, Ordering::SeqCst);
        } else {
            return Err(PacketUpUploadError::StaleSeq {
                expected,
                received: handle.seq,
            });
        }

        let mut bridge_launch = self.flush_ready_seq_buffers(runtime.as_ref())?;
        if bridge_launch.is_none() {
            bridge_launch = self.try_launch_bridge(runtime.as_ref())?;
        }

        if runtime.bytes_streamed.load(Ordering::SeqCst) > 0 {
            debug!(
                session_id = %handle.session_id,
                seq = handle.seq,
                bytes = runtime.bytes_streamed.load(Ordering::SeqCst),
                "xhttp packet-up body appended"
            );
        }

        Ok(PacketUpCommitOutcome {
            session_outcome: handle.session_outcome,
            bridge_launch,
            bytes_appended: runtime.bytes_streamed.load(Ordering::SeqCst) as usize,
        })
    }

    pub fn finish_upload_packet(&self, session_id: &str) {
        let runtime = self.get_or_create_runtime(session_id);
        let prev = runtime.active_uploads.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            runtime.active_uploads.store(0, Ordering::SeqCst);
        }
        self.touch_session(session_id);
        debug!(session_id = %session_id, "xhttp packet-up request completed");
    }

    pub fn bind_download_session(
        &self,
        session_id: &str,
    ) -> Result<mpsc::Receiver<Bytes>, XHttpSessionError> {
        let session_outcome = self
            .meta
            .ensure_session(session_id, EffectiveXHttpMode::PacketUp)?;
        match session_outcome {
            XHttpSessionEnsureOutcome::Created => {
                debug!(session_id = %session_id, "xhttp packet-up session created");
            }
            XHttpSessionEnsureOutcome::Reused => {
                debug!(session_id = %session_id, "xhttp packet-up session reused");
            }
        }
        let runtime = self.get_or_create_runtime(session_id);
        {
            let mut listeners = runtime
                .download_listeners
                .lock()
                .expect("packet-up download listeners lock poisoned");
            listeners.retain(|tx| !tx.is_closed());
            if !listeners.is_empty() {
                return Err(XHttpSessionError::DownloadAlreadyAttached);
            }
        }
        let (tx, rx) = mpsc::channel(PACKET_UP_DOWNLOAD_CHANNEL);
        runtime
            .download_listeners
            .lock()
            .expect("packet-up download listeners lock poisoned")
            .push(tx);
        Ok(rx)
    }

    pub fn detach_download_session(&self, session_id: &str) {
        if let Ok(runtime) = self.runtime_for_existing(session_id) {
            runtime
                .download_listeners
                .lock()
                .expect("packet-up download listeners lock poisoned")
                .clear();
        }
    }

    pub fn cleanup_idle_sessions(&self) -> usize {
        let removed = self.meta.cleanup_idle();
        let mut sessions = self
            .sessions
            .lock()
            .expect("packet-up sessions lock poisoned");
        sessions.retain(|session_id, runtime| {
            if self.meta.get(session_id).is_err() {
                runtime.input.close();
                false
            } else {
                true
            }
        });
        removed
    }

    pub fn close_session(&self, session_id: &str, reason: &str) {
        if self.meta.close(session_id, reason).is_ok() {
            let mut sessions = self
                .sessions
                .lock()
                .expect("packet-up sessions lock poisoned");
            if let Some(runtime) = sessions.remove(session_id) {
                runtime.input.close();
            }
        } else {
            let mut sessions = self
                .sessions
                .lock()
                .expect("packet-up sessions lock poisoned");
            if let Some(runtime) = sessions.remove(session_id) {
                runtime.input.close();
            }
        }
    }

    fn touch_session(&self, session_id: &str) {
        let _ = self
            .meta
            .ensure_session(session_id, EffectiveXHttpMode::PacketUp);
    }

    fn runtime_for(&self, session_id: &str) -> Arc<PacketUpSessionRuntime> {
        let input = {
            let override_limits = self
                .test_input_override
                .lock()
                .expect("packet-up test input override lock poisoned");
            if let Some((max_queued, slots)) = *override_limits {
                PacketUpBoundedInput::for_test(max_queued, slots)
            } else {
                PacketUpBoundedInput::from_env()
            }
        };
        Arc::new(PacketUpSessionRuntime {
            session_id: session_id.to_string(),
            input,
            seq_buffers: Mutex::new(BTreeMap::new()),
            next_expected_seq: AtomicU64::new(0),
            next_arrival_seq: AtomicU64::new(0),
            bridge_started: AtomicBool::new(false),
            active_uploads: AtomicU32::new(0),
            out_of_order_posts: AtomicU32::new(0),
            bytes_streamed: AtomicU64::new(0),
            download_listeners: Mutex::new(Vec::new()),
        })
    }

    fn runtime_for_existing(
        &self,
        session_id: &str,
    ) -> Result<Arc<PacketUpSessionRuntime>, XHttpSessionError> {
        self.sessions
            .lock()
            .expect("packet-up sessions lock poisoned")
            .get(session_id)
            .cloned()
            .ok_or(XHttpSessionError::SessionNotFound)
    }

    pub(crate) fn get_or_create_runtime(&self, session_id: &str) -> Arc<PacketUpSessionRuntime> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("packet-up sessions lock poisoned");
        if let Some(runtime) = sessions.get(session_id) {
            return Arc::clone(runtime);
        }
        let runtime = self.runtime_for(session_id);
        sessions.insert(session_id.to_string(), Arc::clone(&runtime));
        runtime
    }

    fn write_input(
        &self,
        runtime: &PacketUpSessionRuntime,
        chunk: Bytes,
    ) -> Result<(), PacketUpUploadError> {
        let len = chunk.len() as u64;
        runtime
            .input
            .try_write_chunk(chunk)
            .map_err(|err| match err {
                PacketUpInputError::SessionClosed => PacketUpUploadError::UploadClosed,
                PacketUpInputError::Backpressure => PacketUpUploadError::Backpressure,
            })?;
        runtime.bytes_streamed.fetch_add(len, Ordering::SeqCst);
        Ok(())
    }

    fn flush_ready_seq_buffers(
        &self,
        runtime: &PacketUpSessionRuntime,
    ) -> Result<Option<PacketUpBridgeLaunch>, PacketUpUploadError> {
        let mut launch = None;
        loop {
            let expected = runtime.next_expected_seq.load(Ordering::SeqCst);
            let chunks = {
                let mut buffers = runtime
                    .seq_buffers
                    .lock()
                    .expect("packet-up seq buffers lock poisoned");
                let Some(buffer) = buffers.get(&expected) else {
                    break;
                };
                if !buffer.request_complete {
                    break;
                }
                let chunks = std::mem::take(&mut buffers.get_mut(&expected).unwrap().chunks);
                buffers.remove(&expected);
                chunks
            };
            for chunk in chunks {
                self.write_input(runtime, chunk)?;
            }
            runtime
                .next_expected_seq
                .store(expected + 1, Ordering::SeqCst);
            if launch.is_none() {
                launch = self.try_launch_bridge(runtime)?;
            }
        }
        Ok(launch)
    }

    fn try_launch_bridge(
        &self,
        runtime: &PacketUpSessionRuntime,
    ) -> Result<Option<PacketUpBridgeLaunch>, PacketUpUploadError> {
        if runtime.bytes_streamed.load(Ordering::SeqCst) == 0 {
            return Ok(None);
        }
        if runtime
            .bridge_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(None);
        }

        let Some(reader) = runtime.input.take_reader() else {
            runtime.bridge_started.store(false, Ordering::SeqCst);
            return Err(PacketUpUploadError::UploadClosed);
        };

        Ok(Some(PacketUpBridgeLaunch {
            session_id: runtime.session_id.clone(),
            reader,
            runtime: self.get_or_create_runtime(&runtime.session_id),
        }))
    }
}

pub fn broadcast_download(runtime: &PacketUpSessionRuntime, chunk: Bytes) {
    let mut listeners = runtime
        .download_listeners
        .lock()
        .expect("packet-up download listeners lock poisoned");
    listeners.retain(|tx| tx.try_send(chunk.clone()).is_ok());
}

pub fn spawn_packet_up_bridge(
    launch: PacketUpBridgeLaunch,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
    inbound_tag: String,
    conn_id: u64,
) {
    let session_id = launch.session_id.clone();
    let runtime_for_download = Arc::clone(&launch.runtime);
    let manager = shared_packet_up_manager();
    tokio::spawn(async move {
        let started = Instant::now();
        let result = run_packet_up_bridge(
            launch.reader,
            move |chunk| broadcast_download(&runtime_for_download, chunk),
            &inbound_tag,
            conn_id,
            &session_id,
            &users,
            stats_state.as_ref(),
        )
        .await;
        manager.close_session(&session_id, "bridge_completed");
        if let Err(err) = result {
            warn!(
                inbound_tag = %inbound_tag,
                conn_id,
                session_id = %session_id,
                error = %err,
                "xhttp packet-up bridge failed"
            );
        } else {
            debug!(
                inbound_tag = %inbound_tag,
                conn_id,
                session_id = %session_id,
                duration_ms = started.elapsed().as_millis(),
                "xhttp packet-up bridge completed"
            );
        }
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketUpUploadError {
    UploadClosed,
    Backpressure,
    StaleSeq { expected: u64, received: u64 },
    PostTooLarge { max_bytes: u64, received: u64 },
}

impl std::fmt::Display for PacketUpUploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UploadClosed => write!(f, "packet-up upload channel closed"),
            Self::Backpressure => write!(f, "packet-up upload backpressure"),
            Self::StaleSeq { expected, received } => {
                write!(
                    f,
                    "packet-up stale seq expected={expected} received={received}"
                )
            }
            Self::PostTooLarge {
                max_bytes,
                received,
            } => {
                write!(
                    f,
                    "packet-up post exceeds scMaxEachPostBytes max={max_bytes} received={received}"
                )
            }
        }
    }
}

impl std::error::Error for PacketUpUploadError {}

static PACKET_UP_MANAGER: OnceLock<XHttpPacketUpManager> = OnceLock::new();

pub fn shared_packet_up_manager() -> &'static XHttpPacketUpManager {
    PACKET_UP_MANAGER.get_or_init(XHttpPacketUpManager::from_env)
}

#[cfg(test)]
#[path = "../../../tests/unit/transport/xhttp/packet_up.rs"]
mod tests;
