//! Stream-up upload/download session runtime (separate from packet-up).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::bridge::run_packet_up_bridge;
use super::mode::EffectiveXHttpMode;
use super::packet_up_input::{
    PacketUpBoundedInput, PacketUpInputError, PacketUpSessionInputReader,
};
use super::session::{XHttpSessionEnsureOutcome, XHttpSessionError, XHttpSessionManager};
use crate::config::XHttpSettings;
use crate::stats::StatsState;
use crate::vless::VlessUserManager;

const STREAM_UP_DOWNLOAD_CHANNEL: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamUpLimits {
    pub max_upload_bytes: u64,
}

impl StreamUpLimits {
    pub fn from_settings(settings: &XHttpSettings) -> Self {
        Self {
            max_upload_bytes: settings.sc_max_each_post_bytes(),
        }
    }
}

pub struct XHttpStreamUpManager {
    sessions: Mutex<HashMap<String, Arc<StreamUpSessionRuntime>>>,
    meta: XHttpSessionManager,
    test_input_override: Mutex<Option<(usize, usize)>>,
}

pub(crate) struct StreamUpBridgeLaunch {
    pub(crate) session_id: String,
    pub(crate) reader: PacketUpSessionInputReader,
    pub(crate) runtime: Arc<StreamUpSessionRuntime>,
}

#[derive(Debug)]
pub struct StreamUpUploadHandle {
    pub session_id: String,
    pub session_outcome: XHttpSessionEnsureOutcome,
    limits: StreamUpLimits,
    upload_bytes: u64,
}

pub(crate) struct StreamUpSessionRuntime {
    session_id: String,
    input: PacketUpBoundedInput,
    bridge_started: AtomicBool,
    upload_attached: AtomicBool,
    bytes_streamed: AtomicU64,
    download_listeners: Mutex<Vec<mpsc::Sender<Bytes>>>,
    pending_download: Mutex<Vec<Bytes>>,
}

impl XHttpStreamUpManager {
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
            .expect("stream-up test input override lock poisoned") =
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

    pub fn download_wait_timeout(&self, session_id: &str) -> Duration {
        let runtime = self.get_or_create_runtime(session_id);
        if runtime.upload_attached.load(Ordering::SeqCst)
            || runtime.bytes_streamed.load(Ordering::SeqCst) > 0
            || runtime.bridge_started.load(Ordering::SeqCst)
        {
            Duration::from_secs(120)
        } else {
            Duration::from_secs(30)
        }
    }

    pub fn upload_attached_for(&self, session_id: &str) -> bool {
        self.get_or_create_runtime(session_id)
            .upload_attached
            .load(Ordering::SeqCst)
    }

    fn touch_active_sessions(&self) {
        let sessions = self
            .sessions
            .lock()
            .expect("stream-up sessions lock poisoned");
        for (session_id, runtime) in sessions.iter() {
            let has_download = !runtime
                .download_listeners
                .lock()
                .expect("stream-up download listeners lock poisoned")
                .is_empty();
            if runtime.upload_attached.load(Ordering::SeqCst)
                || runtime.bridge_started.load(Ordering::SeqCst)
                || has_download
            {
                let _ = self.meta.touch(session_id);
            }
        }
    }

    fn ensure_stream_up_session(
        &self,
        session_id: &str,
    ) -> Result<XHttpSessionEnsureOutcome, XHttpSessionError> {
        self.touch_active_sessions();
        self.meta
            .ensure_session(session_id, EffectiveXHttpMode::StreamUp)
    }
    pub fn attach_upload(
        &self,
        session_id: &str,
        limits: StreamUpLimits,
    ) -> Result<StreamUpUploadHandle, XHttpSessionError> {
        let session_outcome = self.ensure_stream_up_session(session_id)?;
        match session_outcome {
            XHttpSessionEnsureOutcome::Created => {
                debug!(session_id = %session_id, "xhttp stream-up session created");
            }
            XHttpSessionEnsureOutcome::Reused => {
                debug!(session_id = %session_id, "xhttp stream-up session reused");
            }
        }

        let runtime = self.get_or_create_runtime(session_id);
        if runtime
            .upload_attached
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(XHttpSessionError::UploadAlreadyAttached);
        }

        Ok(StreamUpUploadHandle {
            session_id: session_id.to_string(),
            session_outcome,
            limits,
            upload_bytes: 0,
        })
    }

    pub(crate) fn append_upload_chunk(
        &self,
        handle: &mut StreamUpUploadHandle,
        chunk: Bytes,
    ) -> Result<(), StreamUpUploadError> {
        if chunk.is_empty() {
            return Ok(());
        }
        let new_total = handle.upload_bytes.saturating_add(chunk.len() as u64);
        if new_total > handle.limits.max_upload_bytes {
            return Err(StreamUpUploadError::UploadTooLarge {
                max_bytes: handle.limits.max_upload_bytes,
                received: new_total,
            });
        }
        handle.upload_bytes = new_total;
        let runtime = self.get_or_create_runtime(&handle.session_id);
        self.touch_session(&handle.session_id);
        self.write_input(runtime.as_ref(), chunk)
    }

    pub(crate) fn launch_upload_bridge(
        &self,
        session_id: &str,
    ) -> Result<Option<StreamUpBridgeLaunch>, StreamUpUploadError> {
        let runtime = self.get_or_create_runtime(session_id);
        self.try_launch_bridge(runtime.as_ref())
    }

    pub fn finish_upload(&self, session_id: &str) {
        let runtime = self.get_or_create_runtime(session_id);
        runtime.upload_attached.store(false, Ordering::SeqCst);
        runtime.input.close();
        self.touch_session(session_id);
        debug!(session_id = %session_id, "xhttp stream-up upload stream finished");
    }

    pub fn bind_download_session(
        &self,
        session_id: &str,
    ) -> Result<mpsc::Receiver<Bytes>, XHttpSessionError> {
        let session_outcome = self.ensure_stream_up_session(session_id)?;
        match session_outcome {
            XHttpSessionEnsureOutcome::Created => {
                debug!(session_id = %session_id, "xhttp stream-up session created");
            }
            XHttpSessionEnsureOutcome::Reused => {
                debug!(session_id = %session_id, "xhttp stream-up session reused");
            }
        }
        let runtime = self.get_or_create_runtime(session_id);
        {
            let mut listeners = runtime
                .download_listeners
                .lock()
                .expect("stream-up download listeners lock poisoned");
            listeners.retain(|tx| !tx.is_closed());
            if !listeners.is_empty() {
                return Err(XHttpSessionError::DownloadAlreadyAttached);
            }
        }
        let (tx, rx) = mpsc::channel(STREAM_UP_DOWNLOAD_CHANNEL);
        {
            let mut listeners = runtime
                .download_listeners
                .lock()
                .expect("stream-up download listeners lock poisoned");
            let pending = std::mem::take(
                &mut *runtime
                    .pending_download
                    .lock()
                    .expect("stream-up pending download lock poisoned"),
            );
            for chunk in pending {
                let _ = tx.try_send(chunk);
            }
            listeners.push(tx);
        }
        Ok(rx)
    }

    pub fn detach_download_session(&self, session_id: &str) {
        if let Ok(runtime) = self.runtime_for_existing(session_id) {
            runtime
                .download_listeners
                .lock()
                .expect("stream-up download listeners lock poisoned")
                .clear();
        }
    }

    pub fn cleanup_idle_sessions(&self) -> usize {
        let now = Instant::now();
        let idle_timeout = self.meta.idle_timeout();
        let stale_ids: Vec<String> = self
            .sessions
            .lock()
            .expect("stream-up sessions lock poisoned")
            .iter()
            .filter_map(|(session_id, runtime)| {
                if runtime.upload_attached.load(Ordering::SeqCst)
                    || runtime.bridge_started.load(Ordering::SeqCst)
                    || !runtime
                        .download_listeners
                        .lock()
                        .expect("stream-up download listeners lock poisoned")
                        .is_empty()
                {
                    return None;
                }
                match self.meta.get(session_id) {
                    Ok(session) => {
                        let idle = now
                            .checked_duration_since(session.last_seen)
                            .unwrap_or(Duration::ZERO)
                            >= idle_timeout;
                        idle.then(|| session_id.clone())
                    }
                    Err(_) => Some(session_id.clone()),
                }
            })
            .collect();
        let mut removed = 0usize;
        for session_id in stale_ids {
            if self.meta.close(&session_id, "idle_timeout").is_ok() {
                removed += 1;
            }
            let mut sessions = self
                .sessions
                .lock()
                .expect("stream-up sessions lock poisoned");
            if let Some(runtime) = sessions.remove(&session_id) {
                runtime.input.close();
            }
        }
        removed
    }

    pub fn close_session(&self, session_id: &str, reason: &str) {
        let _ = self.meta.close(session_id, reason);
        let mut sessions = self
            .sessions
            .lock()
            .expect("stream-up sessions lock poisoned");
        if let Some(runtime) = sessions.remove(session_id) {
            runtime.input.close();
        }
    }

    pub fn touch_session(&self, session_id: &str) {
        let _ = self.meta.touch(session_id);
    }

    fn runtime_for(&self, session_id: &str) -> Arc<StreamUpSessionRuntime> {
        let input = {
            let override_limits = self
                .test_input_override
                .lock()
                .expect("stream-up test input override lock poisoned");
            if let Some((max_queued, slots)) = *override_limits {
                PacketUpBoundedInput::for_test(max_queued, slots)
            } else {
                PacketUpBoundedInput::from_env()
            }
        };
        Arc::new(StreamUpSessionRuntime {
            session_id: session_id.to_string(),
            input,
            bridge_started: AtomicBool::new(false),
            upload_attached: AtomicBool::new(false),
            bytes_streamed: AtomicU64::new(0),
            download_listeners: Mutex::new(Vec::new()),
            pending_download: Mutex::new(Vec::new()),
        })
    }

    fn runtime_for_existing(
        &self,
        session_id: &str,
    ) -> Result<Arc<StreamUpSessionRuntime>, XHttpSessionError> {
        self.sessions
            .lock()
            .expect("stream-up sessions lock poisoned")
            .get(session_id)
            .cloned()
            .ok_or(XHttpSessionError::SessionNotFound)
    }

    pub(crate) fn get_or_create_runtime(&self, session_id: &str) -> Arc<StreamUpSessionRuntime> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("stream-up sessions lock poisoned");
        if let Some(runtime) = sessions.get(session_id) {
            return Arc::clone(runtime);
        }
        let runtime = self.runtime_for(session_id);
        sessions.insert(session_id.to_string(), Arc::clone(&runtime));
        runtime
    }

    fn write_input(
        &self,
        runtime: &StreamUpSessionRuntime,
        chunk: Bytes,
    ) -> Result<(), StreamUpUploadError> {
        let len = chunk.len() as u64;
        runtime
            .input
            .try_write_chunk(chunk)
            .map_err(|err| match err {
                PacketUpInputError::SessionClosed => StreamUpUploadError::UploadClosed,
                PacketUpInputError::Backpressure => StreamUpUploadError::Backpressure,
            })?;
        runtime.bytes_streamed.fetch_add(len, Ordering::SeqCst);
        Ok(())
    }

    fn try_launch_bridge(
        &self,
        runtime: &StreamUpSessionRuntime,
    ) -> Result<Option<StreamUpBridgeLaunch>, StreamUpUploadError> {
        if runtime
            .bridge_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(None);
        }

        let Some(reader) = runtime.input.take_reader() else {
            runtime.bridge_started.store(false, Ordering::SeqCst);
            return Err(StreamUpUploadError::UploadClosed);
        };

        Ok(Some(StreamUpBridgeLaunch {
            session_id: runtime.session_id.clone(),
            reader,
            runtime: self.get_or_create_runtime(&runtime.session_id),
        }))
    }
}

pub(crate) fn broadcast_download(runtime: &StreamUpSessionRuntime, chunk: Bytes) {
    if chunk.is_empty() {
        return;
    }
    let mut listeners = runtime
        .download_listeners
        .lock()
        .expect("stream-up download listeners lock poisoned");
    if listeners.is_empty() {
        runtime
            .pending_download
            .lock()
            .expect("stream-up pending download lock poisoned")
            .push(chunk);
        return;
    }
    listeners.retain(|tx| tx.try_send(chunk.clone()).is_ok());
}

pub(crate) fn spawn_stream_up_bridge(
    launch: StreamUpBridgeLaunch,
    users: Arc<VlessUserManager>,
    stats_state: Option<StatsState>,
    inbound_tag: String,
    conn_id: u64,
) {
    let session_id = launch.session_id.clone();
    let runtime_for_download = Arc::clone(&launch.runtime);
    let manager = shared_stream_up_manager();
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
                "xhttp stream-up bridge failed"
            );
        } else {
            debug!(
                inbound_tag = %inbound_tag,
                conn_id,
                session_id = %session_id,
                duration_ms = started.elapsed().as_millis(),
                "xhttp stream-up bridge completed"
            );
        }
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamUpUploadError {
    UploadClosed,
    Backpressure,
    UploadTooLarge { max_bytes: u64, received: u64 },
}

impl std::fmt::Display for StreamUpUploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UploadClosed => write!(f, "stream-up upload channel closed"),
            Self::Backpressure => write!(f, "stream-up upload backpressure"),
            Self::UploadTooLarge {
                max_bytes,
                received,
            } => write!(
                f,
                "stream-up upload exceeds scMaxEachPostBytes max={max_bytes} received={received}"
            ),
        }
    }
}

impl std::error::Error for StreamUpUploadError {}

static STREAM_UP_MANAGER: OnceLock<XHttpStreamUpManager> = OnceLock::new();

pub fn shared_stream_up_manager() -> &'static XHttpStreamUpManager {
    STREAM_UP_MANAGER.get_or_init(XHttpStreamUpManager::from_env)
}

#[cfg(test)]
#[path = "../../../tests/unit/transport/xhttp/stream_up.rs"]
mod tests;
