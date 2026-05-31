//! Packet-up upload/session skeleton.
//!
//! Not enabled for end-to-end runtime until download side is implemented.

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

pub struct PacketUpUploadHandle {
    pub session_id: String,
    pub seq: u64,
    pub session_outcome: XHttpSessionEnsureOutcome,
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
        let resolved_seq =
            seq.unwrap_or_else(|| runtime.next_arrival_seq.fetch_add(1, Ordering::SeqCst));

        Ok(PacketUpUploadHandle {
            session_id: session_id.to_string(),
            seq: resolved_seq,
            session_outcome,
        })
    }

    pub fn append_upload_chunk(
        &self,
        handle: &PacketUpUploadHandle,
        chunk: Bytes,
    ) -> Result<Option<PacketUpBridgeLaunch>, PacketUpUploadError> {
        if chunk.is_empty() {
            return Ok(None);
        }
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
        let (tx, rx) = mpsc::channel(PACKET_UP_DOWNLOAD_CHANNEL);
        runtime
            .download_listeners
            .lock()
            .expect("packet-up download listeners lock poisoned")
            .push(tx);
        Ok(rx)
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
            bytes_streamed: AtomicU64::new(0),
            download_listeners: Mutex::new(Vec::new()),
        })
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
        }
    }
}

impl std::error::Error for PacketUpUploadError {}

static PACKET_UP_MANAGER: OnceLock<XHttpPacketUpManager> = OnceLock::new();

pub fn shared_packet_up_manager() -> &'static XHttpPacketUpManager {
    PACKET_UP_MANAGER.get_or_init(XHttpPacketUpManager::from_env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;
    use tokio::io::AsyncReadExt;

    async fn take_reader_from_launch(launch: PacketUpBridgeLaunch) -> PacketUpSessionInputReader {
        launch.reader
    }

    #[test]
    fn first_packet_creates_session_second_reuses() {
        let manager = XHttpPacketUpManager::for_test(std::time::Duration::from_secs(30), 8);
        let first = manager
            .begin_upload_packet("session-a", Some(0))
            .expect("first");
        assert_eq!(first.session_outcome, XHttpSessionEnsureOutcome::Created);
        assert_eq!(manager.meta_session_count(), 1);

        let second = manager
            .begin_upload_packet("session-a", Some(1))
            .expect("second");
        assert_eq!(second.session_outcome, XHttpSessionEnsureOutcome::Reused);
        assert_eq!(manager.meta_session_count(), 1);
    }

    #[tokio::test]
    async fn multiple_packet_bodies_form_continuous_input_stream() {
        let manager = XHttpPacketUpManager::for_test_with_input(
            std::time::Duration::from_secs(30),
            8,
            64 * 1024,
            8,
        );
        let p0 = manager
            .begin_upload_packet("session-a", Some(0))
            .expect("p0");
        let launch = manager
            .append_upload_chunk(&p0, Bytes::from_static(b"hel"))
            .expect("c0")
            .expect("bridge");
        manager.commit_upload_packet(&p0).expect("commit0");
        manager.finish_upload_packet("session-a");

        let p1 = manager
            .begin_upload_packet("session-a", Some(1))
            .expect("p1");
        manager
            .append_upload_chunk(&p1, Bytes::from_static(b"lo"))
            .expect("c1");
        manager.commit_upload_packet(&p1).expect("commit1");
        manager.finish_upload_packet("session-a");
        assert!(!manager.session_input_closed("session-a"));

        let mut reader = take_reader_from_launch(launch).await;
        manager.close_session("session-a", "test_done");
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"hello");
    }

    #[tokio::test]
    async fn per_request_eof_does_not_close_session() {
        let manager = XHttpPacketUpManager::for_test_with_input(
            std::time::Duration::from_secs(30),
            8,
            64 * 1024,
            8,
        );
        let p0 = manager
            .begin_upload_packet("session-a", Some(0))
            .expect("p0");
        let bridge_on_append = manager
            .append_upload_chunk(&p0, Bytes::from_static(b"aa"))
            .expect("append");
        manager.commit_upload_packet(&p0).expect("commit");
        manager.finish_upload_packet("session-a");
        assert!(!manager.session_input_closed("session-a"));

        let p1 = manager
            .begin_upload_packet("session-a", Some(1))
            .expect("p1");
        manager
            .append_upload_chunk(&p1, Bytes::from_static(b"bb"))
            .expect("append2");
        manager.commit_upload_packet(&p1).expect("commit2");
        manager.finish_upload_packet("session-a");
        assert!(!manager.session_input_closed("session-a"));
        assert!(bridge_on_append.is_some());
    }

    #[test]
    fn idle_timeout_closes_session() {
        let manager = XHttpPacketUpManager::for_test_with_input(
            std::time::Duration::from_millis(20),
            8,
            64 * 1024,
            8,
        );
        manager
            .begin_upload_packet("session-a", Some(0))
            .expect("begin");
        thread::sleep(StdDuration::from_millis(30));
        let removed = manager.cleanup_idle_sessions();
        assert_eq!(removed, 1);
        assert!(manager.meta.get("session-a").is_err());
    }

    #[tokio::test]
    async fn backpressure_is_bounded() {
        let manager =
            XHttpPacketUpManager::for_test_with_input(std::time::Duration::from_secs(30), 8, 64, 2);
        let handle = manager
            .begin_upload_packet("session-a", Some(0))
            .expect("begin");
        let _launch = manager
            .append_upload_chunk(&handle, Bytes::from(vec![0u8; 32]))
            .expect("chunk1")
            .expect("bridge");
        manager
            .append_upload_chunk(&handle, Bytes::from(vec![0u8; 32]))
            .expect("chunk2");
        assert!(matches!(
            manager.append_upload_chunk(&handle, Bytes::from(vec![0u8; 16])),
            Err(PacketUpUploadError::Backpressure)
        ));
    }

    #[tokio::test]
    async fn vless_bridge_starts_once_per_session() {
        let manager = XHttpPacketUpManager::for_test_with_input(
            std::time::Duration::from_secs(30),
            8,
            64 * 1024,
            8,
        );
        let first = manager
            .begin_upload_packet("session-a", Some(0))
            .expect("begin");
        let bridge_on_first_append = manager
            .append_upload_chunk(&first, Bytes::from_static(b"a"))
            .expect("append");
        let outcome = manager.commit_upload_packet(&first).expect("commit");
        assert!(bridge_on_first_append.is_some());
        assert!(outcome.bridge_launch.is_none());
        assert!(manager.bridge_started_for("session-a"));

        let second = manager
            .begin_upload_packet("session-a", Some(1))
            .expect("begin2");
        manager
            .append_upload_chunk(&second, Bytes::from_static(b"b"))
            .expect("append2");
        let outcome = manager.commit_upload_packet(&second).expect("commit2");
        assert!(outcome.bridge_launch.is_none());
    }

    #[tokio::test]
    async fn body_chunks_appended_in_seq_order() {
        let manager = XHttpPacketUpManager::for_test_with_input(
            std::time::Duration::from_secs(30),
            8,
            64 * 1024,
            8,
        );
        let seq1 = manager
            .begin_upload_packet("session-a", Some(1))
            .expect("begin1");
        manager
            .append_upload_chunk(&seq1, Bytes::from_static(b"b"))
            .expect("append1");
        manager.commit_upload_packet(&seq1).expect("commit1");

        let seq0 = manager
            .begin_upload_packet("session-a", Some(0))
            .expect("begin0");
        let launch = manager
            .append_upload_chunk(&seq0, Bytes::from_static(b"a"))
            .expect("append0")
            .expect("bridge");
        manager.commit_upload_packet(&seq0).expect("commit0");
        let mut reader = take_reader_from_launch(launch).await;
        manager.close_session("session-a", "test_done");
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"ab");
    }

    #[tokio::test]
    async fn vless_handler_close_cleans_session() {
        let manager = XHttpPacketUpManager::for_test_with_input(
            std::time::Duration::from_secs(30),
            8,
            64 * 1024,
            8,
        );
        let handle = manager
            .begin_upload_packet("session-a", Some(0))
            .expect("begin");
        let launch = manager
            .append_upload_chunk(&handle, Bytes::from_static(b"x"))
            .expect("append")
            .expect("launch");
        manager.commit_upload_packet(&handle).expect("commit");
        drop(launch.reader);
        manager.close_session("session-a", "test_reader_drop");
        assert!(manager.meta.get("session-a").is_err());
    }

    #[tokio::test]
    async fn large_packet_stream_does_not_full_buffer() {
        let manager = XHttpPacketUpManager::for_test_with_input(
            std::time::Duration::from_secs(30),
            8,
            8 * 1024,
            4,
        );
        let handle = manager
            .begin_upload_packet("session-a", Some(0))
            .expect("begin");
        let launch = manager
            .append_upload_chunk(&handle, Bytes::from(vec![0xCDu8; 512]))
            .expect("first chunk")
            .expect("bridge");
        let mut reader = take_reader_from_launch(launch).await;

        let read_task = tokio::spawn(async move {
            let mut total = 0usize;
            let mut buf = [0u8; 1024];
            loop {
                let n = reader.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                total += n;
            }
            total
        });

        for _ in 1..64 {
            loop {
                match manager.append_upload_chunk(&handle, Bytes::from(vec![0xCDu8; 512])) {
                    Ok(_) => break,
                    Err(PacketUpUploadError::Backpressure) => {
                        tokio::task::yield_now().await;
                    }
                    Err(err) => panic!("chunk: {err}"),
                }
            }
        }
        manager.commit_upload_packet(&handle).expect("commit");
        manager.finish_upload_packet("session-a");
        manager.close_session("session-a", "test_done");

        let total = read_task.await.expect("read task");
        assert_eq!(total, 64 * 512);
    }
}
