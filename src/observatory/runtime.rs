use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use super::config::ObservatoryRuntimeConfig;
use super::probe::{probe_outbound, ProbeResult, DEAD_PROBE_DELAY_MS};
use crate::api::proto::app::observatory::{ObservationResult, OutboundStatus};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::{OutboundHealthObservation, OutboundHealthProvider};
use crate::runtime::RuntimeOutboundManager;

#[derive(Debug, Default)]
struct StatusStore {
    entries: HashMap<String, OutboundStatus>,
    order: Vec<String>,
}

impl StatusStore {
    fn snapshot(&self) -> ObservationResult {
        ObservationResult {
            status: self
                .order
                .iter()
                .filter_map(|tag| self.entries.get(tag).cloned())
                .collect(),
        }
    }

    fn prune(&mut self, selected: &[String]) {
        self.order.retain(|tag| selected.contains(tag));
        self.entries.retain(|tag, _| selected.contains(tag));
    }

    fn apply_result(&mut self, outbound_tag: &str, result: &ProbeResult) {
        let now = unix_now_secs();
        let entry = self
            .entries
            .entry(outbound_tag.to_string())
            .or_insert_with(|| OutboundStatus {
                outbound_tag: outbound_tag.to_string(),
                ..Default::default()
            });
        if !self.order.iter().any(|tag| tag == outbound_tag) {
            self.order.push(outbound_tag.to_string());
        }
        entry.outbound_tag = outbound_tag.to_string();
        entry.last_try_time = now;
        entry.alive = result.alive;
        entry.health_ping = None;
        if result.alive {
            entry.delay = result.delay_ms;
            entry.last_seen_time = now;
            entry.last_error_reason.clear();
        } else {
            entry.delay = DEAD_PROBE_DELAY_MS;
            entry.last_error_reason = result.last_error_reason.clone();
        }
    }
}

pub struct RuntimeObservatory {
    config: ObservatoryRuntimeConfig,
    outbound: Arc<RuntimeOutboundManager>,
    connect_runtime: Arc<OutboundConnectRuntime>,
    status: RwLock<StatusStore>,
    shutdown: AtomicBool,
    worker_started: AtomicBool,
    worker_notify: Notify,
    worker_handle: Mutex<Option<JoinHandle<()>>>,
    #[doc(hidden)]
    pub test_hooks: Mutex<TestHooks>,
}

#[derive(Default)]
#[doc(hidden)]
pub struct TestHooks {
    pub before_probe: Option<ProbeTagHook>,
    pub after_probe: Option<ProbeTagHook>,
    pub sequential_sleep: Option<ProbeSleepHook>,
}

type ProbeTagHook = Arc<dyn Fn(&str) + Send + Sync>;
type ProbeSleepHook = Arc<dyn Fn() + Send + Sync>;

impl RuntimeObservatory {
    pub fn new(
        config: ObservatoryRuntimeConfig,
        outbound: Arc<RuntimeOutboundManager>,
        connect_runtime: Arc<OutboundConnectRuntime>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            outbound,
            connect_runtime,
            status: RwLock::new(StatusStore::default()),
            shutdown: AtomicBool::new(false),
            worker_started: AtomicBool::new(false),
            worker_notify: Notify::new(),
            worker_handle: Mutex::new(None),
            test_hooks: Mutex::new(TestHooks::default()),
        })
    }

    pub fn config(&self) -> &ObservatoryRuntimeConfig {
        &self.config
    }

    pub fn observation_result(&self) -> ObservationResult {
        self.status
            .read()
            .expect("observatory status lock")
            .snapshot()
    }

    pub fn start(self: &Arc<Self>) {
        if self.config.subject_selector.is_empty() {
            return;
        }
        if self
            .worker_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            this.background_loop().await;
        });
        if let Ok(mut guard) = self.worker_handle.try_lock() {
            *guard = Some(handle);
        }
    }

    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.worker_notify.notify_waiters();
        let handle = self.worker_handle.lock().await.take();
        if let Some(handle) = handle {
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
    }

    /// Run one scheduler round immediately (shared probe path with background worker).
    pub async fn probe_once(self: &Arc<Self>) {
        self.run_round().await;
    }

    /// Wake the background worker to run another round immediately.
    pub fn wake(&self) {
        self.worker_notify.notify_one();
    }

    async fn background_loop(self: Arc<Self>) {
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }

            if self.config.subject_selector.is_empty() {
                if self.wait_next_round().await {
                    break;
                }
                continue;
            }

            let selected = self
                .outbound
                .select_outbounds(&self.config.subject_selector);
            {
                let mut status = self.status.write().expect("observatory status lock");
                status.prune(&selected);
            }

            if selected.is_empty() {
                if self.wait_next_round().await {
                    break;
                }
                continue;
            }

            if self.config.enable_concurrency {
                let mut handles = Vec::with_capacity(selected.len());
                for tag in selected {
                    let this = Arc::clone(&self);
                    handles.push(tokio::spawn(async move {
                        this.probe_and_store(&tag).await;
                    }));
                }
                for handle in handles {
                    if self.shutdown.load(Ordering::Acquire) {
                        handle.abort();
                    } else {
                        let _ = handle.await;
                    }
                }
            } else {
                let mut tags = selected;
                tags.sort();
                for tag in tags {
                    if self.shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    self.probe_and_store(&tag).await;
                    if self.shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    if let Some(hook) = self.test_hooks.lock().await.sequential_sleep.as_ref() {
                        hook();
                    }
                    if self.wait_next_round().await {
                        break;
                    }
                }
                continue;
            }

            if self.wait_next_round().await {
                break;
            }
        }
    }

    async fn wait_next_round(&self) -> bool {
        tokio::select! {
            _ = sleep(self.config.probe_interval) => false,
            _ = self.worker_notify.notified() => self.shutdown.load(Ordering::Acquire),
        }
    }

    async fn run_round(self: &Arc<Self>) {
        if self.config.subject_selector.is_empty() {
            return;
        }
        let selected = self
            .outbound
            .select_outbounds(&self.config.subject_selector);
        {
            let mut status = self.status.write().expect("observatory status lock");
            status.prune(&selected);
        }
        if selected.is_empty() {
            return;
        }

        if self.config.enable_concurrency {
            let mut handles = Vec::with_capacity(selected.len());
            for tag in selected {
                let this = Arc::clone(self);
                handles.push(tokio::spawn(async move {
                    this.probe_and_store(&tag).await;
                }));
            }
            for handle in handles {
                let _ = handle.await;
            }
            return;
        }

        let mut tags = selected;
        tags.sort();
        for tag in tags {
            self.probe_and_store(&tag).await;
        }
    }

    async fn probe_and_store(self: &Arc<Self>, outbound_tag: &str) {
        if let Some(hook) = self.test_hooks.lock().await.before_probe.as_ref() {
            hook(outbound_tag);
        }

        let result = probe_outbound(
            outbound_tag,
            &self.config.probe_url,
            Arc::clone(&self.outbound),
            Arc::clone(&self.connect_runtime),
        )
        .await;

        {
            let mut status = self.status.write().expect("observatory status lock");
            status.apply_result(outbound_tag, &result);
        }

        if let Some(hook) = self.test_hooks.lock().await.after_probe.as_ref() {
            hook(outbound_tag);
        }
    }
}

impl OutboundHealthProvider for RuntimeObservatory {
    fn observations(&self) -> Result<Vec<OutboundHealthObservation>, String> {
        let snapshot = self.observation_result();
        Ok(snapshot
            .status
            .into_iter()
            .map(|status| OutboundHealthObservation {
                outbound_tag: status.outbound_tag,
                alive: status.alive,
                delay_ms: status.delay,
                health_ping: None,
            })
            .collect())
    }
}

fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl RuntimeObservatory {
    #[doc(hidden)]
    pub async fn set_test_hooks(&self, hooks: TestHooks) {
        *self.test_hooks.lock().await = hooks;
    }
}
