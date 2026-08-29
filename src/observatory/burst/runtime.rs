use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{self, sleep, MissedTickBehavior};

use super::config::{BurstObservatoryRuntimeConfig, HealthPingRuntimeConfig};
use super::health_ping::{HealthPingRing, HealthPingStats};
use crate::api::proto::app::observatory::{
    HealthPingMeasurementResult, ObservationResult, OutboundStatus,
};
use crate::observatory::probe::{measure_delay_direct, measure_delay_tagged, HttpProbeOptions};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::{HealthPingObservation, OutboundHealthObservation, OutboundHealthProvider};
use crate::runtime::RuntimeOutboundManager;

pub trait ProbeDelaySource: Send + Sync {
    fn delay(&self, max: Duration, seed: u64) -> Duration;
}

pub type BurstProbeHook = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Default)]
pub struct RandomProbeDelaySource;

impl ProbeDelaySource for RandomProbeDelaySource {
    fn delay(&self, max: Duration, _seed: u64) -> Duration {
        if max.is_zero() {
            return Duration::ZERO;
        }
        let mut rng = rand::thread_rng();
        Duration::from_nanos(rng.gen_range(0..=max.as_nanos()) as u64)
    }
}

#[derive(Default)]
#[doc(hidden)]
pub struct BurstTestHooks {
    pub before_probe: Option<BurstProbeHook>,
    pub after_probe: Option<BurstProbeHook>,
    pub delay_source: Option<Arc<dyn ProbeDelaySource>>,
    pub clock: Option<Arc<dyn Fn() -> Instant + Send + Sync>>,
}

pub struct RuntimeBurstObservatory {
    config: BurstObservatoryRuntimeConfig,
    outbound: Arc<RuntimeOutboundManager>,
    connect_runtime: Arc<OutboundConnectRuntime>,
    results: RwLock<HashMap<String, HealthPingRing>>,
    shutdown: AtomicBool,
    worker_started: AtomicBool,
    oneshot_generation: AtomicU64,
    scheduled_generation: AtomicU64,
    scheduler_handle: Mutex<Option<JoinHandle<()>>>,
    scheduled_round_handle: Mutex<Option<JoinHandle<()>>>,
    delay_source: Arc<dyn ProbeDelaySource>,
    #[doc(hidden)]
    pub test_hooks: Mutex<BurstTestHooks>,
    #[doc(hidden)]
    pub scheduled_round_starts: AtomicUsize,
}

#[derive(Clone, Copy)]
enum RoundKind {
    Oneshot,
    Scheduled,
}

impl RuntimeBurstObservatory {
    pub fn new(
        config: BurstObservatoryRuntimeConfig,
        outbound: Arc<RuntimeOutboundManager>,
        connect_runtime: Arc<OutboundConnectRuntime>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            outbound,
            connect_runtime,
            results: RwLock::new(HashMap::new()),
            shutdown: AtomicBool::new(false),
            worker_started: AtomicBool::new(false),
            oneshot_generation: AtomicU64::new(0),
            scheduled_generation: AtomicU64::new(0),
            scheduler_handle: Mutex::new(None),
            scheduled_round_handle: Mutex::new(None),
            delay_source: Arc::new(RandomProbeDelaySource),
            test_hooks: Mutex::new(BurstTestHooks::default()),
            scheduled_round_starts: AtomicUsize::new(0),
        })
    }

    pub fn config(&self) -> &BurstObservatoryRuntimeConfig {
        &self.config
    }

    pub fn observation_result(&self) -> ObservationResult {
        let now = self.now();
        let results = match self.results.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut status = results
            .iter()
            .map(|(tag, ring)| outbound_status_from_stats(tag, &ring.statistics(now)))
            .collect::<Vec<_>>();
        status.sort_by(|left, right| left.outbound_tag.cmp(&right.outbound_tag));
        ObservationResult { status }
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
            let selected = this.select_tags();
            if !selected.is_empty() {
                let tags = selected.clone();
                let oneshot = Arc::clone(&this);
                tokio::spawn(async move {
                    oneshot.check(&tags).await;
                });
            }
            this.launch_scheduled_round().await;

            let period = this.config.ping.scheduler_period;
            let mut ticker = time::interval(period);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if this.shutdown.load(Ordering::Acquire) {
                    break;
                }
                this.launch_scheduled_round().await;
            }
        });
        if let Ok(mut guard) = self.scheduler_handle.try_lock() {
            *guard = Some(handle);
        }
    }

    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.scheduled_generation.fetch_add(1, Ordering::AcqRel);
        self.oneshot_generation.fetch_add(1, Ordering::AcqRel);

        if let Some(handle) = self.scheduled_round_handle.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.scheduler_handle.lock().await.take() {
            handle.abort();
            let _ = time::timeout(Duration::from_secs(2), handle).await;
        }
    }

    pub async fn check(self: &Arc<Self>, tags: &[String]) {
        let generation = self.oneshot_generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.do_check(tags, Duration::ZERO, 1, RoundKind::Oneshot, generation)
            .await;
    }

    #[doc(hidden)]
    pub async fn do_scheduled_check_for_test(
        self: &Arc<Self>,
        tags: &[String],
        duration: Duration,
        rounds: u32,
    ) {
        let generation = self.scheduled_generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.do_check(tags, duration, rounds, RoundKind::Scheduled, generation)
            .await;
    }

    async fn launch_scheduled_round(self: &Arc<Self>) {
        if self.shutdown.load(Ordering::Acquire) {
            return;
        }
        let selected = self.select_tags();
        if selected.is_empty() {
            return;
        }
        self.scheduled_round_starts.fetch_add(1, Ordering::AcqRel);

        self.scheduled_generation.fetch_add(1, Ordering::AcqRel);
        if let Some(handle) = self.scheduled_round_handle.lock().await.take() {
            handle.abort();
        }
        let generation = self.scheduled_generation.load(Ordering::Acquire);
        let this = Arc::clone(self);
        let tags = selected.clone();
        let handle = tokio::spawn(async move {
            this.do_check(
                &tags,
                this.config.ping.scheduler_period,
                this.config.ping.sampling_count,
                RoundKind::Scheduled,
                generation,
            )
            .await;
            this.cleanup(&tags);
        });
        *self.scheduled_round_handle.lock().await = Some(handle);
    }

    async fn do_check(
        self: &Arc<Self>,
        tags: &[String],
        duration: Duration,
        rounds: u32,
        kind: RoundKind,
        generation: u64,
    ) {
        let count = tags.len().saturating_mul(rounds as usize);
        if count == 0 {
            return;
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel(count);
        let mut handles = Vec::with_capacity(count);
        let ping = self.config.ping.clone();
        let mut seed = 0_u64;

        for tag in tags {
            for _ in 0..rounds {
                let this = Arc::clone(self);
                let tag = tag.clone();
                let tx = tx.clone();
                let ping = ping.clone();
                let delay = self.delay_for(duration, seed);
                seed = seed.wrapping_add(1);
                handles.push(tokio::spawn(async move {
                    if !delay.is_zero() {
                        sleep(delay).await;
                    }
                    if this.shutdown.load(Ordering::Acquire)
                        || !this.is_generation_active(kind, generation)
                    {
                        return;
                    }
                    if let Some(hook) = this.test_hooks.lock().await.before_probe.as_ref() {
                        hook(&tag);
                    }
                    let options = match HttpProbeOptions::parse_method(
                        &ping.http_method,
                        super::health_ping::DEFAULT_BURST_HTTP_METHOD,
                    ) {
                        Ok(options) => options.with_timeout(ping.timeout),
                        Err(_) => {
                            let _ = tx.send((tag.clone(), ProbeOutcome::Skip)).await;
                            return;
                        }
                    };
                    let outcome = match measure_delay_tagged(
                        &tag,
                        &ping.destination,
                        &options,
                        Arc::clone(&this.outbound),
                        Arc::clone(&this.connect_runtime),
                    )
                    .await
                    {
                        Ok(delay) => ProbeOutcome::Success(delay),
                        Err(_) if !this.check_connectivity(&ping, &options).await => {
                            ProbeOutcome::Skip
                        }
                        Err(_) => ProbeOutcome::Failed,
                    };
                    if this.shutdown.load(Ordering::Acquire)
                        || !this.is_generation_active(kind, generation)
                    {
                        return;
                    }
                    let _ = tx.send((tag.clone(), outcome)).await;
                    if let Some(hook) = this.test_hooks.lock().await.after_probe.as_ref() {
                        hook(&tag);
                    }
                }));
            }
        }
        drop(tx);

        for _ in 0..count {
            if self.shutdown.load(Ordering::Acquire) || !self.is_generation_active(kind, generation)
            {
                break;
            }
            let Some((tag, outcome)) = rx.recv().await else {
                break;
            };
            if !self.is_generation_active(kind, generation) {
                break;
            }
            self.apply_outcome(&tag, outcome);
        }

        for handle in handles {
            handle.abort();
        }
    }

    fn is_generation_active(&self, kind: RoundKind, generation: u64) -> bool {
        match kind {
            RoundKind::Oneshot => self.oneshot_generation.load(Ordering::Acquire) == generation,
            RoundKind::Scheduled => self.scheduled_generation.load(Ordering::Acquire) == generation,
        }
    }

    fn apply_outcome(self: &Arc<Self>, tag: &str, outcome: ProbeOutcome) {
        let now = self.now();
        let mut results = match self.results.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match outcome {
            ProbeOutcome::Skip => {}
            ProbeOutcome::Success(delay) => {
                let ring = results.entry(tag.to_string()).or_insert_with(|| {
                    HealthPingRing::new(self.config.ping.sampling_count, self.config.ping.validity)
                });
                ring.put_success(now, delay);
            }
            ProbeOutcome::Failed => {
                let ring = results.entry(tag.to_string()).or_insert_with(|| {
                    HealthPingRing::new(self.config.ping.sampling_count, self.config.ping.validity)
                });
                ring.put_failed(now);
            }
        }
    }

    #[doc(hidden)]
    pub fn cleanup(self: &Arc<Self>, tags: &[String]) {
        let mut results = match self.results.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        results.retain(|tag, _| tags.iter().any(|selected| selected == tag));
    }

    async fn check_connectivity(
        self: &Arc<Self>,
        ping: &HealthPingRuntimeConfig,
        options: &HttpProbeOptions,
    ) -> bool {
        if ping.connectivity.is_empty() {
            return true;
        }
        measure_delay_direct(&ping.connectivity, options)
            .await
            .is_ok()
    }

    fn select_tags(&self) -> Vec<String> {
        self.outbound
            .select_outbounds(&self.config.subject_selector)
    }

    fn delay_for(&self, duration: Duration, seed: u64) -> Duration {
        if duration.is_zero() {
            return Duration::ZERO;
        }
        if let Ok(hooks) = self.test_hooks.try_lock() {
            if let Some(source) = hooks.delay_source.as_ref() {
                return source.delay(duration, seed);
            }
        }
        self.delay_source.delay(duration, seed)
    }

    fn now(&self) -> Instant {
        if let Ok(hooks) = self.test_hooks.try_lock() {
            if let Some(clock) = hooks.clock.as_ref() {
                return clock();
            }
        }
        Instant::now()
    }
}

enum ProbeOutcome {
    Success(Duration),
    Failed,
    Skip,
}

impl OutboundHealthProvider for RuntimeBurstObservatory {
    fn observations(&self) -> Result<Vec<OutboundHealthObservation>, String> {
        let snapshot = self.observation_result();
        Ok(snapshot
            .status
            .into_iter()
            .map(|status| {
                let health_ping = status
                    .health_ping
                    .as_ref()
                    .map(|ping| HealthPingObservation {
                        all: ping.all as u32,
                        fail: ping.fail as u32,
                        average: ping.average,
                        deviation: ping.deviation,
                        max: ping.max,
                        min: ping.min,
                    });
                OutboundHealthObservation {
                    outbound_tag: status.outbound_tag,
                    alive: status.alive,
                    delay_ms: status.delay,
                    health_ping,
                }
            })
            .collect())
    }
}

fn outbound_status_from_stats(tag: &str, stats: &HealthPingStats) -> OutboundStatus {
    OutboundStatus {
        alive: stats.alive,
        delay: stats.average.as_millis() as i64,
        last_error_reason: String::new(),
        outbound_tag: tag.to_string(),
        last_seen_time: 0,
        last_try_time: 0,
        health_ping: Some(HealthPingMeasurementResult {
            all: stats.all,
            fail: stats.fail,
            deviation: stats.deviation.as_nanos() as i64,
            average: stats.average.as_nanos() as i64,
            max: stats.max.as_nanos() as i64,
            min: stats.min.as_nanos() as i64,
        }),
    }
}

impl RuntimeBurstObservatory {
    #[doc(hidden)]
    pub async fn set_test_hooks(&self, hooks: BurstTestHooks) {
        *self.test_hooks.lock().await = hooks;
    }
}
