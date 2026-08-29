//! Standard and Burst Xray Observatory runtimes (Stage 8E4).

mod active;
mod burst;
mod config;
mod probe;
mod runtime;

pub use active::ActiveObservatory;
pub use burst::{
    BurstObservatoryRuntimeConfig, BurstTestHooks, HealthPingRuntimeConfig, ProbeDelaySource,
    RuntimeBurstObservatory,
};
pub use config::{
    parse_probe_interval, parse_xray_duration, ObservatoryRuntimeConfig, DEFAULT_PROBE_INTERVAL,
};
pub use probe::DEAD_PROBE_DELAY_MS;
pub use runtime::{RuntimeObservatory, TestHooks};
