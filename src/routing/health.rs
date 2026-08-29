use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPingObservation {
    pub all: u32,
    pub fail: u32,
    /// Nanoseconds, matching Xray observatory HealthPingMeasurement fields.
    pub average: i64,
    /// Nanoseconds, matching Xray observatory HealthPingMeasurement fields.
    pub deviation: i64,
    /// Nanoseconds, matching Xray observatory HealthPingMeasurement fields.
    pub max: i64,
    /// Nanoseconds, matching Xray observatory HealthPingMeasurement fields.
    pub min: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHealthObservation {
    pub outbound_tag: String,
    pub alive: bool,
    /// Milliseconds, matching Observatory OutboundStatus.delay.
    pub delay_ms: i64,
    pub health_ping: Option<HealthPingObservation>,
}

/// Snapshot source consumed by Observatory-aware balancer algorithms.
/// Stage 8E4 supplies the production implementation; Stage 8E2 owns selection semantics.
pub trait OutboundHealthProvider: Send + Sync {
    fn observations(&self) -> Result<Vec<OutboundHealthObservation>, String>;
}

#[derive(Default)]
pub struct NoOutboundHealthProvider;

impl OutboundHealthProvider for NoOutboundHealthProvider {
    fn observations(&self) -> Result<Vec<OutboundHealthObservation>, String> {
        Err(
            "outbound health observations are unavailable until ObservatoryService (Stage 8E4)"
                .to_string(),
        )
    }
}

pub type SharedHealthProvider = Arc<dyn OutboundHealthProvider>;
