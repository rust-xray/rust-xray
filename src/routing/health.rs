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
/// Observatory runtime supplies the production implementation; selection semantics owns selection semantics.
pub trait OutboundHealthProvider: Send + Sync {
    fn observations(&self) -> Result<Vec<OutboundHealthObservation>, String>;
}

#[derive(Default)]
pub struct NoOutboundHealthProvider;

impl OutboundHealthProvider for NoOutboundHealthProvider {
    fn observations(&self) -> Result<Vec<OutboundHealthObservation>, String> {
        Err(
            "outbound health observations are unavailable until ObservatoryService (Observatory runtime)"
                .to_string(),
        )
    }
}

pub type SharedHealthProvider = Arc<dyn OutboundHealthProvider>;
