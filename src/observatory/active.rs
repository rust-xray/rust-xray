use std::sync::Arc;

use crate::api::proto::app::observatory::ObservationResult;
use crate::observatory::burst::RuntimeBurstObservatory;
use crate::observatory::RuntimeObservatory;
use crate::routing::OutboundHealthProvider;

/// Active observatory feature selected at runtime.
pub enum ActiveObservatory {
    Standard(Arc<RuntimeObservatory>),
    Burst(Arc<RuntimeBurstObservatory>),
}

impl Clone for ActiveObservatory {
    fn clone(&self) -> Self {
        match self {
            Self::Standard(observatory) => Self::Standard(Arc::clone(observatory)),
            Self::Burst(observatory) => Self::Burst(Arc::clone(observatory)),
        }
    }
}

impl ActiveObservatory {
    pub fn standard(&self) -> Option<&Arc<RuntimeObservatory>> {
        match self {
            Self::Standard(observatory) => Some(observatory),
            Self::Burst(_) => None,
        }
    }

    pub fn burst(&self) -> Option<&Arc<RuntimeBurstObservatory>> {
        match self {
            Self::Burst(observatory) => Some(observatory),
            Self::Standard(_) => None,
        }
    }

    pub fn observation_result(&self) -> ObservationResult {
        match self {
            Self::Standard(observatory) => observatory.observation_result(),
            Self::Burst(observatory) => observatory.observation_result(),
        }
    }

    pub fn start(&self) {
        match self {
            Self::Standard(observatory) => observatory.start(),
            Self::Burst(observatory) => observatory.start(),
        }
    }

    pub async fn shutdown(&self) {
        match self {
            Self::Standard(observatory) => observatory.shutdown().await,
            Self::Burst(observatory) => observatory.shutdown().await,
        }
    }
}

impl OutboundHealthProvider for ActiveObservatory {
    fn observations(&self) -> Result<Vec<crate::routing::OutboundHealthObservation>, String> {
        match self {
            Self::Standard(observatory) => observatory.observations(),
            Self::Burst(observatory) => observatory.observations(),
        }
    }
}
