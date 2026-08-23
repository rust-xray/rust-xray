//! ALPN profile classification for REALITY post-handshake probe cache keys.

use crate::protocol::structs::ClientHelloPayload;
use crate::vless::extract_client_alpn_offers;

/// ALPN profile bucket used for proactive post-handshake record-length probes.
///
/// Matches upstream REALITY grouping (`record_detect.go` probe loop and runtime lookup in `tls.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RealityAlpnProfile {
    /// ClientHello without ALPN extension / empty offer list.
    None,
    /// ALPN present and first offer is not `h2` (typically `http/1.1`).
    Http11,
    /// First ALPN offer is exactly `h2`.
    H2,
}

impl RealityAlpnProfile {
    /// Profiles used when starting background probes (`serverName × 3`).
    pub const PROBE_PROFILES: [Self; 3] = [Self::None, Self::Http11, Self::H2];

    /// Classifies an accepted REALITY client ClientHello for runtime cache lookup.
    pub fn classify_client_hello(client_hello: &ClientHelloPayload) -> Self {
        Self::classify_alpn_offers(&extract_client_alpn_offers(client_hello))
    }

    /// Classifies ordered ALPN offers from a ClientHello extension.
    pub fn classify_alpn_offers(offers: &[String]) -> Self {
        match offers.first().map(|value| value.as_str()) {
            None => Self::None,
            Some("h2") => Self::H2,
            Some(_) => Self::Http11,
        }
    }

    /// Wire names for probe TLS client configuration (Stage 5B+ probing).
    pub fn probe_next_protocols(self) -> Option<Vec<&'static str>> {
        match self {
            Self::None => None,
            Self::Http11 => Some(vec!["http/1.1"]),
            Self::H2 => Some(vec!["h2", "http/1.1"]),
        }
    }
}
