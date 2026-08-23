//! Target useless-record tolerance model (Stage 5C).

/// How many consecutive non-advancing TLS records a REALITY dest tolerates.
///
/// Probe results are always one of `Finite(1)`, `Finite(16)`, `Finite(32)`, or `Unlimited`.
/// Runtime fallback before/for failed detection is [`Self::DEFAULT`] (`Finite(32)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UselessRecordTolerance {
    Finite(usize),
    Unlimited,
}

impl UselessRecordTolerance {
    /// Upstream baseline when probe is not ready, failed, or cache has no entry.
    pub const DEFAULT: Self = Self::Finite(32);

    pub const PROBE_FINITE_ONE: Self = Self::Finite(1);
    pub const PROBE_FINITE_SIXTEEN: Self = Self::Finite(16);
    pub const PROBE_FINITE_THIRTY_TWO: Self = Self::Finite(32);

    /// Returns the numeric cap when finite, or `None` when unlimited.
    pub fn effective_limit(self) -> Option<usize> {
        match self {
            Self::Finite(limit) => Some(limit),
            Self::Unlimited => None,
        }
    }

    /// Whether `self` is one of the four upstream probe tier results.
    pub fn is_probe_tier_result(self) -> bool {
        matches!(
            self,
            Self::PROBE_FINITE_ONE
                | Self::PROBE_FINITE_SIXTEEN
                | Self::PROBE_FINITE_THIRTY_TWO
                | Self::Unlimited
        )
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/tolerance.rs"]
mod tests;
