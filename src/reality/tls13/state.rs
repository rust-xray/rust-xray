use std::io::{Error, ErrorKind};

const HANDSHAKE_NOT_IMPLEMENTED_MSG: &str =
    "REALITY TLS 1.3 server state machine is not implemented yet";

/// Placeholder for the REALITY accepted-path TLS 1.3 server handshake state.
///
/// Upstream equivalent: Go `serverHandshakeStateTLS13` in XTLS/REALITY.
pub struct RealityTls13ServerState {
    // TODO: client hello metadata
    // TODO: accepted REALITY auth
    // TODO: observed dest ServerHello shape
}

impl RealityTls13ServerState {
    pub fn new() -> Self {
        Self {}
    }

    pub fn handshake_not_implemented(&self) -> Error {
        Error::new(ErrorKind::Unsupported, HANDSHAKE_NOT_IMPLEMENTED_MSG)
    }
}

impl Default for RealityTls13ServerState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_tls13_server_state_new_compiles() {
        let _state = RealityTls13ServerState::new();
    }

    #[test]
    fn handshake_not_implemented_returns_unsupported() {
        let state = RealityTls13ServerState::new();
        let err = state.handshake_not_implemented();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.to_string(), HANDSHAKE_NOT_IMPLEMENTED_MSG);
    }
}
