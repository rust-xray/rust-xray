use std::io::{Error, ErrorKind};

/// Placeholder for TLS 1.3 key schedule derivation.
///
/// Upstream equivalent: early/handshake/application secret derivation in Go
/// `serverHandshakeStateTLS13`.
pub struct Tls13KeySchedule {
    // TODO: early secret
    // TODO: handshake traffic secrets
    // TODO: application traffic secrets
}

impl Tls13KeySchedule {
    pub fn new() -> Self {
        Self {}
    }

    /// TODO: derive handshake traffic secrets from shared secret + transcript.
    pub fn derive_handshake_secrets(&mut self, _shared_secret: &[u8]) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "REALITY TLS 1.3 key schedule is not implemented yet",
        ))
    }

    /// TODO: derive application traffic secrets after server Finished.
    pub fn derive_application_secrets(&mut self) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "REALITY TLS 1.3 key schedule is not implemented yet",
        ))
    }
}

impl Default for Tls13KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}
