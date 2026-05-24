use std::io::{Error, ErrorKind};

/// Placeholder for TLS 1.3 transcript hash maintenance.
///
/// Upstream equivalent: transcript updates inside Go `serverHandshakeStateTLS13`.
pub struct TranscriptHash {
    // TODO: hash state (e.g. SHA-256 context)
}

impl TranscriptHash {
    pub fn new() -> Self {
        Self {}
    }

    /// TODO: append a handshake message to the running transcript hash.
    pub fn add_message(&mut self, _message: &[u8]) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "REALITY TLS 1.3 transcript hash is not implemented yet",
        ))
    }

    /// TODO: return the current transcript hash for Finished / CertificateVerify.
    pub fn current_hash(&self) -> Result<Vec<u8>, Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "REALITY TLS 1.3 transcript hash is not implemented yet",
        ))
    }
}

impl Default for TranscriptHash {
    fn default() -> Self {
        Self::new()
    }
}
