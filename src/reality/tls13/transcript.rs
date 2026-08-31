use sha2::{Digest, Sha256, Sha384};

/// Hash algorithm used by the TLS 1.3 transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13HashAlgorithm {
    Sha256,
    Sha384,
}

#[derive(Clone)]
enum TranscriptHasher {
    Sha256(Sha256),
    Sha384(Sha384),
}

/// Incremental TLS 1.3 handshake transcript hasher.
///
/// Handshake messages are fed to an internal SHA-256/SHA-384 state. `digest()`
/// clones that state and finalizes the clone so repeated digests stay stable while
/// appends continue to update the live transcript.
#[derive(Clone)]
pub struct TranscriptHash {
    hasher: TranscriptHasher,
    len: usize,
}

impl std::fmt::Debug for TranscriptHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranscriptHash")
            .field("algorithm", &self.algorithm())
            .field("len", &self.len())
            .finish()
    }
}

impl TranscriptHash {
    pub fn new(algorithm: Tls13HashAlgorithm) -> Self {
        let hasher = match algorithm {
            Tls13HashAlgorithm::Sha256 => TranscriptHasher::Sha256(Sha256::new()),
            Tls13HashAlgorithm::Sha384 => TranscriptHasher::Sha384(Sha384::new()),
        };
        Self { hasher, len: 0 }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.len += message.len();
        match &mut self.hasher {
            TranscriptHasher::Sha256(hasher) => hasher.update(message),
            TranscriptHasher::Sha384(hasher) => hasher.update(message),
        }
    }

    pub fn digest(&self) -> Vec<u8> {
        match &self.hasher {
            TranscriptHasher::Sha256(hasher) => hasher.clone().finalize().to_vec(),
            TranscriptHasher::Sha384(hasher) => hasher.clone().finalize().to_vec(),
        }
    }

    pub fn algorithm(&self) -> Tls13HashAlgorithm {
        match self.hasher {
            TranscriptHasher::Sha256(_) => Tls13HashAlgorithm::Sha256,
            TranscriptHasher::Sha384(_) => Tls13HashAlgorithm::Sha384,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/transcript.rs"]
mod tests;
