use sha2::{Digest, Sha256, Sha384};

/// Hash algorithm used by the TLS 1.3 transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13HashAlgorithm {
    Sha256,
    Sha384,
}

/// Running transcript buffer for TLS 1.3 handshake hash input.
///
/// Handshake messages are accumulated in `buffer`; `digest()` computes the hash
/// on demand. This can be replaced with a streaming hasher later.
#[derive(Clone)]
pub struct TranscriptHash {
    algorithm: Tls13HashAlgorithm,
    buffer: Vec<u8>,
}

impl std::fmt::Debug for TranscriptHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranscriptHash")
            .field("algorithm", &self.algorithm)
            .field("len", &self.len())
            .finish()
    }
}

impl TranscriptHash {
    pub fn new(algorithm: Tls13HashAlgorithm) -> Self {
        Self {
            algorithm,
            buffer: Vec::new(),
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.buffer.extend_from_slice(message);
    }

    pub fn digest(&self) -> Vec<u8> {
        match self.algorithm {
            Tls13HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&self.buffer);
                hasher.finalize().to_vec()
            }
            Tls13HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&self.buffer);
                hasher.finalize().to_vec()
            }
        }
    }

    pub fn algorithm(&self) -> Tls13HashAlgorithm {
        self.algorithm
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/transcript.rs"]
mod tests;
