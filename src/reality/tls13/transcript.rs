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
mod tests {
    use super::*;

    const SHA256_EMPTY_DIGEST: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    const SHA384_EMPTY_DIGEST: [u8; 48] = [
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3,
        0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6,
        0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48,
        0x98, 0xb9, 0x5b,
    ];

    #[test]
    fn empty_sha256_digest_matches_known_value() {
        let transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
        assert_eq!(transcript.digest(), SHA256_EMPTY_DIGEST);
    }

    #[test]
    fn empty_sha384_digest_matches_known_value() {
        let transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha384);
        assert_eq!(transcript.digest(), SHA384_EMPTY_DIGEST);
    }

    #[test]
    fn update_order_matters_for_concatenation() {
        let mut split = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
        split.update(b"a");
        split.update(b"b");

        let mut combined = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
        combined.update(b"ab");

        assert_eq!(split.digest(), combined.digest());
    }

    #[test]
    fn debug_does_not_include_raw_buffer_content() {
        let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
        transcript.update(&[0xde, 0xad, 0xbe, 0xef]);

        let debug = format!("{transcript:?}");

        assert!(debug.contains("Sha256"));
        assert!(debug.contains("len: 4"));
        assert!(!debug.contains("deadbeef"));
        assert!(!debug.contains("buffer"));
        assert!(!debug.contains("de"));
    }

    #[test]
    fn len_tracks_total_transcript_bytes() {
        let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha384);

        assert_eq!(transcript.len(), 0);
        transcript.update(b"hello");
        assert_eq!(transcript.len(), 5);
        transcript.update(b" world");
        assert_eq!(transcript.len(), 11);
    }
}
