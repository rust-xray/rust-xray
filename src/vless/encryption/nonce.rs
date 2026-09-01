/// Upstream `MaxNonce` — triggers AEAD context rotation when reached.
pub const MAX_NONCE: [u8; 12] = [0xff; 12];

/// 12-byte AEAD nonce counter matching upstream `IncreaseNonce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NonceCounter([u8; 12]);

impl NonceCounter {
    pub fn new() -> Self {
        Self([0u8; 12])
    }

    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; 12] {
        &mut self.0
    }
}

/// Increment 96-bit little-endian style counter (upstream increments from index 11 down).
pub fn increase_nonce(nonce: &mut [u8; 12]) {
    for i in 0..12 {
        let idx = 11 - i;
        nonce[idx] = nonce[idx].wrapping_add(1);
        if nonce[idx] != 0 {
            break;
        }
    }
}

pub fn is_max_nonce(nonce: &[u8; 12]) -> bool {
    nonce == &MAX_NONCE
}
