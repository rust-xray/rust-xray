use std::io::{Error, ErrorKind};

use super::transcript::Tls13HashAlgorithm;

pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
pub const TLS_AES_128_CCM_SHA256: u16 = 0x1304;
pub const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// REALITY accepted path — TLS 1.3 cipher suite compatibility matrix.
///
/// | IANA ID | Name | Record crypto | Key schedule |
/// |---------|------|---------------|--------------|
/// | 0x1301 | TLS_AES_128_GCM_SHA256 | Supported | SHA-256 |
/// | 0x1302 | TLS_AES_256_GCM_SHA384 | Supported | SHA-384 |
/// | 0x1303 | TLS_CHACHA20_POLY1305_SHA256 | Supported | SHA-256 |
/// | 0x1304 | TLS_AES_128_CCM_SHA256 | Rejected | — |
/// | 0x1305 | TLS_AES_128_CCM_8_SHA256 | Rejected | — |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tls13CipherSuite {
    pub id: u16,
    pub name: &'static str,
    pub hash: Tls13HashAlgorithm,
    pub aead: Tls13AeadAlgorithm,
    pub key_len: usize,
    pub iv_len: usize,
}

const AES_128_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    id: TLS_AES_128_GCM_SHA256,
    name: "TLS_AES_128_GCM_SHA256",
    hash: Tls13HashAlgorithm::Sha256,
    aead: Tls13AeadAlgorithm::Aes128Gcm,
    key_len: 16,
    iv_len: 12,
};

const AES_256_GCM_SHA384: Tls13CipherSuite = Tls13CipherSuite {
    id: TLS_AES_256_GCM_SHA384,
    name: "TLS_AES_256_GCM_SHA384",
    hash: Tls13HashAlgorithm::Sha384,
    aead: Tls13AeadAlgorithm::Aes256Gcm,
    key_len: 32,
    iv_len: 12,
};

const CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    id: TLS_CHACHA20_POLY1305_SHA256,
    name: "TLS_CHACHA20_POLY1305_SHA256",
    hash: Tls13HashAlgorithm::Sha256,
    aead: Tls13AeadAlgorithm::ChaCha20Poly1305,
    key_len: 32,
    iv_len: 12,
};

impl Tls13CipherSuite {
    /// AEAD authentication tag length for TLS 1.3 record protection.
    pub const fn aead_tag_len(self) -> usize {
        match self.aead {
            Tls13AeadAlgorithm::Aes128Gcm | Tls13AeadAlgorithm::Aes256Gcm => 16,
            Tls13AeadAlgorithm::ChaCha20Poly1305 => 16,
        }
    }
}

pub fn is_tls13_ccm_cipher_suite(id: u16) -> bool {
    matches!(id, TLS_AES_128_CCM_SHA256 | TLS_AES_128_CCM_8_SHA256)
}

pub fn tls13_cipher_suite(id: u16) -> Option<Tls13CipherSuite> {
    match id {
        TLS_AES_128_GCM_SHA256 => Some(AES_128_GCM_SHA256),
        TLS_AES_256_GCM_SHA384 => Some(AES_256_GCM_SHA384),
        TLS_CHACHA20_POLY1305_SHA256 => Some(CHACHA20_POLY1305_SHA256),
        _ => None,
    }
}

/// Resolves a destination ServerHello cipher suite for the REALITY accepted path.
pub fn resolve_tls13_cipher_suite(id: u16) -> Result<Tls13CipherSuite, Error> {
    if is_tls13_ccm_cipher_suite(id) {
        let name = match id {
            TLS_AES_128_CCM_SHA256 => "TLS_AES_128_CCM_SHA256",
            TLS_AES_128_CCM_8_SHA256 => "TLS_AES_128_CCM_8_SHA256",
            _ => unreachable!("CCM cipher suite id checked above"),
        };
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "TLS 1.3 CCM cipher suite {name} (0x{id:04x}) is not supported; \
                 supported suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, \
                 TLS_CHACHA20_POLY1305_SHA256"
            ),
        ));
    }

    tls13_cipher_suite(id).ok_or_else(|| {
        Error::new(
            ErrorKind::Unsupported,
            format!("unsupported destination ServerHello cipher suite: 0x{id:04x}"),
        )
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/cipher_suite.rs"]
mod tests;
