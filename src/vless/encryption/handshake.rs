use std::fmt;
use std::io::{Error, ErrorKind};
use std::time::Duration;

use super::aead::TrafficAead;
use super::config::XorMode;
use super::hybrid::{PfsKey, UnitedKey};
use super::keys::SecretBytes;
use super::xor::CtrStream;

/// Default inbound encrypted handshake timeout (upstream policy-compatible baseline).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

pub const IV_LEN: usize = 16;
pub const NFS_ENCRYPTED_RECORD_OVERHEAD: usize = 16;
pub const NFS_PLAINTEXT_LENGTH_LEN: usize = 2;
pub const NFS_ENCRYPTED_LENGTH_LEN: usize =
    NFS_PLAINTEXT_LENGTH_LEN + NFS_ENCRYPTED_RECORD_OVERHEAD;
pub const PFS_CLIENT_PUBLIC_KEY_LEN: usize = 1184 + 32;
pub const PFS_CLIENT_BUNDLE_MIN: usize = PFS_CLIENT_PUBLIC_KEY_LEN + NFS_ENCRYPTED_RECORD_OVERHEAD;
pub const PFS_SERVER_EXCHANGE_LEN: usize = 1088 + 32 + NFS_ENCRYPTED_RECORD_OVERHEAD;
pub const ENCRYPTED_TICKET_LEN: usize = 16 + NFS_ENCRYPTED_RECORD_OVERHEAD;
pub const ZERO_RTT_LENGTH: u16 = 32;

/// Directional traffic AEAD material for Stage VLESS-4D `CommonConn` construction.
pub struct TrafficDirectionKeys {
    pub aead: TrafficAead,
    pub context_label: Vec<u8>,
}

impl fmt::Debug for TrafficDirectionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrafficDirectionKeys")
            .field("kind", &self.aead.kind())
            .field("context_len", &self.context_label.len())
            .finish()
    }
}

/// Optional XOR wrapping state for `random` mode (Stage VLESS-4D).
pub struct XorConnState {
    pub outbound_ctr: CtrStream,
    pub inbound_ctr: CtrStream,
    pub outbound_skip: usize,
    pub inbound_skip: usize,
}

impl fmt::Debug for XorConnState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XorConnState")
            .field("outbound_skip", &self.outbound_skip)
            .field("inbound_skip", &self.inbound_skip)
            .finish()
    }
}

/// Typed result of a successful inbound encrypted handshake (1-RTT or 0-RTT).
#[derive(Debug)]
pub struct ServerHandshakeResult {
    pub united_key: UnitedKey,
    pub pfs_key: PfsKey,
    pub nfs_key: SecretBytes<32>,
    pub xor_mode: XorMode,
    pub use_aes: bool,
    pub client_iv: [u8; IV_LEN],
    pub upload_keys: TrafficDirectionKeys,
    pub download_keys: TrafficDirectionKeys,
    pub xor_conn: Option<XorConnState>,
    /// Ticket issued to client (16 bytes; first two encode lifetime when configured).
    pub issued_ticket: [u8; 16],
    pub ticket_lifetime_secs: u64,
    /// Whether the connection resumed via 0-RTT ticket presentation.
    pub is_zero_rtt: bool,
    /// Server random prefix written before the first upload record (0-RTT only).
    pub server_prewrite: Option<[u8; 16]>,
}

/// Handshake failure taxonomy.
#[derive(Debug)]
pub enum HandshakeError {
    Malformed(&'static str),
    UnsupportedMode(&'static str),
    AuthenticationFailed,
    CryptoFailure(&'static str),
    Truncated,
    LengthExceeded,
    Timeout,
    UnknownSession,
    ExpiredSession,
    ReplayRejected,
    ResumeNotAllowed,
    Io(Error),
}

impl HandshakeError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Io(err) => err.kind(),
            Self::Timeout => ErrorKind::TimedOut,
            Self::Truncated => ErrorKind::UnexpectedEof,
            Self::LengthExceeded | Self::Malformed(_) | Self::UnsupportedMode(_) => {
                ErrorKind::InvalidData
            }
            Self::AuthenticationFailed
            | Self::CryptoFailure(_)
            | Self::ReplayRejected
            | Self::UnknownSession
            | Self::ExpiredSession
            | Self::ResumeNotAllowed => ErrorKind::PermissionDenied,
        }
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "malformed VLESS encryption handshake: {msg}"),
            Self::UnsupportedMode(msg) => write!(f, "unsupported VLESS encryption mode: {msg}"),
            Self::AuthenticationFailed => f.write_str("VLESS encryption authentication failed"),
            Self::CryptoFailure(msg) => write!(f, "VLESS encryption crypto failure: {msg}"),
            Self::Truncated => f.write_str("truncated VLESS encryption handshake"),
            Self::LengthExceeded => f.write_str("VLESS encryption handshake length exceeded"),
            Self::Timeout => f.write_str("VLESS encryption handshake timed out"),
            Self::UnknownSession => f.write_str("VLESS encryption unknown session ticket"),
            Self::ExpiredSession => f.write_str("VLESS encryption session ticket expired"),
            Self::ReplayRejected => f.write_str("VLESS encryption replay rejected"),
            Self::ResumeNotAllowed => f.write_str("VLESS encryption 0-RTT resume not allowed"),
            Self::Io(err) => write!(f, "VLESS encryption handshake I/O error: {err}"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<Error> for HandshakeError {
    fn from(err: Error) -> Self {
        if err.kind() == ErrorKind::UnexpectedEof {
            Self::Truncated
        } else if err.kind() == ErrorKind::TimedOut {
            Self::Timeout
        } else {
            Self::Io(err)
        }
    }
}

impl From<HandshakeError> for Error {
    fn from(err: HandshakeError) -> Self {
        Error::new(err.kind(), err.to_string())
    }
}

pub(crate) fn handshake_invalid_data(message: &'static str) -> HandshakeError {
    HandshakeError::CryptoFailure(message)
}

pub(crate) fn map_crypto_err(err: Error) -> HandshakeError {
    match err.kind() {
        ErrorKind::UnexpectedEof => HandshakeError::Truncated,
        ErrorKind::InvalidData | ErrorKind::PermissionDenied => {
            HandshakeError::CryptoFailure("AEAD operation failed")
        }
        _ => HandshakeError::Io(err),
    }
}

pub fn prefer_aes_hardware() -> bool {
    // Upstream server CommonConn defaults to AES; clients probe hardware support.
    true
}

#[cfg(test)]
impl TrafficDirectionKeys {
    pub fn kind(&self) -> super::aead::TrafficAeadKind {
        self.aead.kind()
    }
}
