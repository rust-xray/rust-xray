use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    MalformedQuery,
    Timeout,
    /// Upstream resolver returned an error or failed I/O.
    Upstream,
    ServerFailed,
    UnsupportedTransport(String),
    Io(std::io::ErrorKind, String),
}

impl DnsError {
    pub fn kind(&self) -> std::io::ErrorKind {
        match self {
            Self::MalformedQuery => std::io::ErrorKind::InvalidData,
            Self::Timeout => std::io::ErrorKind::TimedOut,
            Self::Upstream | Self::ServerFailed => std::io::ErrorKind::Other,
            Self::UnsupportedTransport(_) => std::io::ErrorKind::Unsupported,
            Self::Io(kind, _) => *kind,
        }
    }
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedQuery => write!(f, "malformed DNS query"),
            Self::Timeout => write!(f, "DNS query timed out"),
            Self::Upstream => write!(f, "DNS upstream failure"),
            Self::ServerFailed => write!(f, "DNS server failure"),
            Self::UnsupportedTransport(transport) => {
                write!(f, "unsupported DNS transport: {transport}")
            }
            Self::Io(_, message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.kind(), err.to_string())
    }
}

impl From<DnsError> for std::io::Error {
    fn from(err: DnsError) -> Self {
        std::io::Error::new(err.kind(), err.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct DnsQueryResponse {
    pub raw_response: Vec<u8>,
    pub server: std::net::SocketAddr,
    pub cached: bool,
    pub latency: Duration,
}
