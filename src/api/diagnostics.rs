//! Xray API gRPC request and wire-protocol diagnostics (Remna / XTLS-SDK compat).

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tracing::{info, warn};

use crate::api::server::ApiTransportMode;
use tonic::Request;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// First bytes observed on a new API TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiWireHint {
    Http2PriorKnowledge,
    TlsClientHello,
    Other { hex_prefix: String },
    Empty,
}

impl ApiWireHint {
    pub fn as_log_label(&self) -> &'static str {
        match self {
            Self::Http2PriorKnowledge => "http2-prior-knowledge",
            Self::TlsClientHello => "tls-client-hello",
            Self::Other { .. } => "other",
            Self::Empty => "empty",
        }
    }
}

pub fn classify_initial_bytes(bytes: &[u8]) -> ApiWireHint {
    if bytes.is_empty() {
        return ApiWireHint::Empty;
    }
    if bytes.len() >= 3
        && bytes[0] == 0x16
        && bytes[1] == 0x03
        && (bytes[2] == 0x01 || bytes[2] == 0x03)
    {
        return ApiWireHint::TlsClientHello;
    }
    if bytes.starts_with(HTTP2_PREFACE) || bytes.starts_with(b"PRI") {
        return ApiWireHint::Http2PriorKnowledge;
    }
    ApiWireHint::Other {
        hex_prefix: hex_prefix(bytes, 12),
    }
}

fn hex_prefix(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(unix)]
fn peek_initial_bytes(stream: &TcpStream) -> Option<Vec<u8>> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut buf = [0u8; 32];
    let n = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if n <= 0 {
        return None;
    }
    Some(buf[..n as usize].to_vec())
}

#[cfg(not(unix))]
fn peek_initial_bytes(_stream: &TcpStream) -> Option<Vec<u8>> {
    None
}

pub fn log_api_wire_hint(peer: SocketAddr, hint: &ApiWireHint, transport: &ApiTransportMode) {
    match (hint, transport) {
        (ApiWireHint::TlsClientHello, ApiTransportMode::Plaintext) => {
            warn!(
                %peer,
                wire = hint.as_log_label(),
                api_transport = "plaintext",
                "API received TLS ClientHello on plaintext gRPC listener; client is using TLS against plaintext API"
            );
            crate::startup_log::eprintln_bootstrap(format!(
                "API wire hint from {peer}: TLS ClientHello on plaintext listener (Remna/XTLS-SDK TLS/plaintext mismatch)"
            ));
        }
        (ApiWireHint::TlsClientHello, ApiTransportMode::Tls { .. })
        | (ApiWireHint::TlsClientHello, ApiTransportMode::Mtls { .. }) => {
            info!(%peer, wire = hint.as_log_label(), "API TLS handshake starting");
        }
        (ApiWireHint::Http2PriorKnowledge, _) => {
            info!(%peer, wire = hint.as_log_label(), "API connection uses HTTP/2 prior knowledge");
        }
        (ApiWireHint::Other { hex_prefix }, _) => {
            warn!(
                %peer,
                wire = hint.as_log_label(),
                hex_prefix = %hex_prefix,
                "API connection initial bytes are not HTTP/2 prior knowledge or TLS"
            );
        }
        (ApiWireHint::Empty, _) => {}
    }
}

pub fn rpc_remote_addr<T>(request: &Request<T>) -> String {
    request
        .remote_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn log_rpc_call(service: &str, method: &str, remote: &str) {
    info!(service, method, %remote, "Xray API gRPC call");
    crate::startup_log::eprintln_bootstrap(format!("{service}.{method} called from {remote}"));
}

pub fn log_rpc_ok(service: &str, method: &str, remote: &str, detail: &str) {
    info!(service, method, %remote, detail, "Xray API gRPC ok");
}

pub fn log_rpc_err(service: &str, method: &str, remote: &str, detail: &str) {
    warn!(service, method, %remote, detail, "Xray API gRPC failed");
}

/// `TcpIncoming`-compatible stream that logs TLS/plaintext mismatches on accept.
pub struct DiagnosingTcpIncoming {
    inner: TcpListenerStream,
    nodelay: bool,
    keepalive: Option<std::time::Duration>,
    transport: ApiTransportMode,
}

impl DiagnosingTcpIncoming {
    pub fn from_listener(
        listener: TcpListener,
        nodelay: bool,
        keepalive: Option<std::time::Duration>,
        transport: ApiTransportMode,
    ) -> std::io::Result<Self> {
        Ok(Self {
            inner: TcpListenerStream::new(listener),
            nodelay,
            keepalive,
            transport,
        })
    }
}

impl Stream for DiagnosingTcpIncoming {
    type Item = Result<TcpStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                set_tcp_options(&stream, self.nodelay, self.keepalive);
                if let Some(bytes) = peek_initial_bytes(&stream) {
                    let hint = classify_initial_bytes(&bytes);
                    if let Ok(peer) = stream.peer_addr() {
                        log_api_wire_hint(peer, &hint, &self.transport);
                    }
                }
                Poll::Ready(Some(Ok(stream)))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tls_client_hello() {
        let hint = classify_initial_bytes(&[0x16, 0x03, 0x01, 0x00, 0x05]);
        assert_eq!(hint, ApiWireHint::TlsClientHello);
    }

    #[test]
    fn classify_http2_prior_knowledge() {
        let hint = classify_initial_bytes(HTTP2_PREFACE);
        assert_eq!(hint, ApiWireHint::Http2PriorKnowledge);
    }
}

fn set_tcp_options(stream: &TcpStream, nodelay: bool, _keepalive: Option<std::time::Duration>) {
    if nodelay {
        let _ = stream.set_nodelay(true);
    }
}
