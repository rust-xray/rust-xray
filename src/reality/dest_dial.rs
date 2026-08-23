//! Shared REALITY destination dial helpers (TCP / Unix + optional PROXY v1/v2).

use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::vless::{build_proxy_protocol_v1, build_proxy_protocol_v2, validate_fallback_xver};

const REALITY_DEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How the REALITY `dest`/`target` address should be dialed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RealityDestTransport {
    Tcp,
    #[cfg(unix)]
    Unix,
}

impl RealityDestTransport {
    pub fn parse_config_value(raw: Option<&str>) -> Self {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            #[cfg(unix)]
            Some("unix") => Self::Unix,
            Some("tcp") | None => Self::Tcp,
            #[cfg(not(unix))]
            Some("unix") => Self::Tcp,
            Some(other) => {
                debug!(
                    transport_type = other,
                    "unknown REALITY dest transport type; defaulting to TCP"
                );
                Self::Tcp
            }
        }
    }
}

/// Dial parameters shared by accepted-path dest fetch and proactive probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityDestDialConfig {
    pub dest_addr: String,
    pub transport: RealityDestTransport,
    pub xver: u8,
}

impl RealityDestDialConfig {
    pub fn tcp(dest_addr: impl Into<String>) -> Self {
        Self {
            dest_addr: dest_addr.into(),
            transport: RealityDestTransport::Tcp,
            xver: 0,
        }
    }
}

/// Connected REALITY destination stream.
pub enum RealityDestStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl RealityDestStream {
    pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(buf).await,
            #[cfg(unix)]
            Self::Unix(stream) => stream.write_all(buf).await,
        }
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf).await,
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf).await,
        }
    }

    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown().await,
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown().await,
        }
    }
}

impl AsyncRead for RealityDestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            RealityDestStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            RealityDestStream::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RealityDestStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            RealityDestStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            RealityDestStream::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            RealityDestStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            RealityDestStream::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            RealityDestStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            RealityDestStream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// PROXY header endpoints when `xver` is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityDestProxyEndpoints {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl RealityDestProxyEndpoints {
    /// Synthetic endpoints for background probes (no inbound client socket).
    pub fn for_probe(dest_addr: &str) -> std::io::Result<Self> {
        Ok(Self {
            source: "127.0.0.1:65535".parse().expect("valid probe source"),
            destination: parse_dest_socket_addr(dest_addr)?,
        })
    }
}

fn parse_dest_socket_addr(dest_addr: &str) -> std::io::Result<SocketAddr> {
    dest_addr.parse().map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("REALITY dest {dest_addr:?} is not a dialable TCP socket address: {err}"),
        )
    })
}

async fn write_reality_dest_proxy_header(
    stream: &mut RealityDestStream,
    xver: u8,
    endpoints: RealityDestProxyEndpoints,
) -> std::io::Result<()> {
    validate_fallback_xver(xver)?;
    if xver == 0 {
        return Ok(());
    }

    let header = if xver == 1 {
        build_proxy_protocol_v1(endpoints.source, endpoints.destination)?
    } else {
        build_proxy_protocol_v2(endpoints.source, endpoints.destination)?
    };
    stream.write_all(&header).await?;
    debug!(
        xver,
        proxy_header_len = header.len(),
        "REALITY dest PROXY header written"
    );
    Ok(())
}

/// Connects to a REALITY destination using the configured transport and optional PROXY header.
pub async fn dial_reality_dest(
    config: &RealityDestDialConfig,
    proxy_endpoints: Option<RealityDestProxyEndpoints>,
) -> std::io::Result<RealityDestStream> {
    validate_fallback_xver(config.xver)?;

    let mut stream = match config.transport {
        RealityDestTransport::Tcp => {
            let tcp = timeout(
                REALITY_DEST_CONNECT_TIMEOUT,
                TcpStream::connect(&config.dest_addr),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "REALITY dest connect to {} timed out after {:?}",
                        config.dest_addr, REALITY_DEST_CONNECT_TIMEOUT
                    ),
                )
            })??;
            RealityDestStream::Tcp(tcp)
        }
        #[cfg(unix)]
        RealityDestTransport::Unix => {
            use tokio::net::UnixStream;
            let unix = timeout(
                REALITY_DEST_CONNECT_TIMEOUT,
                UnixStream::connect(&config.dest_addr),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "REALITY unix dest connect to {} timed out after {:?}",
                        config.dest_addr, REALITY_DEST_CONNECT_TIMEOUT
                    ),
                )
            })??;
            RealityDestStream::Unix(unix)
        }
    };

    if config.xver == 1 || config.xver == 2 {
        let endpoints = proxy_endpoints.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY dest xver requires PROXY endpoints",
            )
        })?;
        write_reality_dest_proxy_header(&mut stream, config.xver, endpoints).await?;
    }

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_parse_defaults_to_tcp() {
        assert_eq!(
            RealityDestTransport::parse_config_value(None),
            RealityDestTransport::Tcp
        );
        assert_eq!(
            RealityDestTransport::parse_config_value(Some("tcp")),
            RealityDestTransport::Tcp
        );
    }

    #[cfg(unix)]
    #[test]
    fn transport_parse_recognizes_unix() {
        assert_eq!(
            RealityDestTransport::parse_config_value(Some("unix")),
            RealityDestTransport::Unix
        );
    }
}
