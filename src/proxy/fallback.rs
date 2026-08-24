use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::config::LimitFallback;
use crate::proxy::rate_limit::DirectionalLimiter;
use crate::stats::StatsSession;
use crate::vless::{build_proxy_protocol_v1, build_proxy_protocol_v2, validate_fallback_xver};

const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const FALLBACK_COPY_BUFFER_SIZE: usize = 8192;

#[derive(Debug, Clone, Copy)]
pub(crate) struct FallbackRelayOptions {
    xver: u8,
    upload_limit: LimitFallback,
    download_limit: LimitFallback,
}

impl FallbackRelayOptions {
    pub(crate) fn with_reality_limits(
        xver: u8,
        upload_limit: LimitFallback,
        download_limit: LimitFallback,
    ) -> Self {
        Self {
            xver,
            upload_limit,
            download_limit,
        }
    }

    fn unlimited(xver: u8) -> Self {
        Self::with_reality_limits(xver, LimitFallback::default(), LimitFallback::default())
    }

    fn is_unlimited(self) -> bool {
        self.upload_limit.is_disabled() && self.download_limit.is_disabled()
    }
}

fn is_benign_fallback_client_disconnect(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

pub async fn relay_fallback(
    client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
) -> std::io::Result<()> {
    relay_fallback_with_xver(client, dest_addr, initial_client_bytes, 0, None).await
}

pub async fn relay_fallback_with_xver(
    client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
    xver: u8,
    stats: Option<&StatsSession>,
) -> std::io::Result<()> {
    relay_fallback_with_options(
        client,
        dest_addr,
        initial_client_bytes,
        FallbackRelayOptions::unlimited(xver),
        stats,
    )
    .await
}

pub(crate) async fn relay_fallback_with_options(
    mut client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
    options: FallbackRelayOptions,
    stats: Option<&StatsSession>,
) -> std::io::Result<()> {
    validate_fallback_xver(options.xver)?;

    debug!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver = options.xver,
        upload_limit = ?options.upload_limit,
        download_limit = ?options.download_limit,
        "forwarding client bytes to fallback target"
    );
    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver = options.xver,
        "fallback relay started"
    );

    debug!(%dest_addr, xver = options.xver, "fallback target connect started");
    let mut dest = timeout(FALLBACK_CONNECT_TIMEOUT, TcpStream::connect(dest_addr))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "fallback connect to {dest_addr} timed out after {:?}",
                    FALLBACK_CONNECT_TIMEOUT
                ),
            )
        })??;
    debug!(%dest_addr, xver = options.xver, "fallback target connected");

    if options.xver == 1 || options.xver == 2 {
        let peer = client.peer_addr()?;
        let local = client.local_addr()?;
        let proxy_header = if options.xver == 1 {
            build_proxy_protocol_v1(peer, local)?
        } else {
            build_proxy_protocol_v2(peer, local)?
        };
        dest.write_all(&proxy_header).await?;
        info!(
            %dest_addr,
            proxy_header_len = proxy_header.len(),
            xver = options.xver,
            "PROXY protocol header written"
        );
    }

    dest.write_all(initial_client_bytes).await?;
    if let Some(stats) = stats {
        stats.record_uplink(initial_client_bytes.len() as u64);
    }
    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver = options.xver,
        "initial bytes forwarded"
    );

    let outcome = if options.is_unlimited() {
        relay_bidirectional_unlimited(
            &mut client,
            &mut dest,
            dest_addr,
            options.xver,
            initial_client_bytes,
            stats.is_some(),
        )
        .await
    } else {
        relay_bidirectional_limited(client, dest, dest_addr, options, initial_client_bytes).await
    };

    if let Some(stats) = stats {
        stats.record_relay(outcome.client_to_dest, outcome.dest_to_client);
    }
    if let Some(err) = outcome.error {
        return Err(err);
    }

    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver = options.xver,
        client_to_dest = outcome.client_to_dest,
        dest_to_client = outcome.dest_to_client,
        "fallback relay completed"
    );
    Ok(())
}

struct RelayOutcome {
    client_to_dest: u64,
    dest_to_client: u64,
    error: Option<std::io::Error>,
}

async fn relay_bidirectional_unlimited(
    client: &mut TcpStream,
    dest: &mut TcpStream,
    dest_addr: &str,
    xver: u8,
    initial_client_bytes: &[u8],
    count_partial_writes: bool,
) -> RelayOutcome {
    let (result, client_to_dest, dest_to_client) = if count_partial_writes {
        let mut client = WriteCountingStream::new(client);
        let mut dest = WriteCountingStream::new(dest);
        let result = copy_bidirectional(&mut client, &mut dest).await;
        (result, dest.written, client.written)
    } else {
        match copy_bidirectional(client, dest).await {
            Ok((upload, download)) => (Ok((upload, download)), upload, download),
            Err(err) => (Err(err), 0, 0),
        }
    };

    let error = match result {
        Ok(_) => None,
        Err(err)
            if !initial_client_bytes.is_empty() && is_benign_fallback_client_disconnect(&err) =>
        {
            info!(
                %dest_addr,
                xver,
                error = %err,
                "fallback client disconnected after initial bytes were forwarded"
            );
            None
        }
        Err(err) => Some(err),
    };

    RelayOutcome {
        client_to_dest,
        dest_to_client,
        error,
    }
}

async fn relay_bidirectional_limited(
    client: TcpStream,
    dest: TcpStream,
    dest_addr: &str,
    options: FallbackRelayOptions,
    initial_client_bytes: &[u8],
) -> RelayOutcome {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut dest_read, mut dest_write) = dest.into_split();
    let mut client_to_dest = 0_u64;
    let mut dest_to_client = 0_u64;
    let initial_was_forwarded = !initial_client_bytes.is_empty();

    let upload = relay_direction(
        &mut client_read,
        &mut dest_write,
        DirectionalLimiter::new(options.upload_limit),
        &mut client_to_dest,
        RelayEndpoints::ClientToTarget,
        initial_was_forwarded,
    );
    let download = relay_direction(
        &mut dest_read,
        &mut client_write,
        DirectionalLimiter::new(options.download_limit),
        &mut dest_to_client,
        RelayEndpoints::TargetToClient,
        initial_was_forwarded,
    );

    let error = match tokio::try_join!(upload, download) {
        Ok(_) => None,
        Err(LimitedRelayError::ClientDisconnect(err)) => {
            info!(
                %dest_addr,
                xver = options.xver,
                error = %err,
                "fallback client disconnected during limited relay"
            );
            None
        }
        Err(LimitedRelayError::Io(err)) => Some(err),
    };

    RelayOutcome {
        client_to_dest,
        dest_to_client,
        error,
    }
}

#[derive(Debug, Clone, Copy)]
enum RelayEndpoints {
    ClientToTarget,
    TargetToClient,
}

enum LimitedRelayError {
    ClientDisconnect(std::io::Error),
    Io(std::io::Error),
}

async fn relay_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut limiter: DirectionalLimiter,
    total: &mut u64,
    endpoints: RelayEndpoints,
    initial_was_forwarded: bool,
) -> Result<(), LimitedRelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0_u8; FALLBACK_COPY_BUFFER_SIZE];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|err| classify_limited_error(err, endpoints, true, initial_was_forwarded))?;
        if n == 0 {
            writer.shutdown().await.map_err(|err| {
                classify_limited_error(err, endpoints, false, initial_was_forwarded)
            })?;
            return Ok(());
        }

        limiter.after_read(n).await;
        write_all_counted(writer, &buf[..n], total)
            .await
            .map_err(|err| classify_limited_error(err, endpoints, false, initial_was_forwarded))?;
    }
}

fn classify_limited_error(
    err: std::io::Error,
    endpoints: RelayEndpoints,
    reading: bool,
    initial_was_forwarded: bool,
) -> LimitedRelayError {
    let touches_client = matches!(
        (endpoints, reading),
        (RelayEndpoints::ClientToTarget, true) | (RelayEndpoints::TargetToClient, false)
    );
    if touches_client && initial_was_forwarded && is_benign_fallback_client_disconnect(&err) {
        LimitedRelayError::ClientDisconnect(err)
    } else {
        LimitedRelayError::Io(err)
    }
}

async fn write_all_counted<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut bytes: &[u8],
    total: &mut u64,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written = writer.write(bytes).await?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write relayed fallback bytes",
            ));
        }
        *total = total.saturating_add(written as u64);
        bytes = &bytes[written..];
    }
    Ok(())
}

struct WriteCountingStream<'a> {
    inner: &'a mut TcpStream,
    written: u64,
}

impl<'a> WriteCountingStream<'a> {
    fn new(inner: &'a mut TcpStream) -> Self {
        Self { inner, written: 0 }
    }
}

impl AsyncRead for WriteCountingStream<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for WriteCountingStream<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                this.written = this.written.saturating_add(written as u64);
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/fallback.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/proxy/fallback_limits.rs"]
mod limit_tests;
