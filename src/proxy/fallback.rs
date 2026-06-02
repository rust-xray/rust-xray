use std::time::Duration;

use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::stats::StatsSession;
use crate::vless::{build_proxy_protocol_v1, build_proxy_protocol_v2, validate_fallback_xver};

const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    mut client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
    xver: u8,
    stats: Option<&StatsSession>,
) -> std::io::Result<()> {
    validate_fallback_xver(xver)?;

    debug!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        "forwarding client bytes to fallback target"
    );

    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        "fallback relay started"
    );

    debug!(%dest_addr, xver, "fallback target connect started");
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
    debug!(%dest_addr, xver, "fallback target connected");

    if xver == 1 || xver == 2 {
        let peer = client.peer_addr()?;
        let local = client.local_addr()?;
        let proxy_header = if xver == 1 {
            build_proxy_protocol_v1(peer, local)?
        } else {
            build_proxy_protocol_v2(peer, local)?
        };
        dest.write_all(&proxy_header).await?;
        info!(
            %dest_addr,
            proxy_header_len = proxy_header.len(),
            xver,
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
        xver,
        "initial bytes forwarded"
    );

    let relay_result = copy_bidirectional(&mut client, &mut dest).await;
    let (client_to_dest, dest_to_client) = match relay_result {
        Ok(counts) => counts,
        Err(err)
            if !initial_client_bytes.is_empty() && is_benign_fallback_client_disconnect(&err) =>
        {
            info!(
                %dest_addr,
                xver,
                error = %err,
                "fallback client disconnected after initial bytes were forwarded"
            );
            (initial_client_bytes.len() as u64, 0)
        }
        Err(err) => return Err(err),
    };

    if let Some(stats) = stats {
        stats.record_relay(client_to_dest, dest_to_client);
    }

    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        client_to_dest,
        dest_to_client,
        "fallback relay completed"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/proxy/fallback.rs"]
mod tests;
