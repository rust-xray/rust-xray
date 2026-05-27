use std::time::Duration;

use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use crate::vless::{build_proxy_protocol_v1, build_proxy_protocol_v2, validate_fallback_xver};

const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn relay_fallback(
    client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
) -> std::io::Result<()> {
    relay_fallback_with_xver(client, dest_addr, initial_client_bytes, 0).await
}

pub async fn relay_fallback_with_xver(
    mut client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
    xver: u8,
) -> std::io::Result<()> {
    validate_fallback_xver(xver)?;

    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        "fallback relay started"
    );

    info!(%dest_addr, xver, "fallback connect started");
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
    info!(%dest_addr, xver, "fallback connected");

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
            "PROXY protocol header forwarded"
        );
    }

    dest.write_all(initial_client_bytes).await?;
    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        "initial bytes forwarded"
    );

    let (client_to_dest, dest_to_client) = copy_bidirectional(&mut client, &mut dest).await?;

    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        client_to_dest,
        dest_to_client,
        "fallback relay ended"
    );
    Ok(())
}
