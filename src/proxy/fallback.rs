use std::time::Duration;

use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn relay_fallback(
    mut client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
) -> std::io::Result<()> {
    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        "fallback relay started"
    );

    info!(%dest_addr, "fallback connect started");
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
    info!(%dest_addr, "fallback connected");

    dest.write_all(initial_client_bytes).await?;
    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        "initial bytes forwarded"
    );

    let (client_to_dest, dest_to_client) = copy_bidirectional(&mut client, &mut dest).await?;

    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        client_to_dest,
        dest_to_client,
        "fallback relay ended"
    );
    Ok(())
}
