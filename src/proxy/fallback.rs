use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

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

    let mut dest = TcpStream::connect(dest_addr).await?;
    dest.write_all(initial_client_bytes).await?;
    copy_bidirectional(&mut client, &mut dest).await?;

    info!(%dest_addr, "fallback relay ended");
    Ok(())
}
