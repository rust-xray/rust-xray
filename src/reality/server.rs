use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::tls::TlsClientHelloRecord;
use crate::vless::VlessClient;

use super::decision::RealityAccepted;
use super::handshake::{fetch_dest_handshake, patch_reality_server_hello};
use super::session::short_id_prefix_len;

const ACCEPTED_DEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Handles a REALITY client that passed AEAD decrypt and policy validation.
///
/// Accepted clients must **not** be relayed to fallback. This handler is the
/// only entry point for the future server-side REALITY handshake path.
pub async fn handle_accepted_reality_client(
    client: TcpStream,
    record: TlsClientHelloRecord,
    accepted: RealityAccepted,
    dest_addr: &str,
    vless_clients: &[VlessClient],
) -> std::io::Result<()> {
    let _client = client;

    info!(
        sni = ?accepted.sni,
        client_version = ?accepted.client.client_version,
        unix_time = accepted.client.unix_time,
        short_id_len = short_id_prefix_len(&accepted.client.short_id),
        vless_client_count = vless_clients.len(),
        %dest_addr,
        "REALITY accepted path started"
    );

    info!(%dest_addr, "REALITY accepted path connecting to dest");
    let mut dest = timeout(ACCEPTED_DEST_CONNECT_TIMEOUT, TcpStream::connect(dest_addr))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "REALITY accepted path connect to {dest_addr} timed out after {:?}",
                    ACCEPTED_DEST_CONNECT_TIMEOUT
                ),
            )
        })??;
    info!(%dest_addr, "REALITY accepted path dest connected");

    info!(
        %dest_addr,
        client_hello_record_len = record.raw_record.len(),
        "REALITY accepted path forwarding client hello record to dest"
    );
    let dest_handshake = fetch_dest_handshake(&mut dest, &record.raw_record).await?;

    info!(
        %dest_addr,
        dest_record_count = dest_handshake.records.len(),
        dest_bytes = dest_handshake.raw_server_bytes.len(),
        "REALITY accepted path dest ServerHello observed"
    );

    match patch_reality_server_hello(dest_handshake, &accepted) {
        Ok(_) => Ok(()),
        Err(err) => {
            if err.to_string().contains("TLS 1.3 server handshake") {
                warn!(
                    %dest_addr,
                    "REALITY accepted path stopping because TLS server handshake is not implemented"
                );
            }
            Err(err)
        }
    }
}
