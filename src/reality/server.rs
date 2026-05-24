use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use crate::protocol::structs::ClientHelloPayload;
use crate::tls::TlsClientHelloRecord;
use crate::vless::handle_vless_tcp_inbound;
use crate::vless::VlessClient;

use super::decision::RealityAccepted;
use super::handshake::{fetch_dest_handshake, prepare_reality_tls13_state};
use super::session::short_id_prefix_len;
use super::tls13::complete_reality_tls13_handshake;

const ACCEPTED_DEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Handles a REALITY client that passed AEAD decrypt and policy validation.
///
/// Accepted clients must **not** be relayed to fallback. This handler completes the
/// REALITY TLS 1.3 handshake and hands the decrypted application stream to VLESS.
pub async fn handle_accepted_reality_client(
    client: TcpStream,
    record: TlsClientHelloRecord,
    client_hello_payload: ClientHelloPayload,
    accepted: RealityAccepted,
    dest_addr: &str,
    vless_clients: &[VlessClient],
) -> std::io::Result<()> {
    info!(
        sni = ?accepted.sni,
        client_version = ?accepted.client.client_version,
        unix_time = accepted.client.unix_time,
        short_id_len = short_id_prefix_len(&accepted.client.short_id),
        vless_client_count = vless_clients.len(),
        %dest_addr,
        "REALITY accepted client"
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

    let state = prepare_reality_tls13_state(dest_handshake, accepted)?;

    info!(
        %dest_addr,
        cipher_suite = state.suite.name,
        sni = ?state.accepted.sni,
        "REALITY observed destination ServerHello OK"
    );

    let cipher_suite = state.suite.name;

    let mut tls_app_stream = complete_reality_tls13_handshake(
        client,
        &client_hello_payload,
        &record.handshake_message,
        state,
    )
    .await?;

    info!(
        %dest_addr,
        cipher_suite,
        "REALITY TLS 1.3 handshake complete"
    );

    info!(
        %dest_addr,
        vless_client_count = vless_clients.len(),
        "REALITY VLESS handler started"
    );

    handle_vless_tcp_inbound(&mut tls_app_stream, vless_clients).await?;

    info!(%dest_addr, "REALITY accepted path relay ended");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::reality::tls13::RealityTls13ApplicationStream;
    use tokio::io::{AsyncRead, AsyncWrite};

    fn assert_vless_stream_bounds<S: AsyncRead + AsyncWrite + Unpin>() {}

    #[test]
    fn reality_application_stream_satisfies_vless_inbound_bounds() {
        assert_vless_stream_bounds::<RealityTls13ApplicationStream<tokio::io::DuplexStream>>();
    }
}
