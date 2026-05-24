use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::protocol::structs::ClientHelloPayload;
use crate::tls::TlsClientHelloRecord;
use crate::vless::VlessClient;

use super::decision::RealityAccepted;
use super::handshake::{
    fetch_dest_handshake, generate_partial_tls13_handshake, prepare_reality_tls13_state,
};
use super::session::short_id_prefix_len;

const ACCEPTED_DEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const PARTIAL_TLS13_ACCEPTED_PATH_UNSUPPORTED_MSG: &str =
    "REALITY partial TLS 1.3 handshake generated; full server handshake not implemented yet";

/// Returns true when `RUST_XRAY_EXPERIMENTAL_SEND_PARTIAL_TLS13=1`.
pub fn experimental_partial_tls13_send_enabled() -> bool {
    experimental_partial_tls13_send_enabled_with(
        std::env::var("RUST_XRAY_EXPERIMENTAL_SEND_PARTIAL_TLS13")
            .ok()
            .as_deref(),
    )
}

pub(crate) fn experimental_partial_tls13_send_enabled_with(env_value: Option<&str>) -> bool {
    env_value == Some("1")
}

pub fn partial_tls13_accepted_path_result() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        PARTIAL_TLS13_ACCEPTED_PATH_UNSUPPORTED_MSG,
    )
}

/// Handles a REALITY client that passed AEAD decrypt and policy validation.
///
/// Accepted clients must **not** be relayed to fallback. This handler is the
/// only entry point for the future server-side REALITY handshake path.
pub async fn handle_accepted_reality_client(
    mut client: TcpStream,
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

    let mut state = prepare_reality_tls13_state(dest_handshake, accepted)?;

    info!(
        %dest_addr,
        cipher_suite = state.suite.name,
        sni = ?state.accepted.sni,
        "REALITY observed destination ServerHello OK"
    );

    let partial = generate_partial_tls13_handshake(
        &mut state,
        &client_hello_payload,
        &record.handshake_message,
    )?;

    let experimental_send = experimental_partial_tls13_send_enabled();

    info!(
        %dest_addr,
        server_hello_record_len = partial.server_hello_record.len(),
        encrypted_handshake_records_len = partial.encrypted_handshake_records.len(),
        partial_tls13_total_len = partial.total_len(),
        experimental_send_enabled = experimental_send,
        "REALITY partial TLS 1.3 handshake generated"
    );

    if experimental_send {
        info!(
            %dest_addr,
            "REALITY experimental partial TLS 1.3 send enabled; writing ServerHello and encrypted records to client (packet inspection only)"
        );
        client.write_all(&partial.server_hello_record).await?;
        client
            .write_all(&partial.encrypted_handshake_records)
            .await?;
    } else {
        info!(
            %dest_addr,
            "REALITY partial TLS 1.3 handshake generated but not sent (set RUST_XRAY_EXPERIMENTAL_SEND_PARTIAL_TLS13=1 for packet inspection only)"
        );
    }

    warn!(
        %dest_addr,
        cipher_suite = state.suite.name,
        experimental_send_enabled = experimental_send,
        "REALITY accepted path stopping before full TLS 1.3 server handshake"
    );

    Err(partial_tls13_accepted_path_result())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn experimental_partial_tls13_send_disabled_unless_env_one() {
        assert!(!experimental_partial_tls13_send_enabled_with(None));
        assert!(!experimental_partial_tls13_send_enabled_with(Some("0")));
        assert!(!experimental_partial_tls13_send_enabled_with(Some("true")));
        assert!(experimental_partial_tls13_send_enabled_with(Some("1")));
    }

    #[test]
    fn accepted_path_still_returns_unsupported_after_partial_generation() {
        let err = partial_tls13_accepted_path_result();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.to_string(), PARTIAL_TLS13_ACCEPTED_PATH_UNSUPPORTED_MSG);
    }
}
