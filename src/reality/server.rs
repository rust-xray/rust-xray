use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::tls::TlsClientHelloRecord;

use super::decision::RealityAccepted;
use super::session::short_id_prefix_len;

const NOT_IMPLEMENTED_MSG: &str =
    "REALITY accepted path is not implemented yet: ServerHello patching and VLESS/Vision integration are TODO";

/// Handles a REALITY client that passed AEAD decrypt and policy validation.
///
/// This is the entry point for the future server-side REALITY handshake path.
pub async fn handle_accepted_reality_client(
    _client: TcpStream,
    _record: TlsClientHelloRecord,
    accepted: RealityAccepted,
    dest_addr: &str,
) -> std::io::Result<()> {
    info!(
        sni = ?accepted.sni,
        client_version = ?accepted.client.client_version,
        unix_time = accepted.client.unix_time,
        short_id_len = short_id_prefix_len(&accepted.client.short_id),
        %dest_addr,
        "REALITY client accepted after AEAD + policy validation"
    );

    warn!(
        %dest_addr,
        "REALITY accepted path reached but not implemented"
    );

    // TODO: connect to dest;
    // TODO: forward ClientHello;
    // TODO: read ServerHello/handshake from dest;
    // TODO: patch ServerHello/session;
    // TODO: pass accepted stream to VLESS/Vision.

    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        NOT_IMPLEMENTED_MSG,
    ))
}
