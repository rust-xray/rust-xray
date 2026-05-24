use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::tls::TlsClientHelloRecord;

use super::decision::RealityAccepted;
use super::session::short_id_prefix_len;

pub(crate) const NOT_IMPLEMENTED_MSG: &str =
    "REALITY accepted path is not implemented yet: ServerHello patching and VLESS/Vision integration are TODO";

pub(crate) fn accepted_path_not_implemented_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Unsupported, NOT_IMPLEMENTED_MSG)
}

/// Handles a REALITY client that passed AEAD decrypt and policy validation.
///
/// Accepted clients must **not** be relayed to fallback. This handler is the
/// only entry point for the future server-side REALITY handshake path.
pub async fn handle_accepted_reality_client(
    client: TcpStream,
    record: TlsClientHelloRecord,
    accepted: RealityAccepted,
    dest_addr: &str,
) -> std::io::Result<()> {
    let _ = (client, record);

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

    // TODO: connect to dest
    // TODO: forward ClientHello
    // TODO: read dest ServerHello/handshake
    // TODO: patch ServerHello according to REALITY
    // TODO: send patched handshake to client
    // TODO: hand off stream to VLESS/Vision

    Err(accepted_path_not_implemented_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_path_not_implemented_error_is_unsupported() {
        let err = accepted_path_not_implemented_error();

        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), NOT_IMPLEMENTED_MSG);
    }
}
