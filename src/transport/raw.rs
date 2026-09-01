use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};

use crate::reality::stages;
use crate::reality::tls13::RealityTls13ApplicationStream;
use crate::vless::encryption::{handshake_and_wrap, map_handshake_error};
use crate::vless::handle_vless_tcp_inbound_with_auth_context;

use super::VlessHandler;

pub async fn run_raw_transport<S>(
    stream: RealityTls13ApplicationStream<S>,
    handler: &VlessHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(
        kind = "raw",
        inbound_tag = handler.inbound_tag(),
        encrypted = handler.encryption_server().is_some(),
        "transport bridge started"
    );

    if let Some(server) = handler.encryption_server() {
        debug!(
            stage = stages::VLESS_START,
            inbound_tag = handler.inbound_tag(),
            nfs_key_count = server.nfs_key_count(),
            xor_mode = ?server.xor_mode(),
            "starting VLESS encryption handshake"
        );
        let encrypted = handshake_and_wrap(server.as_ref(), stream)
            .await
            .map_err(map_handshake_error)?;
        debug!(
            stage = stages::VLESS_START,
            inbound_tag = handler.inbound_tag(),
            "VLESS encryption handshake complete; handing off to VLESS inbound"
        );
        let result = handle_vless_tcp_inbound_with_auth_context(
            encrypted,
            handler.auth_context(),
            handler.socket_meta(),
            handler.router(),
        )
        .await;
        if result.is_ok() {
            info!(
                kind = "raw",
                inbound_tag = handler.inbound_tag(),
                encrypted = true,
                "transport bridge completed"
            );
        }
        return result;
    }

    debug!(
        stage = stages::VLESS_START,
        inbound_tag = handler.inbound_tag(),
        vless_client_count = handler.user_count(),
        "handing off to VLESS inbound"
    );

    let result = crate::vless::handle_reality_vless_tcp_inbound_traced(
        stream,
        Some(handler.auth_context()),
        None,
        None,
        handler.mux_trace(),
        handler.socket_meta(),
        handler.router(),
    )
    .await;

    if result.is_ok() {
        info!(
            kind = "raw",
            inbound_tag = handler.inbound_tag(),
            "transport bridge completed"
        );
    }

    result
}

#[cfg(test)]
#[path = "../../tests/unit/transport/raw.rs"]
mod tests;
