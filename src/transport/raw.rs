use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};

use crate::reality::stages;
use crate::reality::tls13::RealityTls13ApplicationStream;
use crate::vless::handle_reality_vless_tcp_inbound_traced;

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
        "transport bridge started"
    );
    debug!(
        stage = stages::VLESS_START,
        inbound_tag = handler.inbound_tag(),
        vless_client_count = handler.user_count(),
        "handing off to VLESS inbound"
    );

    let result = handle_reality_vless_tcp_inbound_traced(
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
