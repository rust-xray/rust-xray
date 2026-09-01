use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::config::InboundTransportConfig;
use crate::mux::MuxSessionTrace;
use crate::protocol::structs::ClientHelloPayload;
use crate::reality::Mldsa65Seed;
use crate::routing::{RouteSocketMeta, RuntimeRouter};
use crate::runtime::VlessInboundAuthContext;
use crate::tls::{PrefixedStream, TlsClientHelloRecord};
use crate::transport::{run_inbound_transport, AcceptedTransport, VlessHandler};
use crate::vless::encryption::SharedVlessEncryptionServer;

use super::decision::RealityAccepted;
use super::handshake::{fetch_dest_handshake, prepare_reality_tls13_state};
use super::session::short_id_prefix_len;
use super::stages::{self, stage_error, RealityAcceptedStage};
use super::tls13::complete_reality_tls13_handshake;

const ACCEPTED_DEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Handles a REALITY client that passed AEAD decrypt and policy validation.
///
/// Accepted clients must **not** be relayed to fallback. This handler completes the
/// REALITY TLS 1.3 handshake and hands the decrypted application stream to transport dispatch.
pub async fn handle_accepted_reality_client(
    client: TcpStream,
    record: TlsClientHelloRecord,
    client_hello_payload: ClientHelloPayload,
    accepted: RealityAccepted,
    dest_addr: &str,
    auth: VlessInboundAuthContext,
    mldsa65_seed: Option<&Mldsa65Seed>,
    transport: &InboundTransportConfig,
    source_ip: Option<std::net::IpAddr>,
) -> std::io::Result<()> {
    handle_accepted_reality_client_traced(
        client,
        record,
        client_hello_payload,
        accepted,
        dest_addr,
        auth,
        mldsa65_seed,
        transport,
        None,
        RouteSocketMeta {
            source_ip,
            ..Default::default()
        },
        None,
        None,
    )
    .await
}

pub async fn handle_accepted_reality_client_traced(
    client: TcpStream,
    record: TlsClientHelloRecord,
    client_hello_payload: ClientHelloPayload,
    accepted: RealityAccepted,
    dest_addr: &str,
    auth: VlessInboundAuthContext,
    mldsa65_seed: Option<&Mldsa65Seed>,
    transport: &InboundTransportConfig,
    mux_trace: Option<MuxSessionTrace>,
    socket_meta: RouteSocketMeta,
    router: Option<std::sync::Arc<RuntimeRouter>>,
    encryption_server: Option<SharedVlessEncryptionServer>,
) -> std::io::Result<()> {
    let path_started = Instant::now();
    let logical_inbound_count = auth.auth_set().manager_count();
    info!(
        conn_id = mux_trace.map(|trace| trace.conn_id),
        elapsed_ms_since_conn_start = mux_trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        stage = stages::ACCEPTED_START,
        sni = ?accepted.sni,
        client_version = ?accepted.client.client_version,
        unix_time = accepted.client.unix_time,
        short_id_len = short_id_prefix_len(&accepted.client.short_id),
        logical_inbound_count,
        client_hello_record_len = record.raw_record.len(),
        %dest_addr,
        "REALITY accepted path started"
    );

    debug!(
        conn_id = mux_trace.map(|trace| trace.conn_id),
        elapsed_ms_since_conn_start = mux_trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        stage = stages::DEST_CONNECT_START,
        %dest_addr,
        "connecting to dest"
    );
    let dest_handshake = {
        let mut dest = timeout(ACCEPTED_DEST_CONNECT_TIMEOUT, TcpStream::connect(dest_addr))
            .await
            .map_err(|_| {
                stage_error(
                    RealityAcceptedStage::DestConnect,
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "connect to {dest_addr} timed out after {:?}",
                            ACCEPTED_DEST_CONNECT_TIMEOUT
                        ),
                    ),
                )
            })?
            .map_err(|err| stage_error(RealityAcceptedStage::DestConnect, err))?;

        debug!(
            conn_id = mux_trace.map(|trace| trace.conn_id),
            elapsed_ms_since_conn_start =
                mux_trace.map(|trace| trace.conn_started.elapsed().as_millis()),
            stage = stages::DEST_CONNECT_OK,
            %dest_addr,
            "dest TCP connected"
        );

        debug!(
            stage = stages::DEST_SERVER_HELLO_OBSERVED,
            %dest_addr,
            client_hello_record_len = record.raw_record.len(),
            "forwarding ClientHello record to dest"
        );
        let dest_handshake = fetch_dest_handshake(&mut dest, &record.raw_record)
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::DestServerHello, err))?;

        debug!(
            stage = stages::DEST_SERVER_HELLO_OBSERVED,
            %dest_addr,
            dest_record_count = dest_handshake.records.len(),
            observed_server_bytes_len = dest_handshake.raw_server_bytes.len(),
            "dest ServerHello observed; closing target observation socket"
        );

        // Observation data is copied into `dest_handshake`; drop the outbound target TCP socket.
        drop(dest);
        dest_handshake
    };

    let mut state = prepare_reality_tls13_state(dest_handshake, accepted)
        .map_err(|err| stage_error(RealityAcceptedStage::Tls13State, err))?;
    state.post_handshake_dest_addr = dest_addr.to_string();

    let cipher_suite = state.suite.name;

    let client = PrefixedStream::new(client, record.trailing_bytes.clone());

    let handshake_started = Instant::now();
    let tls_app_stream = complete_reality_tls13_handshake(
        client,
        &client_hello_payload,
        &record.handshake_message,
        mldsa65_seed,
        state,
    )
    .await?;
    debug!(
        conn_id = mux_trace.map(|trace| trace.conn_id),
        elapsed_ms_since_conn_start =
            mux_trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        stage = stages::TLS13_APPLICATION_STREAM_READY,
        duration_ms = handshake_started.elapsed().as_millis(),
        cipher_suite,
        "REALITY TLS 1.3 handshake completed"
    );

    let accepted_transport = AcceptedTransport::from_inbound_transport_config(transport)?;
    let vless_handler = VlessHandler::new_with_auth_context(
        auth,
        mux_trace,
        socket_meta,
        router,
        encryption_server,
    );

    run_inbound_transport(accepted_transport, tls_app_stream, &vless_handler).await?;

    debug!(
        stage = stages::VLESS_RELAY_DONE,
        %dest_addr,
        duration_ms = path_started.elapsed().as_millis(),
        "REALITY accepted path completed"
    );
    info!(stage = stages::VLESS_RELAY_DONE, %dest_addr, "REALITY accepted path complete");

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/reality/server.rs"]
mod tests;
