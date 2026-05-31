use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::config::TransportNetwork;
use crate::config::XHttpSettings;
use crate::protocol::structs::ClientHelloPayload;
use crate::reality::Mldsa65Seed;
use crate::stats::StatsState;
use crate::tls::{PrefixedStream, TlsClientHelloRecord};
use crate::transport::{run_inbound_transport, AcceptedTransport, VlessHandler};
use crate::vless::mux::MuxSessionTrace;
use crate::vless::VlessUserManager;

use super::decision::RealityAccepted;
use super::handshake::{fetch_dest_handshake, prepare_reality_tls13_state};
use super::session::short_id_prefix_len;
use super::stages::{self, stage_error, RealityAcceptedStage};
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
    users: std::sync::Arc<VlessUserManager>,
    mldsa65_seed: Option<&Mldsa65Seed>,
    stats_state: Option<&StatsState>,
    transport: &TransportNetwork,
    xhttp_settings: Option<&XHttpSettings>,
) -> std::io::Result<()> {
    handle_accepted_reality_client_traced(
        client,
        record,
        client_hello_payload,
        accepted,
        dest_addr,
        users,
        mldsa65_seed,
        stats_state,
        transport,
        xhttp_settings,
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
    users: std::sync::Arc<VlessUserManager>,
    mldsa65_seed: Option<&Mldsa65Seed>,
    stats_state: Option<&StatsState>,
    transport: &TransportNetwork,
    xhttp_settings: Option<&XHttpSettings>,
    mux_trace: Option<MuxSessionTrace>,
) -> std::io::Result<()> {
    let path_started = Instant::now();
    info!(
        conn_id = mux_trace.map(|trace| trace.conn_id),
        elapsed_ms_since_conn_start = mux_trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        stage = stages::ACCEPTED_START,
        sni = ?accepted.sni,
        client_version = ?accepted.client.client_version,
        unix_time = accepted.client.unix_time,
        short_id_len = short_id_prefix_len(&accepted.client.short_id),
        vless_client_count = users.user_count(),
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
        elapsed_ms_since_conn_start = mux_trace.map(|trace| trace.conn_started.elapsed().as_millis()),
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
    let server_hello_original = dest_handshake.raw_server_bytes.clone();

    debug!(
        stage = stages::DEST_SERVER_HELLO_OBSERVED,
        %dest_addr,
        dest_record_count = dest_handshake.records.len(),
        observed_server_bytes_len = dest_handshake.raw_server_bytes.len(),
        "dest ServerHello observed"
    );

    let state = prepare_reality_tls13_state(dest_handshake, accepted)
        .map_err(|err| stage_error(RealityAcceptedStage::Tls13State, err))?;

    let cipher_suite = state.suite.name;

    let client = PrefixedStream::new(client, record.trailing_bytes.clone());

    let handshake_started = Instant::now();
    let tls_app_stream = complete_reality_tls13_handshake(
        client,
        &client_hello_payload,
        &record.handshake_message,
        &record.raw_record,
        &server_hello_original,
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

    let accepted_transport = AcceptedTransport::from_reality_runtime(transport, xhttp_settings)?;
    let vless_handler = VlessHandler::new(users, stats_state.cloned(), mux_trace);

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
mod tests {
    use crate::reality::tls13::RealityTls13ApplicationStream;
    use tokio::io::{AsyncRead, AsyncWrite};

    fn assert_vless_stream_bounds<S: AsyncRead + AsyncWrite + Unpin>() {}

    #[test]
    fn reality_application_stream_satisfies_vless_inbound_bounds() {
        assert_vless_stream_bounds::<RealityTls13ApplicationStream<tokio::io::DuplexStream>>();
    }
}
