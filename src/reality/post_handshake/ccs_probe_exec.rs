//! Active target extra-CCS tolerance probe (Stage 5C).
//!
//! Injection boundary (Stage 5C audit): intercept the first outgoing rustls TLS 1.3
//! middlebox compatibility CCS (`14 03 03 00 01 01`) before forwarding it to the target,
//! inject cumulative extra CCS on the same connection, then forward the original client flight.
//!
//! **Upstream parity:** YES for rustls — audit confirmed rustls emits compatibility CCS on the
//! TLS 1.3 client path (coalesced with encrypted Finished in one `write_tls` chunk is handled
//! via [`OutgoingTlsRecordBuffer`]).

use std::io::{Error as IoError, ErrorKind};
use std::time::Duration;

use tokio::time::{sleep, timeout};
use tracing::debug;

use crate::reality::dest_dial::{
    RealityDestDialConfig, RealityDestProxyEndpoints, RealityDestStream,
};

use super::cache::PostHandshakeProbeKey;
use super::ccs_probe::{build_extra_ccs_probe_payload, CcsProbeStep, CcsToleranceProbe};
use super::probe::POST_HANDSHAKE_PROBE_HANDSHAKE_TIMEOUT;
use super::probe_io::{
    is_tls13_compatibility_ccs_record, rustls_error_to_io, InboundAlertObserver,
    OutgoingTlsRecordBuffer,
};
use super::tls_client::{
    build_post_handshake_probe_client_config, build_post_handshake_probe_connection,
};
use super::tolerance::UselessRecordTolerance;

/// Upstream waits ~1 second after each cumulative CCS batch.
pub const CCS_PROBE_BATCH_WAIT: Duration = Duration::from_secs(1);

/// Overall bound for dial + handshake + cumulative CCS tiers on one connection.
pub const CCS_PROBE_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

const PROBE_READ_CHUNK: usize = 4096;

/// Runs a full CCS tolerance probe; any failure returns [`UselessRecordTolerance::DEFAULT`].
pub async fn execute_ccs_tolerance_probe(
    dial_config: &RealityDestDialConfig,
    key: &PostHandshakeProbeKey,
) -> UselessRecordTolerance {
    let client_config = match build_post_handshake_probe_client_config(key.alpn_profile) {
        Ok(config) => config,
        Err(err) => {
            debug!(
                dest = %key.dest_addr,
                server_name = %key.server_name,
                alpn_profile = ?key.alpn_profile,
                error = %err,
                "REALITY CCS tolerance probe TLS config failed"
            );
            return UselessRecordTolerance::DEFAULT;
        }
    };

    match timeout(
        CCS_PROBE_TOTAL_TIMEOUT,
        execute_ccs_tolerance_probe_with_client_config(dial_config, key, client_config),
    )
    .await
    {
        Ok(Ok(tolerance)) => tolerance,
        Ok(Err(err)) => {
            debug!(
                dest = %key.dest_addr,
                server_name = %key.server_name,
                alpn_profile = ?key.alpn_profile,
                error = %err,
                "REALITY CCS tolerance probe failed"
            );
            UselessRecordTolerance::DEFAULT
        }
        Err(_) => {
            debug!(
                dest = %key.dest_addr,
                server_name = %key.server_name,
                alpn_profile = ?key.alpn_profile,
                timeout_secs = CCS_PROBE_TOTAL_TIMEOUT.as_secs(),
                "REALITY CCS tolerance probe timed out"
            );
            UselessRecordTolerance::DEFAULT
        }
    }
}

/// Test hook: run CCS tolerance probe with an explicit root store (local mock CA).
#[cfg(test)]
pub(crate) async fn execute_ccs_tolerance_probe_with_roots(
    dial_config: &RealityDestDialConfig,
    key: &PostHandshakeProbeKey,
    roots: rustls::RootCertStore,
) -> UselessRecordTolerance {
    let client_config = match super::tls_client::build_post_handshake_probe_client_config_with_roots(
        key.alpn_profile,
        roots,
    ) {
        Ok(config) => config,
        Err(_) => return UselessRecordTolerance::DEFAULT,
    };

    timeout(
        CCS_PROBE_TOTAL_TIMEOUT,
        execute_ccs_tolerance_probe_with_client_config(dial_config, key, client_config),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or(UselessRecordTolerance::DEFAULT)
}

async fn execute_ccs_tolerance_probe_with_client_config(
    dial_config: &RealityDestDialConfig,
    key: &PostHandshakeProbeKey,
    client_config: std::sync::Arc<rustls::ClientConfig>,
) -> Result<UselessRecordTolerance, IoError> {
    let proxy_endpoints = if dial_config.xver == 1 || dial_config.xver == 2 {
        Some(RealityDestProxyEndpoints::for_probe(
            &dial_config.dest_addr,
        )?)
    } else {
        None
    };

    debug!(
        dest = %key.dest_addr,
        server_name = %key.server_name,
        alpn_profile = ?key.alpn_profile,
        xver = dial_config.xver,
        transport = ?dial_config.transport,
        "REALITY CCS tolerance probe started"
    );

    let mut stream =
        crate::reality::dest_dial::dial_reality_dest(dial_config, proxy_endpoints).await?;

    let mut connection = build_post_handshake_probe_connection(client_config, &key.server_name)
        .map_err(|err| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("REALITY CCS tolerance probe TLS connection failed: {err}"),
            )
        })?;

    let tolerance = timeout(
        POST_HANDSHAKE_PROBE_HANDSHAKE_TIMEOUT,
        drive_ccs_probe_handshake(&mut connection, &mut stream),
    )
    .await
    .map_err(|_| {
        IoError::new(
            ErrorKind::TimedOut,
            format!(
                "REALITY CCS tolerance probe TLS handshake timed out after {:?}",
                POST_HANDSHAKE_PROBE_HANDSHAKE_TIMEOUT
            ),
        )
    })??;

    let _ = stream.shutdown().await;

    debug!(
        dest = %key.dest_addr,
        server_name = %key.server_name,
        alpn_profile = ?key.alpn_profile,
        ?tolerance,
        "REALITY CCS tolerance probe completed"
    );

    Ok(tolerance)
}

async fn drive_ccs_probe_handshake(
    connection: &mut rustls::ClientConnection,
    stream: &mut RealityDestStream,
) -> Result<UselessRecordTolerance, IoError> {
    let mut inbound = vec![0u8; PROBE_READ_CHUNK];
    let mut outbound = Vec::new();
    let mut outbound_buffer = OutgoingTlsRecordBuffer::default();
    let mut alert_observer = InboundAlertObserver::default();
    let mut ccs_probe = CcsToleranceProbe::new();
    let mut ccs_injected = false;
    let mut probe_result: Option<UselessRecordTolerance> = None;

    loop {
        while connection.wants_write() {
            outbound.clear();
            let written = connection.write_tls(&mut outbound)?;
            if written == 0 {
                break;
            }
            outbound_buffer.push_chunk(&outbound);
            while let Some(record) = outbound_buffer.pop_complete_record() {
                if is_tls13_compatibility_ccs_record(&record) && !ccs_injected {
                    ccs_injected = true;
                    probe_result = Some(
                        run_cumulative_ccs_probe(stream, &mut ccs_probe, &mut alert_observer)
                            .await?,
                    );
                }
                stream.write_all(&record).await?;
            }
        }

        if !connection.is_handshaking() {
            break;
        }

        if connection.wants_read() {
            let read_len = stream.read(&mut inbound).await?;
            if read_len == 0 {
                return Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "REALITY CCS tolerance probe destination closed during TLS handshake",
                ));
            }
            alert_observer.ingest(&inbound[..read_len]);
            let mut cursor = &inbound[..read_len];
            while !cursor.is_empty() {
                connection.read_tls(&mut cursor)?;
            }
            connection
                .process_new_packets()
                .map_err(rustls_error_to_io)?;
        } else if ccs_injected && ccs_probe.is_complete() {
            sleep(Duration::from_millis(10)).await;
        }
    }

    Ok(probe_result.unwrap_or(UselessRecordTolerance::DEFAULT))
}

async fn run_cumulative_ccs_probe(
    stream: &mut RealityDestStream,
    probe: &mut CcsToleranceProbe,
    alert_observer: &mut InboundAlertObserver,
) -> Result<UselessRecordTolerance, IoError> {
    while !probe.is_complete() {
        let batch_count = probe.pending_batch_count().ok_or_else(|| {
            IoError::new(
                ErrorKind::InvalidData,
                "REALITY CCS tolerance probe requested batch while complete",
            )
        })?;

        let payload = build_extra_ccs_probe_payload(batch_count);
        stream.write_all(&payload).await?;
        probe.record_batch_sent();

        alert_observer.begin_observation();
        let alerted = wait_for_batch_alert(stream, alert_observer).await?;
        if alerted {
            alert_observer.end_observation();
            return Ok(probe.observe_alert());
        }
        alert_observer.end_observation();

        match probe.observe_no_alert() {
            CcsProbeStep::SendBatch(_) => {}
            CcsProbeStep::Complete(tolerance) => return Ok(tolerance),
        }
    }

    Ok(probe.result().unwrap_or(UselessRecordTolerance::DEFAULT))
}

async fn wait_for_batch_alert(
    stream: &mut RealityDestStream,
    alert_observer: &mut InboundAlertObserver,
) -> Result<bool, IoError> {
    let mut inbound = vec![0u8; PROBE_READ_CHUNK];
    let deadline = tokio::time::Instant::now() + CCS_PROBE_BATCH_WAIT;

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let read_result = timeout(remaining, stream.read(&mut inbound)).await;

        match read_result {
            Ok(Ok(0)) => {
                return Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "REALITY CCS tolerance probe destination closed during batch wait",
                ));
            }
            Ok(Ok(read_len)) => {
                alert_observer.ingest(&inbound[..read_len]);
                if alert_observer.alert_seen_in_current_observation() {
                    return Ok(true);
                }
            }
            Ok(Err(err)) => return Err(err),
            Err(_) => break,
        }
    }

    Ok(false)
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/ccs_probe_exec.rs"]
mod tests;
