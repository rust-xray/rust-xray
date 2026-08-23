//! Proactive REALITY post-handshake TLS probe execution.

use std::io::{Error as IoError, ErrorKind};
use std::time::Duration;

use tokio::time::timeout;
use tracing::debug;

use crate::reality::dest_dial::{
    RealityDestDialConfig, RealityDestProxyEndpoints, RealityDestStream,
};

use super::cache::PostHandshakeProbeKey;
use super::parser::{parse_post_handshake_application_record_lengths, PostHandshakeParseError};
use super::tls_client::{
    build_post_handshake_probe_client_config, build_post_handshake_probe_connection,
};

/// Upstream post-handshake capture uses ~5 seconds; mirror that for probe I/O bounds.
pub const POST_HANDSHAKE_PROBE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const POST_HANDSHAKE_PROBE_CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum raw post-handshake bytes retained while draining the target (prevents unbounded alloc).
const POST_HANDSHAKE_CAPTURE_READ_CAP: usize = 256 * 1024;

const POST_HANDSHAKE_READ_CHUNK: usize = 4096;

/// Runs a full proactive TLS 1.3 probe: dial, handshake, capture post-handshake wire records, parse.
pub async fn execute_post_handshake_probe(
    dial_config: &RealityDestDialConfig,
    key: &PostHandshakeProbeKey,
) -> Result<Vec<usize>, IoError> {
    let client_config =
        build_post_handshake_probe_client_config(key.alpn_profile).map_err(|err| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("REALITY post-handshake probe TLS config failed: {err}"),
            )
        })?;
    execute_post_handshake_probe_with_client_config(dial_config, key, client_config).await
}

/// Test hook: run probe with an explicit root store (local mock CA).
#[cfg(test)]
pub(crate) async fn execute_post_handshake_probe_with_roots(
    dial_config: &RealityDestDialConfig,
    key: &PostHandshakeProbeKey,
    roots: rustls::RootCertStore,
) -> Result<Vec<usize>, IoError> {
    let client_config = super::tls_client::build_post_handshake_probe_client_config_with_roots(
        key.alpn_profile,
        roots,
    )
    .map_err(|err| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("REALITY post-handshake probe TLS config failed: {err}"),
        )
    })?;
    execute_post_handshake_probe_with_client_config(dial_config, key, client_config).await
}

async fn execute_post_handshake_probe_with_client_config(
    dial_config: &RealityDestDialConfig,
    key: &PostHandshakeProbeKey,
    client_config: std::sync::Arc<rustls::ClientConfig>,
) -> Result<Vec<usize>, IoError> {
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
        "REALITY post-handshake probe started"
    );

    let mut stream =
        crate::reality::dest_dial::dial_reality_dest(dial_config, proxy_endpoints).await?;

    let mut connection = build_post_handshake_probe_connection(client_config, &key.server_name)
        .map_err(|err| {
            IoError::new(
                ErrorKind::InvalidData,
                format!("REALITY post-handshake probe TLS connection failed: {err}"),
            )
        })?;

    timeout(
        POST_HANDSHAKE_PROBE_HANDSHAKE_TIMEOUT,
        drive_rustls_client_handshake(&mut connection, &mut stream),
    )
    .await
    .map_err(|_| {
        IoError::new(
            ErrorKind::TimedOut,
            format!(
                "REALITY post-handshake probe TLS handshake timed out after {:?}",
                POST_HANDSHAKE_PROBE_HANDSHAKE_TIMEOUT
            ),
        )
    })??;

    // rustls does not emit TLS 1.2-style CCS on the client path. Upstream uTLS probes may use
    // CCS as a capture boundary; here we start raw capture immediately after the rustls client
    // handshake completes (all subsequent wire bytes are post-handshake TLS records).
    let captured = timeout(
        POST_HANDSHAKE_PROBE_CAPTURE_TIMEOUT,
        capture_post_handshake_wire_bytes(&mut stream),
    )
    .await
    .unwrap_or_else(|_| Ok(Vec::new()))
    .unwrap_or_default();

    let _ = stream.shutdown().await;

    let lengths = probe_lengths_from_capture(&captured);
    debug!(
        dest = %key.dest_addr,
        server_name = %key.server_name,
        alpn_profile = ?key.alpn_profile,
        record_count = lengths.len(),
        record_lengths = ?lengths,
        "REALITY post-handshake probe completed"
    );
    Ok(lengths)
}

/// Parses captured wire bytes into record lengths, tolerating trailing partial records on timeout.
pub fn probe_lengths_from_capture(captured: &[u8]) -> Vec<usize> {
    if captured.is_empty() {
        return Vec::new();
    }

    match parse_post_handshake_application_record_lengths(captured) {
        Ok(lengths) => lengths,
        Err(PostHandshakeParseError::TrailingIncompleteRecord { parsed_lengths, .. }) => {
            parsed_lengths
        }
        Err(PostHandshakeParseError::TruncatedPayload { offset, .. }) if offset > 0 => {
            parse_post_handshake_application_record_lengths(&captured[..offset]).unwrap_or_default()
        }
        Err(_) => Vec::new(),
    }
}

async fn drive_rustls_client_handshake(
    connection: &mut rustls::ClientConnection,
    stream: &mut RealityDestStream,
) -> Result<(), IoError> {
    let mut inbound = vec![0u8; POST_HANDSHAKE_READ_CHUNK];
    let mut outbound = Vec::new();

    loop {
        while connection.wants_write() {
            outbound.clear();
            let written = connection.write_tls(&mut outbound)?;
            if written == 0 {
                break;
            }
            stream.write_all(&outbound).await?;
        }

        if !connection.is_handshaking() {
            break;
        }

        if connection.wants_read() {
            let read_len = stream.read(&mut inbound).await?;
            if read_len == 0 {
                return Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "REALITY post-handshake probe destination closed during TLS handshake",
                ));
            }
            let mut cursor = &inbound[..read_len];
            while !cursor.is_empty() {
                connection.read_tls(&mut cursor)?;
            }
            connection
                .process_new_packets()
                .map_err(rustls_error_to_io)?;
        }
    }

    Ok(())
}

/// Drains readable target bytes after the TLS handshake without decrypting application data.
///
/// Matches upstream `io.Copy(discard)` intent: keep reading so the wire wrapper observes
/// post-handshake TLS records, without sending HTTP requests or consuming plaintext logically.
async fn capture_post_handshake_wire_bytes(
    stream: &mut RealityDestStream,
) -> Result<Vec<u8>, IoError> {
    let mut captured = Vec::new();
    let mut scratch = vec![0u8; POST_HANDSHAKE_READ_CHUNK];

    loop {
        if captured.len() >= POST_HANDSHAKE_CAPTURE_READ_CAP {
            break;
        }

        let remaining = POST_HANDSHAKE_CAPTURE_READ_CAP - captured.len();
        scratch.resize(remaining.min(POST_HANDSHAKE_READ_CHUNK), 0);

        let read_len = stream.read(&mut scratch).await?;
        if read_len == 0 {
            break;
        }
        captured.extend_from_slice(&scratch[..read_len]);
    }

    Ok(captured)
}

fn rustls_error_to_io(err: rustls::Error) -> IoError {
    IoError::new(
        ErrorKind::InvalidData,
        format!("REALITY post-handshake probe TLS error: {err}"),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/probe.rs"]
mod tests;
