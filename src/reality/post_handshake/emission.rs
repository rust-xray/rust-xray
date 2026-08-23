//! Production emission of cached post-handshake camouflage TLS records (Stage 5B).

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::protocol::structs::ClientHelloPayload;
use crate::reality::post_handshake_probe::post_handshake_probe_cache;
use crate::reality::tls13::Tls13CipherSuite;
use crate::reality::tls13::Tls13RecordEncryptor;

use super::alpn::RealityAlpnProfile;
#[cfg(test)]
use super::cache::PostHandshakeProbeCache;
use super::cache::PostHandshakeProbeKey;
use super::tolerance::UselessRecordTolerance;
use super::validation::is_valid_post_handshake_wire_length;
use crate::reality::post_handshake_probe::ccs_tolerance_probe_cache;

/// Bounded wait for proactive detector results (upstream polling ~5s).
pub const POST_HANDSHAKE_CACHE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds the typed probe cache key from accepted-path connection metadata.
pub fn post_handshake_probe_key(
    dest_addr: &str,
    server_name: &str,
    client_hello: &ClientHelloPayload,
) -> PostHandshakeProbeKey {
    PostHandshakeProbeKey {
        dest_addr: dest_addr.to_string(),
        server_name: server_name.to_string(),
        alpn_profile: RealityAlpnProfile::classify_client_hello(client_hello),
    }
}

/// Waits for cached CCS tolerance, returning [`UselessRecordTolerance::DEFAULT`] on timeout/absence.
///
/// **Upstream timing note:** Xray REALITY loads probed `MaxUselessRecords` after verified client
/// Finished (post-handshake camouflage polling). Rust resolves tolerance with the same bounded wait
/// immediately before reading client Finished so detected target parity applies during
/// `readClientFinished` when the cache is ready — wire-visible behavior differs only when probe
/// completes before the client flight and returns a non-default tier.
pub async fn resolve_ccs_tolerance(key: &PostHandshakeProbeKey) -> UselessRecordTolerance {
    ccs_tolerance_probe_cache()
        .wait_for_ready_tolerance(key, POST_HANDSHAKE_CACHE_WAIT_TIMEOUT)
        .await
}

/// Waits for cached post-handshake wire lengths, returning an empty list on timeout or absence.
pub async fn resolve_post_handshake_wire_lengths(key: &PostHandshakeProbeKey) -> Vec<usize> {
    post_handshake_probe_cache()
        .wait_for_ready_wire_lengths(key, POST_HANDSHAKE_CACHE_WAIT_TIMEOUT)
        .await
}

/// Emits Stage 5B camouflage ApplicationData records after verified client Finished.
///
/// Uses the current server application traffic encryptor and advances its sequence once per record.
/// Does not modify the handshake transcript.
pub async fn emit_post_handshake_camouflage_records<S>(
    stream: &mut S,
    suite: Tls13CipherSuite,
    encryptor: &mut Tls13RecordEncryptor,
    wire_lengths: &[usize],
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if wire_lengths.is_empty() {
        return Ok(());
    }

    let mut emitted = Vec::with_capacity(wire_lengths.len());
    for &desired_wire_len in wire_lengths {
        if !is_valid_post_handshake_wire_length(desired_wire_len) {
            debug!(
                desired_wire_len,
                cipher_suite = suite.name,
                "skipping invalid cached post-handshake record wire length"
            );
            continue;
        }

        match encryptor.encrypt_camouflage_position6_record_with_desired_wire_len(desired_wire_len)
        {
            Ok(record) => {
                stream.write_all(&record).await?;
                emitted.push(record.len());
            }
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                debug!(
                    desired_wire_len,
                    cipher_suite = suite.name,
                    error = %err,
                    "skipping cached post-handshake record length rejected by encryptor"
                );
            }
            Err(err) => return Err(err),
        }
    }

    if !emitted.is_empty() {
        stream.flush().await?;
        debug!(
            record_count = emitted.len(),
            record_lengths = ?emitted,
            next_application_sequence = encryptor.sequence,
            "emitted cached post-handshake camouflage TLS records"
        );
    }

    Ok(())
}

#[cfg(test)]
pub(crate) async fn resolve_post_handshake_wire_lengths_from_cache(
    cache: &PostHandshakeProbeCache,
    key: &PostHandshakeProbeKey,
) -> Vec<usize> {
    cache
        .wait_for_ready_wire_lengths(key, POST_HANDSHAKE_CACHE_WAIT_TIMEOUT)
        .await
}

#[cfg(test)]
pub(crate) async fn resolve_ccs_tolerance_from_cache(
    cache: &super::ccs_cache::CcsToleranceProbeCache,
    key: &PostHandshakeProbeKey,
) -> UselessRecordTolerance {
    cache
        .wait_for_ready_tolerance(key, POST_HANDSHAKE_CACHE_WAIT_TIMEOUT)
        .await
}
