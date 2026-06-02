use std::time::{SystemTime, UNIX_EPOCH};

use tracing::debug;

use crate::protocol::enums::ProtocolVersion;
use crate::protocol::structs::ClientHelloPayload;

use super::auth::{derive_reality_auth_key, extract_x25519_keyshare, RealityAuthResult};
use super::session::{
    open_reality_session_id, validate_reality_client_auth, RealityClientAuth,
    RealitySessionOpenResult, RealityValidationConfig,
};
use super::sni::{extract_sni_hostname, server_name_allowed};

#[derive(Debug)]
pub struct RealityAccepted {
    pub auth: RealityAuthResult,
    pub client: RealityClientAuth,
    pub sni: Option<String>,
}

#[derive(Debug)]
pub enum RealityDecision {
    Accepted(RealityAccepted),
    Fallback,
}

pub struct RealityInspectConfig<'a> {
    pub private_key: &'a str,
    pub server_names: &'a [String],
    pub short_ids: &'a [Vec<u8>],
    pub max_time_diff_ms: u64,
    pub min_client_ver: Option<&'a str>,
    pub max_client_ver: Option<&'a str>,
    /// When set, overrides wall-clock time for maxTimeDiff validation (tests only).
    pub now_unix_ms: Option<u64>,
}

fn log_client_hello_diagnostics(hello: &ClientHelloPayload) {
    match hello.versions_extension() {
        Some(versions) if versions.contains(&ProtocolVersion::TLSv1_3) => {
            debug!("TLS 1.3 supported in supported_versions");
        }
        Some(_) => debug!("TLS 1.3 unsupported in supported_versions"),
        None => debug!("supported_versions extension missing"),
    }

    match extract_x25519_keyshare(hello) {
        Some(_) => debug!("X25519 keyshare found"),
        None => debug!("X25519 keyshare missing or invalid length"),
    }
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub fn inspect_reality_client_hello(
    hello: &ClientHelloPayload,
    raw_client_hello_message: &[u8],
    cfg: RealityInspectConfig<'_>,
) -> std::io::Result<RealityDecision> {
    let sni = match extract_sni_hostname(hello) {
        Some(sni) => sni,
        None => {
            debug!("REALITY fallback: SNI missing");
            return Ok(RealityDecision::Fallback);
        }
    };

    if !server_name_allowed(&sni, cfg.server_names) {
        debug!(%sni, "REALITY fallback: SNI not allowed");
        return Ok(RealityDecision::Fallback);
    }

    debug!(%sni, "REALITY SNI allowed");

    log_client_hello_diagnostics(hello);

    let Some(auth) = derive_reality_auth_key(hello, cfg.private_key)? else {
        return Ok(RealityDecision::Fallback);
    };

    match open_reality_session_id(hello, raw_client_hello_message, &auth.auth_key)? {
        RealitySessionOpenResult::Opened(client_auth) => {
            debug!(
                client_version = ?client_auth.client_version,
                unix_time = client_auth.unix_time,
                "REALITY session_id open ok"
            );

            let now_unix_ms = cfg.now_unix_ms.unwrap_or_else(current_unix_ms);

            let policy_ok = validate_reality_client_auth(
                &client_auth,
                RealityValidationConfig {
                    short_ids: cfg.short_ids,
                    max_time_diff_ms: cfg.max_time_diff_ms,
                    min_client_ver: cfg.min_client_ver,
                    max_client_ver: cfg.max_client_ver,
                },
                now_unix_ms,
            )?;

            if !policy_ok {
                debug!("REALITY policy validation failed");
                return Ok(RealityDecision::Fallback);
            }

            Ok(RealityDecision::Accepted(RealityAccepted {
                auth,
                client: client_auth,
                sni: Some(sni),
            }))
        }
        RealitySessionOpenResult::AuthFailed => {
            debug!("REALITY session_id auth failed");
            Ok(RealityDecision::Fallback)
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/reality/decision.rs"]
mod tests;
