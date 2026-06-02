use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use tracing::debug;

use crate::protocol::structs::ClientHelloPayload;

use super::version::{parse_reality_client_version, version_ge, version_le};

#[derive(Clone, PartialEq, Eq)]
pub struct RealityClientAuth {
    pub client_version: [u8; 4],
    pub unix_time: u32,
    pub short_id: [u8; 8],
}

impl std::fmt::Debug for RealityClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityClientAuth")
            .field("client_version", &self.client_version)
            .field("unix_time", &self.unix_time)
            .field(
                "short_id",
                &format!("<{} bytes>", short_id_prefix_len(&self.short_id)),
            )
            .finish()
    }
}

pub fn short_id_prefix_len(short_id: &[u8; 8]) -> usize {
    short_id
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|index| index + 1)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RealitySessionOpenResult {
    Opened(RealityClientAuth),
    AuthFailed,
}

const REALITY_SESSION_ID_OFFSET: usize = 39;
pub(crate) const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_PLAINTEXT_LEN: usize = 16;
const REALITY_NONCE_LEN: usize = 12;

pub(crate) fn open_reality_session_id(
    hello: &ClientHelloPayload,
    raw_client_hello_message: &[u8],
    auth_key: &[u8; 32],
) -> std::io::Result<RealitySessionOpenResult> {
    let session_id = hello.session_id.as_bytes();

    if session_id.len() != REALITY_SESSION_ID_LEN {
        debug!(
            len = session_id.len(),
            "REALITY session_id open skipped: session_id must be 32 bytes"
        );
        return Ok(RealitySessionOpenResult::AuthFailed);
    }

    if raw_client_hello_message.len() < REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello handshake message too short for REALITY session_id AAD",
        ));
    }

    let mut aad = raw_client_hello_message.to_vec();
    aad[REALITY_SESSION_ID_OFFSET..REALITY_SESSION_ID_OFFSET + REALITY_SESSION_ID_LEN].fill(0);

    let cipher = Aes256Gcm::new_from_slice(auth_key).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("REALITY AES-GCM key invalid: {e}"),
        )
    })?;
    let nonce = Nonce::from_slice(&hello.random.0[20..20 + REALITY_NONCE_LEN]);

    let plaintext = match cipher.decrypt(
        nonce,
        Payload {
            msg: session_id,
            aad: &aad,
        },
    ) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            debug!("REALITY session_id AEAD open failed");
            return Ok(RealitySessionOpenResult::AuthFailed);
        }
    };

    if plaintext.len() != REALITY_PLAINTEXT_LEN {
        debug!(
            len = plaintext.len(),
            "REALITY session_id plaintext has unexpected length"
        );
        return Ok(RealitySessionOpenResult::AuthFailed);
    }

    let mut client_version = [0u8; 4];
    client_version.copy_from_slice(&plaintext[0..4]);

    let unix_time = u32::from_be_bytes(plaintext[4..8].try_into().expect("4-byte timestamp"));

    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plaintext[8..16]);

    Ok(RealitySessionOpenResult::Opened(RealityClientAuth {
        client_version,
        unix_time,
        short_id,
    }))
}

pub struct RealityValidationConfig<'a> {
    pub short_ids: &'a [Vec<u8>],
    pub max_time_diff_ms: u64,
    pub min_client_ver: Option<&'a str>,
    pub max_client_ver: Option<&'a str>,
}

fn short_id_matches(decrypted: &[u8; 8], configured: &[u8]) -> bool {
    configured.len() <= decrypted.len() && &decrypted[..configured.len()] == configured
}

/// Validates REALITY client auth metadata after AEAD session_id decrypt.
///
/// Checks `shortId` prefix match, optional client version bounds, and optional
/// `maxTimeDiff` window.
/// Returns `Ok(true)` when all configured checks pass, `Ok(false)` otherwise.
pub fn validate_reality_client_auth(
    auth: &RealityClientAuth,
    cfg: RealityValidationConfig<'_>,
    now_unix_ms: u64,
) -> std::io::Result<bool> {
    if cfg.short_ids.is_empty() {
        debug!("shortId validation failed: no configured shortIds");
        return Ok(false);
    }

    if !cfg
        .short_ids
        .iter()
        .any(|configured| short_id_matches(&auth.short_id, configured))
    {
        debug!("shortId validation failed");
        return Ok(false);
    }

    if let Some(min) = cfg.min_client_ver {
        let min = parse_reality_client_version(min)?;
        if !version_ge(auth.client_version, min) {
            debug!(
                client_version = ?auth.client_version,
                min_client_ver = ?min,
                "client version below min"
            );
            return Ok(false);
        }
    }

    if let Some(max) = cfg.max_client_ver {
        let max = parse_reality_client_version(max)?;
        if !version_le(auth.client_version, max) {
            debug!(
                client_version = ?auth.client_version,
                max_client_ver = ?max,
                "client version above max"
            );
            return Ok(false);
        }
    }

    debug!(
        client_version = ?auth.client_version,
        "client version ok"
    );

    if cfg.max_time_diff_ms == 0 {
        debug!("REALITY policy validation ok");
        return Ok(true);
    }

    let auth_unix_ms = u64::from(auth.unix_time).saturating_mul(1000);
    let diff_ms = now_unix_ms.abs_diff(auth_unix_ms);

    if diff_ms > cfg.max_time_diff_ms {
        debug!(
            diff_ms,
            max_time_diff_ms = cfg.max_time_diff_ms,
            "maxTimeDiff validation failed"
        );
        return Ok(false);
    }

    debug!("REALITY policy validation ok");
    Ok(true)
}

#[cfg(test)]
#[path = "../../tests/unit/reality/session.rs"]
mod tests;
