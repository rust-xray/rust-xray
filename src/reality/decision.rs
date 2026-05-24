use tracing::{debug, warn};

use crate::protocol::enums::ProtocolVersion;
use crate::protocol::structs::{ClientHelloPayload, ServerNamePayload};

use super::auth::{derive_reality_auth_key, extract_x25519_keyshare, RealityAuthResult};
use super::session::open_reality_session_id;

pub enum RealityDecision {
    Accepted(RealityAuthResult),
    Fallback,
}

fn log_client_hello_diagnostics(hello: &ClientHelloPayload) {
    match hello.sni_extension() {
        Some(names) => {
            let hostnames = names
                .iter()
                .filter_map(|name| match &name.payload {
                    ServerNamePayload::HostName(dns) => Some(dns.as_ref().to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if hostnames.is_empty() {
                debug!(
                    count = names.len(),
                    "SNI extension found without DNS hostnames"
                );
            } else {
                debug!(?hostnames, "SNI extension found");
            }
        }
        None => debug!("SNI extension missing"),
    }

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

pub fn inspect_reality_client_hello(
    hello: &ClientHelloPayload,
    raw_client_hello_payload: &[u8],
    server_private_key_b64: &str,
) -> std::io::Result<RealityDecision> {
    log_client_hello_diagnostics(hello);

    let Some(auth) = derive_reality_auth_key(hello, server_private_key_b64)? else {
        return Ok(RealityDecision::Fallback);
    };

    match open_reality_session_id(hello, raw_client_hello_payload, &auth.auth_key)? {
        Some(_client_auth) => {
            debug!("REALITY session_id open ok");
            Ok(RealityDecision::Accepted(auth))
        }
        None => {
            warn!("REALITY session_id open failed or not implemented");
            Ok(RealityDecision::Fallback)
        }
    }
}
