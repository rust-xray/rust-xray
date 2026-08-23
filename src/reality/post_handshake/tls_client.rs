//! rustls TLS 1.3 client configuration for proactive REALITY post-handshake probes.
//!
//! Uses the project's existing rustls stack (audit Stage 5B). ClientHello fingerprint parity
//! with upstream uTLS (`HelloGolang` / `HelloChrome`) is **partial** — rustls emits its own
//! default ClientHello; this stage targets post-handshake record-length detection only.

use std::sync::{Arc, OnceLock};

use rustls::client::ClientConnection;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use rustls::{ClientConfig, Error as RustlsError};

use super::alpn::RealityAlpnProfile;

static CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();

/// Ensures the rustls ring crypto provider is installed (required for rustls 0.23).
pub fn ensure_rustls_crypto_provider() {
    CRYPTO_PROVIDER.get_or_init(|| {
        if CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("install rustls ring crypto provider");
        }
    });
}

/// Builds a TLS 1.3 client config with Mozilla/system root verification.
///
/// Verification uses native OS roots when available, with Mozilla `webpki-roots` as fallback.
/// This matches upstream intent (normal certificate verification, not disabled).
pub fn build_post_handshake_probe_client_config(
    alpn_profile: RealityAlpnProfile,
) -> Result<Arc<ClientConfig>, RustlsError> {
    ensure_rustls_crypto_provider();

    let mut root_store = RootCertStore::empty();
    let mut native_loaded = false;
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        if root_store.add(cert).is_ok() {
            native_loaded = true;
        }
    }
    if !native_loaded {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if let Some(protocols) = alpn_profile.probe_next_protocols() {
        config.alpn_protocols = protocols
            .into_iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
    }

    Ok(Arc::new(config))
}

pub fn build_post_handshake_probe_connection(
    config: Arc<ClientConfig>,
    server_name: &str,
) -> Result<ClientConnection, RustlsError> {
    let name = ServerName::try_from(server_name.to_string()).map_err(|_| {
        RustlsError::General(format!(
            "invalid REALITY post-handshake probe SNI: {server_name}"
        ))
    })?;
    ClientConnection::new(config, name)
}

#[cfg(test)]
pub(crate) fn build_post_handshake_probe_client_config_with_roots(
    alpn_profile: RealityAlpnProfile,
    roots: RootCertStore,
) -> Result<Arc<ClientConfig>, RustlsError> {
    ensure_rustls_crypto_provider();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if let Some(protocols) = alpn_profile.probe_next_protocols() {
        config.alpn_protocols = protocols
            .into_iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
    }
    Ok(Arc::new(config))
}
