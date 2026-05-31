//! Inbound transport adapters between REALITY application streams and VLESS.

mod raw;
mod xhttp;

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

pub use crate::config::normalized::XHttpRuntimeConfig;
pub use crate::xhttp::matching::{
    host_matches, method_matches_packet_up_download, method_matches_packet_up_upload,
    method_matches_stream_one, path_matches, query_keys, request_path_component,
    validate_packet_up_request, validate_xhttp_stream_one_request, xhttp_match_reject_reason_label,
    XHttpMatchRejectReason, XHttpMatchSettings, XHttpRequestDescriptor,
};
pub use crate::xhttp::mode::{
    configured_xhttp_mode, configured_xhttp_mode_label, effective_xhttp_mode_is_supported,
    effective_xhttp_mode_label, effective_xhttp_mode_unsupported_reason, parse_xhttp_mode,
    resolve_xhttp_mode, transport_security_label, EffectiveXHttpMode, TransportSecurity,
    XHttpError, XHttpMode,
};

use crate::config::{TransportNetwork, XHttpSettings};
use crate::mux::MuxSessionTrace;
use crate::reality::tls13::RealityTls13ApplicationStream;
use crate::stats::StatsState;
use crate::vless::VlessUserManager;

pub use raw::run_raw_transport;
pub use xhttp::run_xhttp_transport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedTransport {
    RawTcp,
    XHttp(XHttpRuntimeConfig),
}

impl AcceptedTransport {
    pub fn from_reality_runtime(
        network: &TransportNetwork,
        xhttp_settings: Option<&XHttpSettings>,
    ) -> io::Result<Self> {
        match network {
            TransportNetwork::RawTcp => Ok(Self::RawTcp),
            TransportNetwork::XHttp => {
                let settings = xhttp_settings.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "network=xhttp is missing xhttp settings runtime",
                    )
                })?;
                Ok(Self::XHttp(XHttpRuntimeConfig::from_settings(settings)))
            }
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::RawTcp => "raw",
            Self::XHttp(_) => "xhttp",
        }
    }
}

/// VLESS inbound handler context shared by all transport adapters.
#[derive(Clone)]
pub struct VlessHandler {
    users: Arc<VlessUserManager>,
    stats: Option<StatsState>,
    mux_trace: Option<MuxSessionTrace>,
}

impl VlessHandler {
    pub fn new(
        users: Arc<VlessUserManager>,
        stats: Option<StatsState>,
        mux_trace: Option<MuxSessionTrace>,
    ) -> Self {
        Self {
            users,
            stats,
            mux_trace,
        }
    }

    pub fn users(&self) -> &VlessUserManager {
        &self.users
    }

    pub fn users_arc(&self) -> Arc<VlessUserManager> {
        Arc::clone(&self.users)
    }

    pub fn stats(&self) -> Option<&StatsState> {
        self.stats.as_ref()
    }

    pub fn mux_trace(&self) -> Option<MuxSessionTrace> {
        self.mux_trace
    }

    pub fn inbound_tag(&self) -> &str {
        self.users.inbound_tag()
    }

    pub fn user_count(&self) -> usize {
        self.users.user_count()
    }
}

/// Dispatch a REALITY-decrypted application stream to the selected inbound transport.
pub async fn run_inbound_transport<S>(
    transport: AcceptedTransport,
    stream: RealityTls13ApplicationStream<S>,
    vless_handler: &VlessHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(
        kind = transport.kind_label(),
        inbound_tag = vless_handler.inbound_tag(),
        "transport selected"
    );

    match transport {
        AcceptedTransport::RawTcp => run_raw_transport(stream, vless_handler).await,
        AcceptedTransport::XHttp(config) => {
            run_xhttp_transport(stream, config, vless_handler).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_transport_from_reality_runtime_raw_tcp() {
        let transport =
            AcceptedTransport::from_reality_runtime(&TransportNetwork::RawTcp, None).unwrap();
        assert_eq!(transport, AcceptedTransport::RawTcp);
    }

    #[test]
    fn accepted_transport_from_reality_runtime_xhttp() {
        let settings = XHttpSettings {
            path: "/xhttp".to_string(),
            mode: Some("stream-one".to_string()),
            ..XHttpSettings::default()
        };
        let transport =
            AcceptedTransport::from_reality_runtime(&TransportNetwork::XHttp, Some(&settings))
                .unwrap();
        assert_eq!(
            transport,
            AcceptedTransport::XHttp(XHttpRuntimeConfig {
                path: "/xhttp".to_string(),
                host: None,
                mode: "stream-one".to_string(),
            })
        );
    }

    #[test]
    fn dispatch_kind_labels() {
        assert_eq!(AcceptedTransport::RawTcp.kind_label(), "raw");
        assert_eq!(
            AcceptedTransport::XHttp(XHttpRuntimeConfig {
                path: "/".to_string(),
                host: None,
                mode: "auto".to_string(),
            })
            .kind_label(),
            "xhttp"
        );
    }

    #[test]
    fn raw_transport_entrypoint_is_wired() {
        let raw = AcceptedTransport::RawTcp;
        assert_eq!(raw.kind_label(), "raw");
    }
}
