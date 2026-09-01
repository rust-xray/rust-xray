//! Inbound transport adapters between REALITY application streams and VLESS.

pub mod raw;
pub mod xhttp;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

pub use crate::config::normalized::XHttpRuntimeConfig;
pub use xhttp::matching::{
    host_matches, method_matches_packet_up_download, method_matches_packet_up_upload,
    method_matches_stream_one, path_matches, query_keys, request_path_component,
    validate_packet_up_request, validate_xhttp_stream_one_request, xhttp_match_reject_reason_label,
    XHttpMatchRejectReason, XHttpMatchSettings, XHttpRequestDescriptor,
};
pub use xhttp::mode::{
    configured_xhttp_mode, configured_xhttp_mode_label, effective_xhttp_mode_is_supported,
    effective_xhttp_mode_label, effective_xhttp_mode_unsupported_reason, parse_xhttp_mode,
    resolve_xhttp_mode, transport_security_label, EffectiveXHttpMode, TransportSecurity,
    XHttpError, XHttpMode,
};

use crate::config::{InboundTransportConfig, TransportNetwork, XHttpSettings};
use crate::mux::MuxSessionTrace;
use crate::reality::tls13::RealityTls13ApplicationStream;
use crate::routing::{RouteSocketMeta, RuntimeRouter};
use crate::runtime::VlessInboundAuthContext;
use crate::stats::StatsState;
use crate::vless::encryption::SharedVlessEncryptionServer;
use crate::vless::VlessUserManager;

pub use raw::run_raw_transport;
pub use xhttp::run_xhttp_transport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedTransport {
    RawTcp,
    XHttp(XHttpRuntimeConfig),
}

impl AcceptedTransport {
    pub fn from_inbound_transport_config(transport: &InboundTransportConfig) -> io::Result<Self> {
        match transport {
            InboundTransportConfig::RawTcp => Ok(Self::RawTcp),
            InboundTransportConfig::XHttp(config) => Ok(Self::XHttp(config.clone())),
        }
    }

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
    auth: VlessInboundAuthContext,
    mux_trace: Option<MuxSessionTrace>,
    socket_meta: RouteSocketMeta,
    router: Option<Arc<RuntimeRouter>>,
    encryption_server: Option<SharedVlessEncryptionServer>,
}

impl VlessHandler {
    pub fn new_with_auth_context(
        auth: VlessInboundAuthContext,
        mux_trace: Option<MuxSessionTrace>,
        socket_meta: RouteSocketMeta,
        router: Option<Arc<RuntimeRouter>>,
        encryption_server: Option<SharedVlessEncryptionServer>,
    ) -> Self {
        Self {
            auth,
            mux_trace,
            socket_meta,
            router,
            encryption_server,
        }
    }

    pub fn new(
        users: Arc<VlessUserManager>,
        stats: Option<StatsState>,
        mux_trace: Option<MuxSessionTrace>,
        source_ip: Option<IpAddr>,
        router: Option<Arc<RuntimeRouter>>,
    ) -> Self {
        Self::new_with_socket_meta(
            users,
            stats,
            mux_trace,
            RouteSocketMeta {
                source_ip,
                ..Default::default()
            },
            router,
        )
    }

    pub fn new_with_socket_meta(
        users: Arc<VlessUserManager>,
        stats: Option<StatsState>,
        mux_trace: Option<MuxSessionTrace>,
        socket_meta: RouteSocketMeta,
        router: Option<Arc<RuntimeRouter>>,
    ) -> Self {
        Self::new_with_auth_context(
            VlessInboundAuthContext::from_single_manager(users, stats.map(Arc::new)),
            mux_trace,
            socket_meta,
            router,
            None,
        )
    }

    pub fn auth_context(&self) -> &VlessInboundAuthContext {
        &self.auth
    }

    pub fn users(&self) -> Option<Arc<VlessUserManager>> {
        self.auth
            .auth_set()
            .tags()
            .first()
            .and_then(|tag| self.auth.auth_set().get_manager(tag))
    }

    pub fn users_arc(&self) -> Option<Arc<VlessUserManager>> {
        self.users()
    }

    pub fn stats(&self) -> Option<Arc<StatsState>> {
        self.auth
            .auth_set()
            .tags()
            .first()
            .and_then(|tag| self.auth.stats_for(tag))
    }

    pub fn mux_trace(&self) -> Option<MuxSessionTrace> {
        self.mux_trace
    }

    pub fn source_ip(&self) -> Option<IpAddr> {
        self.socket_meta.source_ip
    }

    pub fn socket_meta(&self) -> &RouteSocketMeta {
        &self.socket_meta
    }

    pub fn router(&self) -> Option<&Arc<RuntimeRouter>> {
        self.router.as_ref()
    }

    pub fn inbound_tag(&self) -> String {
        self.auth
            .auth_set()
            .tags()
            .into_iter()
            .next()
            .unwrap_or_else(|| "reality-in".to_string())
    }

    pub fn encryption_server(&self) -> Option<&SharedVlessEncryptionServer> {
        self.encryption_server.as_ref()
    }

    pub fn user_count(&self) -> usize {
        self.auth.auth_set().tags().iter().fold(0, |count, tag| {
            count
                + self
                    .auth
                    .auth_set()
                    .get_manager(tag)
                    .map(|manager| manager.user_count())
                    .unwrap_or(0)
        })
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
#[path = "../../tests/unit/transport/mod.rs"]
mod tests;
