use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::server::{Connected, Router};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::api::diagnostics::DiagnosingTcpIncoming;
pub use crate::config::xray::api_listen::{
    bind_api_listen, bind_api_listener, is_internal_commander_listen, parse_api_grpc_listen_addr,
    parse_api_tcp_listen_addr, ApiListenKind, BoundApiListener,
};
use crate::runtime::{CommanderOutboundListener, InternalCommanderHandle};
use tracing::info;

use crate::api::handler::HandlerServiceImpl;
use crate::api::logger::LoggerServiceImpl;
use crate::api::observatory::ObservatoryServiceImpl;
use crate::api::proto::app::log::command::logger_service_server::LoggerServiceServer;
use crate::api::proto::app::observatory::command::observatory_service_server::ObservatoryServiceServer;
use crate::api::proto::app::proxyman::command::handler_service_server::HandlerServiceServer;
use crate::api::proto::app::router::command::routing_service_server::RoutingServiceServer;
use crate::api::proto::app::stats::command::stats_service_server::StatsServiceServer;
use crate::api::proto::FILE_DESCRIPTOR_SET;
use crate::api::routing::RoutingServiceImpl;
use crate::api::stats::StatsServiceImpl;
use crate::config::{
    extract_api_inbound_tls_material, is_localhost_api_listen,
    is_remnawave_http_unix_config_source, ApiTlsMaterial, XrayConfig,
};
use crate::runtime::HandlerRuntime;
use crate::stats::StatsRegistry;

/// Enabled Xray API gRPC services (from `api.services`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiService {
    Reflection,
    Handler,
    Logger,
    Stats,
    Routing,
    Observatory,
}

/// How the Xray-compatible gRPC API is exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiTransportMode {
    Plaintext,
    Tls {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    },
    Mtls {
        ca_pem: Vec<u8>,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    },
}

/// Resolved API transport with a stable reason label for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTransportSelection {
    pub mode: ApiTransportMode,
    pub reason: &'static str,
}

/// Inputs used to resolve API transport (env, Remnawave config source, API inbound TLS).
#[derive(Debug, Clone, Copy)]
pub struct ApiTransportContext<'a> {
    pub config_source: &'a str,
    pub api_listen: Option<&'a str>,
    pub xray: Option<&'a XrayConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiTransportKind {
    Plaintext,
    Tls,
    Mtls,
}

impl ApiTransportMode {
    pub fn as_log_label(&self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Tls { .. } => "tls",
            Self::Mtls { .. } => "mtls",
        }
    }

    pub fn uses_tls(&self) -> bool {
        !matches!(self, Self::Plaintext)
    }
}

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn parse_transport_env(value: Option<&str>) -> Option<ApiTransportKind> {
    let value = value.map(str::trim).filter(|value| !value.is_empty())?;
    if eq_ignore_ascii_case(value, "plaintext") {
        Some(ApiTransportKind::Plaintext)
    } else if eq_ignore_ascii_case(value, "tls") {
        Some(ApiTransportKind::Tls)
    } else if eq_ignore_ascii_case(value, "mtls") {
        Some(ApiTransportKind::Mtls)
    } else {
        None
    }
}

fn parse_legacy_tls_disabled(value: Option<&str>) -> bool {
    value.map(str::trim).is_some_and(|value| {
        value == "0" || value.eq_ignore_ascii_case("false") || value.eq_ignore_ascii_case("no")
    })
}

fn parse_legacy_tls_enabled(value: Option<&str>) -> bool {
    value.map(str::trim).is_some_and(|value| {
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
}

fn read_pem_file(path: &str, label: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(path).map_err(|err| {
        std::io::Error::new(err.kind(), format!("failed to read {label} {path}: {err}"))
    })
}

fn load_tls_files(
    cert_path: &str,
    key_path: &str,
    ca_path: Option<&str>,
    require_ca: bool,
) -> std::io::Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    let cert_pem = read_pem_file(cert_path, "RUST_XRAY_API_TLS_CERT")?;
    let key_pem = read_pem_file(key_path, "RUST_XRAY_API_TLS_KEY")?;
    let ca_pem = match ca_path {
        Some(path) if !path.trim().is_empty() => Some(read_pem_file(path, "RUST_XRAY_API_TLS_CA")?),
        _ if require_ca => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "RUST_XRAY_API_TRANSPORT=mtls requires RUST_XRAY_API_TLS_CA",
            ));
        }
        _ => None,
    };
    Ok((cert_pem, key_pem, ca_pem))
}

fn validate_tls_identity(cert_pem: &[u8], key_pem: &[u8]) -> std::io::Result<()> {
    let tls = build_server_tls_config(&ApiTransportMode::Tls {
        cert_pem: cert_pem.to_vec(),
        key_pem: key_pem.to_vec(),
    })?;
    Server::builder()
        .tls_config(tls)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok(())
}

fn validate_mtls_identity(ca_pem: &[u8], cert_pem: &[u8], key_pem: &[u8]) -> std::io::Result<()> {
    validate_tls_identity(cert_pem, key_pem)?;
    let tls = build_server_tls_config(&ApiTransportMode::Mtls {
        ca_pem: ca_pem.to_vec(),
        cert_pem: cert_pem.to_vec(),
        key_pem: key_pem.to_vec(),
    })?;
    Server::builder()
        .tls_config(tls)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok(())
}

fn tls_material_from_env(require_ca: bool) -> std::io::Result<Option<ApiTlsMaterial>> {
    let cert_path = std::env::var("RUST_XRAY_API_TLS_CERT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let key_path = std::env::var("RUST_XRAY_API_TLS_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let ca_path = std::env::var("RUST_XRAY_API_TLS_CA")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let (cert_path, key_path) = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => (cert_path, key_path),
        _ => return Ok(None),
    };

    let (cert_pem, key_pem, ca_pem) =
        load_tls_files(&cert_path, &key_path, ca_path.as_deref(), require_ca)?;
    let ca_pem = match (require_ca, ca_pem) {
        (true, Some(ca_pem)) => ca_pem,
        (true, None) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "RUST_XRAY_API_TRANSPORT=mtls requires RUST_XRAY_API_TLS_CA",
            ));
        }
        (false, ca_pem) => ca_pem.unwrap_or_default(),
    };

    Ok(Some(ApiTlsMaterial {
        cert_pem,
        key_pem,
        ca_pem,
        server_name: None,
    }))
}

fn tls_material_from_config(xray: &XrayConfig) -> std::io::Result<Option<ApiTlsMaterial>> {
    extract_api_inbound_tls_material(xray)
}

fn select_transport_kind(context: &ApiTransportContext<'_>) -> (ApiTransportKind, &'static str) {
    if let Some(kind) =
        parse_transport_env(std::env::var("RUST_XRAY_API_TRANSPORT").ok().as_deref())
    {
        return (kind, "env-override");
    }

    if parse_legacy_tls_disabled(std::env::var("RUST_XRAY_API_TLS").ok().as_deref()) {
        return (ApiTransportKind::Plaintext, "env-override");
    }

    if parse_legacy_tls_enabled(std::env::var("RUST_XRAY_API_TLS").ok().as_deref()) {
        return (ApiTransportKind::Tls, "env-override");
    }

    if is_remnawave_http_unix_config_source(context.config_source)
        && context.api_listen.is_some_and(is_localhost_api_listen)
    {
        return (ApiTransportKind::Mtls, "remnawave-http-unix-auto");
    }

    (ApiTransportKind::Plaintext, "xray-default-plaintext")
}

fn material_to_mode(kind: ApiTransportKind, material: ApiTlsMaterial) -> ApiTransportMode {
    match kind {
        ApiTransportKind::Plaintext => ApiTransportMode::Plaintext,
        ApiTransportKind::Tls => ApiTransportMode::Tls {
            cert_pem: material.cert_pem,
            key_pem: material.key_pem,
        },
        ApiTransportKind::Mtls => ApiTransportMode::Mtls {
            ca_pem: material.ca_pem,
            cert_pem: material.cert_pem,
            key_pem: material.key_pem,
        },
    }
}

fn resolve_tls_material(
    kind: ApiTransportKind,
    context: &ApiTransportContext<'_>,
) -> std::io::Result<ApiTransportMode> {
    match kind {
        ApiTransportKind::Plaintext => Ok(ApiTransportMode::Plaintext),
        ApiTransportKind::Tls => {
            if let Some(material) = tls_material_from_env(false)? {
                validate_tls_identity(&material.cert_pem, &material.key_pem)?;
                return Ok(material_to_mode(kind, material));
            }
            if let Some(xray) = context.xray {
                if let Some(material) = tls_material_from_config(xray)? {
                    validate_tls_identity(&material.cert_pem, &material.key_pem)?;
                    return Ok(material_to_mode(kind, material));
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS API transport requires RUST_XRAY_API_TLS_CERT and RUST_XRAY_API_TLS_KEY \
                 or API inbound streamSettings.tlsSettings certificates",
            ))
        }
        ApiTransportKind::Mtls => {
            if let Some(material) = tls_material_from_env(true)? {
                validate_mtls_identity(&material.ca_pem, &material.cert_pem, &material.key_pem)?;
                return Ok(material_to_mode(kind, material));
            }
            if let Some(xray) = context.xray {
                if let Some(material) = tls_material_from_config(xray)? {
                    validate_mtls_identity(
                        &material.ca_pem,
                        &material.cert_pem,
                        &material.key_pem,
                    )?;
                    return Ok(material_to_mode(kind, material));
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Remnawave mTLS API transport requires API inbound streamSettings.tlsSettings \
                 (server cert/key + verify CA) from get-config, or explicit \
                 RUST_XRAY_API_TLS_CA / RUST_XRAY_API_TLS_CERT / RUST_XRAY_API_TLS_KEY. \
                 Remnawave generates these in Node memory and injects them into the Xray config; \
                 auto-generated unrelated CA certs will not be trusted by @remnawave/xtls-sdk",
            ))
        }
    }
}

fn build_server_tls_config(mode: &ApiTransportMode) -> std::io::Result<ServerTlsConfig> {
    match mode {
        ApiTransportMode::Plaintext => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "plaintext API transport does not use TLS",
        )),
        ApiTransportMode::Tls { cert_pem, key_pem } => {
            let identity = Identity::from_pem(cert_pem.clone(), key_pem.clone());
            Ok(ServerTlsConfig::new().identity(identity))
        }
        ApiTransportMode::Mtls {
            ca_pem,
            cert_pem,
            key_pem,
        } => {
            let identity = Identity::from_pem(cert_pem.clone(), key_pem.clone());
            let client_ca = Certificate::from_pem(ca_pem.clone());
            Ok(ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(client_ca))
        }
    }
}

/// Resolve API transport from env + optional Remnawave config context.
pub fn resolve_api_transport_mode(
    context: ApiTransportContext<'_>,
) -> std::io::Result<ApiTransportSelection> {
    let (kind, reason) = select_transport_kind(&context);
    let mode = resolve_tls_material(kind, &context)?;
    Ok(ApiTransportSelection { mode, reason })
}

pub fn log_api_transport_selected(selection: &ApiTransportSelection) {
    let label = match &selection.mode {
        ApiTransportMode::Plaintext => "plaintext",
        ApiTransportMode::Tls { .. } => "tls",
        ApiTransportMode::Mtls { .. } => "mTLS",
    };
    info!(
        api_transport = selection.mode.as_log_label(),
        transport_reason = selection.reason,
        "Xray API transport selected: {label}"
    );
    crate::startup_log::eprintln_bootstrap(format!(
        "Xray API transport selected: {label} reason={}",
        selection.reason
    ));
}

/// Resolve API transport from environment only (no Remnawave config context).
pub fn api_transport_mode_from_env() -> std::io::Result<ApiTransportMode> {
    Ok(resolve_api_transport_mode(ApiTransportContext {
        config_source: "",
        api_listen: None,
        xray: None,
    })?
    .mode)
}

fn api_service_canonical_path(service: ApiService) -> &'static str {
    match service {
        ApiService::Reflection => "grpc.reflection.v1.ServerReflection",
        ApiService::Handler => "xray.app.proxyman.command.HandlerService",
        ApiService::Logger => "xray.app.log.command.LoggerService",
        ApiService::Stats => "xray.app.stats.command.StatsService",
        ApiService::Routing => "xray.app.router.command.RoutingService",
        ApiService::Observatory => "xray.core.app.observatory.command.ObservatoryService",
    }
}

fn format_mounted_service_paths(enabled: &[ApiService]) -> String {
    enabled
        .iter()
        .map(|service| api_service_canonical_path(*service))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn log_api_listener_ready(
    configured_listen: &str,
    bound_addr: SocketAddr,
    configured_services: &[String],
    enabled: &[ApiService],
    mode: &ApiTransportMode,
) {
    let configured = configured_listen.trim();
    let transport_label = match mode {
        ApiTransportMode::Plaintext => "plaintext",
        ApiTransportMode::Tls { .. } => "TLS",
        ApiTransportMode::Mtls { .. } => "mTLS",
    };
    let mounted = format_mounted_service_paths(enabled);
    info!(api_listen = %configured, "Xray API config listen");
    info!(
        api_bind_addr = %bound_addr,
        api_transport = mode.as_log_label(),
        api_mounted_services = %mounted,
        "Xray API listening on {bound_addr} {transport_label}"
    );
    info!(
        api_services = ?configured_services,
        api_mounted_services = %mounted,
        "Xray API enabled services"
    );
    crate::startup_log::eprintln_bootstrap(format!(
        "API owns {bound_addr} for {transport_label} gRPC ({mounted})"
    ));
}

/// Parse `api.services` into mountable services (unknown entries are ignored).
pub fn parse_enabled_services(services: &[String]) -> std::io::Result<Vec<ApiService>> {
    let mut enabled = Vec::with_capacity(services.len());
    for service in services {
        let parsed = if eq_ignore_ascii_case(service, "ReflectionService") {
            Some(ApiService::Reflection)
        } else if eq_ignore_ascii_case(service, "HandlerService") {
            Some(ApiService::Handler)
        } else if eq_ignore_ascii_case(service, "LoggerService") {
            Some(ApiService::Logger)
        } else if eq_ignore_ascii_case(service, "StatsService") {
            Some(ApiService::Stats)
        } else if eq_ignore_ascii_case(service, "RoutingService") {
            Some(ApiService::Routing)
        } else if eq_ignore_ascii_case(service, "ObservatoryService") {
            Some(ApiService::Observatory)
        } else {
            None
        };
        if let Some(parsed) = parsed {
            enabled.push(parsed);
        }
    }
    Ok(enabled)
}

fn validate_duplicate_api_services(services: &[ApiService]) -> std::io::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for service in services {
        if !seen.insert(*service) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("duplicate API service registration: {service:?}"),
            ));
        }
    }
    Ok(())
}

enum GrpcBuildState {
    Server(Server),
    Router(Router),
}

impl GrpcBuildState {
    fn add_service(
        self,
        service: ApiService,
        stats_registry: &Arc<StatsRegistry>,
        handler_runtime: &Arc<HandlerRuntime>,
    ) -> std::io::Result<Self> {
        let add = |mut builder: Server| -> std::io::Result<Router> {
            Ok(match service {
                ApiService::Reflection => {
                    let reflection = tonic_reflection::server::Builder::configure()
                        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
                        .build_v1()
                        .map_err(std::io::Error::other)?;
                    builder.add_service(reflection)
                }
                ApiService::Stats => builder.add_service(StatsServiceServer::new(
                    StatsServiceImpl::new(Arc::clone(stats_registry)),
                )),
                ApiService::Handler => builder.add_service(HandlerServiceServer::new(
                    HandlerServiceImpl::new(Arc::clone(handler_runtime)),
                )),
                ApiService::Logger => {
                    let logger = LoggerServiceImpl::from_global().map_err(|err| {
                        std::io::Error::other(format!(
                            "LoggerService unavailable: {}",
                            err.message()
                        ))
                    })?;
                    builder.add_service(LoggerServiceServer::new(logger))
                }
                ApiService::Routing => builder.add_service(RoutingServiceServer::new(
                    RoutingServiceImpl::new(Arc::clone(handler_runtime)),
                )),
                ApiService::Observatory => {
                    let observatory = ObservatoryServiceImpl::new(Arc::clone(handler_runtime))
                        .map_err(|err| {
                            std::io::Error::other(format!(
                                "ObservatoryService unavailable: {}",
                                err.message()
                            ))
                        })?;
                    builder.add_service(ObservatoryServiceServer::new(observatory))
                }
            })
        };

        match self {
            Self::Server(builder) => add(builder).map(Self::Router),
            Self::Router(router) => Ok(Self::Router(match service {
                ApiService::Reflection => {
                    let reflection = tonic_reflection::server::Builder::configure()
                        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
                        .build_v1()
                        .map_err(std::io::Error::other)?;
                    router.add_service(reflection)
                }
                ApiService::Stats => router.add_service(StatsServiceServer::new(
                    StatsServiceImpl::new(Arc::clone(stats_registry)),
                )),
                ApiService::Handler => router.add_service(HandlerServiceServer::new(
                    HandlerServiceImpl::new(Arc::clone(handler_runtime)),
                )),
                ApiService::Logger => {
                    let logger = LoggerServiceImpl::from_global().map_err(|err| {
                        std::io::Error::other(format!(
                            "LoggerService unavailable: {}",
                            err.message()
                        ))
                    })?;
                    router.add_service(LoggerServiceServer::new(logger))
                }
                ApiService::Routing => router.add_service(RoutingServiceServer::new(
                    RoutingServiceImpl::new(Arc::clone(handler_runtime)),
                )),
                ApiService::Observatory => {
                    let observatory = ObservatoryServiceImpl::new(Arc::clone(handler_runtime))
                        .map_err(|err| {
                            std::io::Error::other(format!(
                                "ObservatoryService unavailable: {}",
                                err.message()
                            ))
                        })?;
                    router.add_service(ObservatoryServiceServer::new(observatory))
                }
            })),
        }
    }
}

fn build_grpc_router(
    server_builder: Server,
    services: &[ApiService],
    stats_registry: &Arc<StatsRegistry>,
    handler_runtime: &Arc<HandlerRuntime>,
) -> std::io::Result<Option<Router>> {
    let mut state = GrpcBuildState::Server(server_builder);
    for service in services {
        state = state.add_service(*service, stats_registry, handler_runtime)?;
    }
    match state {
        GrpcBuildState::Server(_) => Ok(None),
        GrpcBuildState::Router(router) => Ok(Some(router)),
    }
}

/// Start the Xray-compatible gRPC API on a custom incoming stream (blocks until shutdown).
pub async fn serve_grpc_incoming<I, IO>(
    incoming: I,
    services: Vec<ApiService>,
    stats_registry: Arc<StatsRegistry>,
    handler_runtime: Arc<HandlerRuntime>,
    transport: ApiTransportMode,
) -> std::io::Result<()>
where
    I: Stream<Item = Result<IO, std::io::Error>> + Send + Unpin + 'static,
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Connected + Unpin + Send + 'static,
{
    let mut server_builder = Server::builder();
    if transport.uses_tls() {
        let tls = build_server_tls_config(&transport)?;
        server_builder = server_builder
            .tls_config(tls)
            .map_err(std::io::Error::other)?;
    }

    let router = build_grpc_router(server_builder, &services, &stats_registry, &handler_runtime)?;

    if let Some(router) = router {
        router
            .serve_with_incoming(incoming)
            .await
            .map_err(|err| std::io::Error::other(format!("Xray API server stopped: {err}")))?;
    } else {
        let mut incoming = incoming;
        while let Some(result) = incoming.next().await {
            let _ = result?;
        }
    }
    Ok(())
}

/// Start the Xray-compatible gRPC API server on a pre-bound TCP listener (blocks until shutdown).
pub async fn serve_grpc_on(
    listener: TcpListener,
    services: Vec<ApiService>,
    stats_registry: Arc<StatsRegistry>,
    handler_runtime: Arc<HandlerRuntime>,
    transport: ApiTransportMode,
) -> std::io::Result<()> {
    let local_addr = listener.local_addr()?;
    let incoming = DiagnosingTcpIncoming::from_listener(listener, true, None, transport.clone())
        .map_err(std::io::Error::other)?;
    serve_grpc_incoming(
        incoming,
        services,
        stats_registry,
        handler_runtime,
        transport,
    )
    .await
    .map_err(|err| std::io::Error::other(format!("Xray API server on {local_addr} stopped: {err}")))
}

#[cfg(unix)]
pub async fn serve_grpc_on_unix(
    listener: tokio::net::UnixListener,
    services: Vec<ApiService>,
    stats_registry: Arc<StatsRegistry>,
    handler_runtime: Arc<HandlerRuntime>,
    transport: ApiTransportMode,
) -> std::io::Result<()> {
    if transport.uses_tls() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TLS/mTLS API transport is not supported on Unix domain listeners",
        ));
    }
    let incoming = UnixListenerStream::new(listener);
    serve_grpc_incoming(
        incoming,
        services,
        stats_registry,
        handler_runtime,
        transport,
    )
    .await
}

/// Result of starting the configured Xray API Commander.
#[derive(Debug)]
pub struct ApiServerStartup {
    pub enabled_services: Vec<ApiService>,
    pub transport: ApiTransportMode,
    pub task: tokio::task::JoinHandle<std::io::Result<()>>,
    pub internal: Option<InternalCommanderHandle>,
    pub configured_listen: String,
    pub bound_label: Option<String>,
}

pub async fn start_configured_api_server(
    config_source: &str,
    xray: &XrayConfig,
    handler_runtime: Arc<HandlerRuntime>,
    stats_registry: Arc<StatsRegistry>,
) -> std::io::Result<Option<ApiServerStartup>> {
    let Some(api) = xray.api.as_ref() else {
        return Ok(None);
    };

    let enabled = parse_enabled_services(&api.services)?;
    validate_duplicate_api_services(&enabled)?;

    for service in &enabled {
        if matches!(service, ApiService::Observatory) {
            ObservatoryServiceImpl::new(Arc::clone(&handler_runtime)).map_err(|err| {
                std::io::Error::other(format!("ObservatoryService unavailable: {}", err.message()))
            })?;
        }
        if matches!(service, ApiService::Logger) {
            LoggerServiceImpl::from_global().map_err(|err| {
                std::io::Error::other(format!("LoggerService unavailable: {}", err.message()))
            })?;
        }
    }

    let selection = resolve_api_transport_mode(ApiTransportContext {
        config_source,
        api_listen: api.listen.as_deref(),
        xray: Some(xray),
    })?;
    log_api_transport_selected(&selection);
    let transport = selection.mode;

    let configured_listen = api.listen.clone().unwrap_or_default();
    if is_internal_commander_listen(api.listen.as_deref()) {
        let (listener, incoming) = CommanderOutboundListener::pair();
        handler_runtime
            .outbound
            .install_commander_outbound(&api.tag, Arc::clone(&listener))
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        let internal = InternalCommanderHandle::new(Arc::clone(&listener));
        let task = tokio::spawn(serve_grpc_incoming(
            incoming,
            enabled.clone(),
            stats_registry,
            handler_runtime,
            transport.clone(),
        ));
        log_api_internal_commander_ready(&api.tag, &api.services, &enabled, &transport);
        return Ok(Some(ApiServerStartup {
            enabled_services: enabled,
            transport,
            task,
            internal: Some(internal),
            configured_listen,
            bound_label: None,
        }));
    }

    let bound = bind_api_listen(configured_listen.trim()).await?;
    let bound_label = bound.log_label();
    match bound {
        BoundApiListener::Tcp(listener, bound_addr) => {
            log_api_listener_ready(
                configured_listen.trim(),
                bound_addr,
                &api.services,
                &enabled,
                &transport,
            );
            let task = tokio::spawn(serve_grpc_on(
                listener,
                enabled.clone(),
                stats_registry,
                handler_runtime,
                transport.clone(),
            ));
            Ok(Some(ApiServerStartup {
                enabled_services: enabled,
                transport,
                task,
                internal: None,
                configured_listen,
                bound_label: Some(bound_label),
            }))
        }
        #[cfg(unix)]
        BoundApiListener::Unix(listener, path) => {
            info!(
                api_listen = %configured_listen.trim(),
                api_unix_path = %path,
                "Xray API listening on Unix socket"
            );
            let task = tokio::spawn(serve_grpc_on_unix(
                listener,
                enabled.clone(),
                stats_registry,
                handler_runtime,
                transport.clone(),
            ));
            Ok(Some(ApiServerStartup {
                enabled_services: enabled,
                transport,
                task,
                internal: None,
                configured_listen,
                bound_label: Some(bound_label),
            }))
        }
    }
}

pub fn log_api_internal_commander_ready(
    api_tag: &str,
    configured_services: &[String],
    enabled: &[ApiService],
    mode: &ApiTransportMode,
) {
    let mounted = format_mounted_service_paths(enabled);
    info!(
        api_tag = %api_tag,
        api_mode = "internal-commander",
        api_mounted_services = %mounted,
        "Xray API internal Commander mode active (no network listener)"
    );
    info!(
        api_services = ?configured_services,
        api_mounted_services = %mounted,
        "Xray API enabled services"
    );
    crate::startup_log::eprintln_bootstrap(format!(
        "API internal Commander outbound tag={api_tag} plaintext gRPC ({mounted})"
    ));
    let _ = mode;
}

/// Start the Xray-compatible gRPC API server (blocks until shutdown).
pub async fn serve_grpc(
    listen: &str,
    services: Vec<ApiService>,
    stats_registry: Arc<StatsRegistry>,
    handler_runtime: Arc<HandlerRuntime>,
) -> std::io::Result<()> {
    let transport = api_transport_mode_from_env()?;
    let (listener, _) = bind_api_listener(listen).await?;
    serve_grpc_on(
        listener,
        services,
        stats_registry,
        handler_runtime,
        transport,
    )
    .await
}

#[cfg(test)]
#[path = "../../tests/unit/api/server.rs"]
mod tests;
