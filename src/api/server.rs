use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::server::Router;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::api::diagnostics::DiagnosingTcpIncoming;
use tracing::info;

use crate::api::handler::HandlerServiceImpl;
use crate::api::logger::LoggerServiceImpl;
use crate::api::proto::app::log::command::logger_service_server::LoggerServiceServer;
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
use crate::runtime::InboundUserManagers;
use crate::stats::StatsRegistry;

/// Enabled Xray API gRPC services (from `api.services`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiService {
    Reflection,
    Handler,
    Logger,
    Stats,
    Routing,
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

/// Parse `api.listen` / resolved API address. Requires an explicit `host:port` (no default port).
pub fn parse_api_grpc_listen_addr(listen: &str) -> std::io::Result<SocketAddr> {
    let listen = listen.trim();
    if listen.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "api.listen must not be empty",
        ));
    }
    if !listen.contains(':') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("api.listen must include host:port (e.g. 127.0.0.1:61000), got {listen:?}"),
        ));
    }

    listen.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid api.listen address {listen}: {e}"),
        )
    })
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

/// Bind the API TCP listener before serving (fail fast if the address is unavailable).
pub async fn bind_api_listener(listen: &str) -> std::io::Result<(TcpListener, SocketAddr)> {
    let configured = listen.trim().to_string();
    let socket_addr = parse_api_grpc_listen_addr(&configured)?;
    let listener = TcpListener::bind(socket_addr).await.map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!(
                "failed to bind Xray API listener on {socket_addr} (api.listen={configured}): {err}"
            ),
        )
    })?;
    let bound = listener.local_addr()?;
    Ok((listener, bound))
}

pub fn log_api_listener_ready(
    configured_listen: &str,
    bound_addr: SocketAddr,
    services: &[String],
    mode: &ApiTransportMode,
) {
    let configured = configured_listen.trim();
    let transport_label = match mode {
        ApiTransportMode::Plaintext => "plaintext",
        ApiTransportMode::Tls { .. } => "TLS",
        ApiTransportMode::Mtls { .. } => "mTLS",
    };
    info!(api_listen = %configured, "Xray API config listen");
    info!(
        api_bind_addr = %bound_addr,
        api_transport = mode.as_log_label(),
        "Xray API listening on {bound_addr} {transport_label}"
    );
    info!(api_services = ?services, "Xray API enabled services");
    crate::startup_log::eprintln_bootstrap(format!(
        "API owns {bound_addr} for {transport_label} gRPC (xray.app.stats.command.StatsService)"
    ));
}

/// Parse `api.services` into mountable services. Unknown or unsupported entries error at startup.
pub fn parse_enabled_services(services: &[String]) -> std::io::Result<Vec<ApiService>> {
    if services.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "api.services must list at least one gRPC service",
        ));
    }

    let mut enabled = Vec::with_capacity(services.len());
    for service in services {
        let parsed = if eq_ignore_ascii_case(service, "ReflectionService") {
            ApiService::Reflection
        } else if eq_ignore_ascii_case(service, "HandlerService") {
            ApiService::Handler
        } else if eq_ignore_ascii_case(service, "LoggerService") {
            ApiService::Logger
        } else if eq_ignore_ascii_case(service, "StatsService") {
            ApiService::Stats
        } else if eq_ignore_ascii_case(service, "RoutingService") {
            ApiService::Routing
        } else if eq_ignore_ascii_case(service, "ObservatoryService") {
            tracing::warn!(
                service = %service,
                "ObservatoryService listed in api.services but is not mounted in rust-xray API server"
            );
            continue;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("api.services entry is not supported: {service}"),
            ));
        };

        if !enabled.contains(&parsed) {
            enabled.push(parsed);
        }
    }

    if enabled.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "api.services did not enable any mountable gRPC service (StatsService, HandlerService, ...)",
        ));
    }

    Ok(enabled)
}

/// Start the Xray-compatible gRPC API server on a pre-bound listener (blocks until shutdown).
pub async fn serve_grpc_on(
    listener: TcpListener,
    services: Vec<ApiService>,
    stats_registry: Arc<StatsRegistry>,
    inbound_users: Arc<InboundUserManagers>,
    transport: ApiTransportMode,
) -> std::io::Result<()> {
    let local_addr = listener.local_addr()?;
    let incoming = DiagnosingTcpIncoming::from_listener(listener, true, None, transport.clone())
        .map_err(std::io::Error::other)?;

    let mut server_builder = Server::builder();
    if transport.uses_tls() {
        let tls = build_server_tls_config(&transport)?;
        server_builder = server_builder
            .tls_config(tls)
            .map_err(std::io::Error::other)?;
    }

    let mut router: Option<Router> = None;
    macro_rules! add_service {
        ($svc:expr) => {
            router = Some(match router {
                None => server_builder.add_service($svc),
                Some(router) => router.add_service($svc),
            });
        };
    }

    if services.contains(&ApiService::Reflection) {
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()
            .map_err(std::io::Error::other)?;
        add_service!(reflection);
    }
    if services.contains(&ApiService::Stats) {
        add_service!(StatsServiceServer::new(StatsServiceImpl::new(Arc::clone(
            &stats_registry,
        ))));
    }
    if services.contains(&ApiService::Handler) {
        add_service!(HandlerServiceServer::new(HandlerServiceImpl::new(
            Arc::clone(&inbound_users,)
        )));
    }
    if services.contains(&ApiService::Logger) {
        add_service!(LoggerServiceServer::new(LoggerServiceImpl));
    }
    if services.contains(&ApiService::Routing) {
        add_service!(RoutingServiceServer::new(RoutingServiceImpl));
    }

    let router = router.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "api.services did not enable any mountable gRPC service",
        )
    })?;

    router.serve_with_incoming(incoming).await.map_err(|err| {
        std::io::Error::other(format!("Xray API server on {local_addr} stopped: {err}"))
    })
}

/// Start the Xray-compatible gRPC API server (blocks until shutdown).
pub async fn serve_grpc(
    listen: &str,
    services: Vec<ApiService>,
    stats_registry: Arc<StatsRegistry>,
    inbound_users: Arc<InboundUserManagers>,
) -> std::io::Result<()> {
    let transport = api_transport_mode_from_env()?;
    let (listener, _) = bind_api_listener(listen).await?;
    serve_grpc_on(listener, services, stats_registry, inbound_users, transport).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        vars: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn new(pairs: &[(&'static str, Option<&str>)]) -> Self {
            let lock = ENV_LOCK.lock().expect("env lock");
            let mut saved = Vec::new();
            for (key, value) in pairs {
                saved.push((*key, std::env::var(key).ok()));
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
            Self {
                _lock: lock,
                vars: saved,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.vars {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn parse_api_listen_requires_host_and_port() {
        assert!(parse_api_grpc_listen_addr("127.0.0.1:10085").is_ok());
        assert!(parse_api_grpc_listen_addr("0.0.0.0:10085").is_ok());
        let err = parse_api_grpc_listen_addr("127.0.0.1").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("host:port"));
    }

    #[test]
    fn transport_defaults_plaintext_for_file_config() {
        let _guard = EnvGuard::new(&[
            ("RUST_XRAY_API_TRANSPORT", None),
            ("RUST_XRAY_API_TLS", None),
            ("RUST_XRAY_API_TLS_CA", None),
            ("RUST_XRAY_API_TLS_CERT", None),
            ("RUST_XRAY_API_TLS_KEY", None),
        ]);
        let sel = resolve_api_transport_mode(ApiTransportContext {
            config_source: "/etc/xray/config.json",
            api_listen: Some("127.0.0.1:61000"),
            xray: None,
        })
        .expect("plaintext");
        assert_eq!(sel.mode, ApiTransportMode::Plaintext);
        assert_eq!(sel.reason, "xray-default-plaintext");
    }

    #[test]
    fn transport_env_plaintext_override() {
        let _guard = EnvGuard::new(&[
            ("RUST_XRAY_API_TRANSPORT", Some("plaintext")),
            ("RUST_XRAY_API_TLS", None),
            ("RUST_XRAY_API_TLS_CA", None),
            ("RUST_XRAY_API_TLS_CERT", None),
            ("RUST_XRAY_API_TLS_KEY", None),
        ]);
        let sel = resolve_api_transport_mode(ApiTransportContext {
            config_source: "http+unix:///run/remna.sock/internal/get-config?token=x",
            api_listen: Some("127.0.0.1:61000"),
            xray: None,
        })
        .expect("plaintext override");
        assert_eq!(sel.mode, ApiTransportMode::Plaintext);
        assert_eq!(sel.reason, "env-override");
    }

    #[test]
    fn transport_remnawave_auto_selects_mtls() {
        let _guard = EnvGuard::new(&[
            ("RUST_XRAY_API_TRANSPORT", None),
            ("RUST_XRAY_API_TLS", None),
            ("RUST_XRAY_API_TLS_CA", None),
            ("RUST_XRAY_API_TLS_CERT", None),
            ("RUST_XRAY_API_TLS_KEY", None),
        ]);
        let err = resolve_api_transport_mode(ApiTransportContext {
            config_source: "http+unix:///run/remna.sock/internal/get-config?token=x",
            api_listen: Some("127.0.0.1:61000"),
            xray: None,
        })
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("Remnawave mTLS"));
    }

    #[test]
    fn transport_env_tls_requires_cert_and_key() {
        let _guard = EnvGuard::new(&[
            ("RUST_XRAY_API_TRANSPORT", Some("tls")),
            ("RUST_XRAY_API_TLS", None),
            ("RUST_XRAY_API_TLS_CA", None),
            ("RUST_XRAY_API_TLS_CERT", None),
            ("RUST_XRAY_API_TLS_KEY", None),
        ]);
        let err = resolve_api_transport_mode(ApiTransportContext {
            config_source: "/etc/xray/config.json",
            api_listen: None,
            xray: None,
        })
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn transport_env_tls_with_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("api.crt");
        let key_path = dir.path().join("api.key");
        write_test_tls_pem(&cert_path, &key_path);
        let _guard = EnvGuard::new(&[
            ("RUST_XRAY_API_TRANSPORT", Some("tls")),
            ("RUST_XRAY_API_TLS", None),
            ("RUST_XRAY_API_TLS_CA", None),
            ("RUST_XRAY_API_TLS_CERT", Some(cert_path.to_str().unwrap())),
            ("RUST_XRAY_API_TLS_KEY", Some(key_path.to_str().unwrap())),
        ]);
        let sel = resolve_api_transport_mode(ApiTransportContext {
            config_source: "/etc/xray/config.json",
            api_listen: None,
            xray: None,
        })
        .expect("tls files");
        assert!(matches!(sel.mode, ApiTransportMode::Tls { .. }));
        assert_eq!(sel.reason, "env-override");
    }

    #[test]
    fn transport_invalid_cert_key_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("bad.crt");
        let key_path = dir.path().join("bad.key");
        std::fs::write(&cert_path, b"not a cert").expect("write cert");
        std::fs::write(&key_path, b"not a key").expect("write key");
        let _guard = EnvGuard::new(&[
            ("RUST_XRAY_API_TRANSPORT", Some("tls")),
            ("RUST_XRAY_API_TLS", None),
            ("RUST_XRAY_API_TLS_CA", None),
            ("RUST_XRAY_API_TLS_CERT", Some(cert_path.to_str().unwrap())),
            ("RUST_XRAY_API_TLS_KEY", Some(key_path.to_str().unwrap())),
        ]);
        let err = resolve_api_transport_mode(ApiTransportContext {
            config_source: "/etc/xray/config.json",
            api_listen: None,
            xray: None,
        })
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parse_enabled_services_skips_observatory_but_mounts_stats() {
        let enabled =
            parse_enabled_services(&["ObservatoryService".to_string(), "StatsService".to_string()])
                .expect("parse services");
        assert_eq!(enabled, vec![ApiService::Stats]);
    }

    fn write_test_tls_pem(cert_path: &std::path::Path, key_path: &std::path::Path) {
        use rcgen::{CertificateParams, KeyPair};
        let key_pair = KeyPair::generate().expect("generate key");
        let params = CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self signed cert");
        std::fs::write(cert_path, cert.pem()).expect("write cert");
        std::fs::write(key_path, key_pair.serialize_pem()).expect("write key");
    }
}
