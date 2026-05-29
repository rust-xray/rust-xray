use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tonic::transport::server::{Router, TcpIncoming};
use tonic::transport::Server;
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

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "ObservatoryService is not implemented in rust-xray API server",
            ));
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

    Ok(enabled)
}

fn parse_listen_addr(listen: &str) -> std::io::Result<SocketAddr> {
    if listen.contains(':') {
        return listen.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid api.listen address {listen}: {e}"),
            )
        });
    }

    format!("{listen}:8080").parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid api.listen address {listen}: {e}"),
        )
    })
}

/// Start the Xray-compatible gRPC API server on a pre-bound listener (blocks until shutdown).
pub async fn serve_grpc_on(
    listener: TcpListener,
    services: Vec<ApiService>,
    stats_registry: Arc<StatsRegistry>,
    inbound_users: Arc<InboundUserManagers>,
) -> std::io::Result<()> {
    let local_addr = listener.local_addr()?;
    let incoming =
        TcpIncoming::from_listener(listener, true, None).map_err(std::io::Error::other)?;

    let mut router: Option<Router> = None;
    macro_rules! add_service {
        ($svc:expr) => {
            router = Some(match router {
                None => Server::builder().add_service($svc),
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

    info!(
        %local_addr,
        services = ?services,
        "Xray-compatible gRPC API listening"
    );

    router
        .serve_with_incoming(incoming)
        .await
        .map_err(std::io::Error::other)
}

/// Start the Xray-compatible gRPC API server (blocks until shutdown).
pub async fn serve_grpc(
    listen: &str,
    services: Vec<ApiService>,
    stats_registry: Arc<StatsRegistry>,
    inbound_users: Arc<InboundUserManagers>,
) -> std::io::Result<()> {
    let addr = parse_listen_addr(listen)?;
    let listener = TcpListener::bind(addr).await?;
    serve_grpc_on(listener, services, stats_registry, inbound_users).await
}
