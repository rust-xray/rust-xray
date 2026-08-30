//! Runtime-only gRPC service name aliases (Xray `RegisterService` parity).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{Request, Response, Uri};
use tonic::body::BoxBody;
use tonic::codegen::Body;
use tonic::codegen::Service;
use tonic::server::NamedService;

pub const CANONICAL_HANDLER_SERVICE: &str = "xray.app.proxyman.command.HandlerService";
pub const LEGACY_HANDLER_SERVICE: &str = "v2ray.core.app.proxyman.command.HandlerService";

pub const CANONICAL_STATS_SERVICE: &str = "xray.app.stats.command.StatsService";
pub const LEGACY_STATS_SERVICE: &str = "v2ray.core.app.stats.command.StatsService";

pub const CANONICAL_ROUTING_SERVICE: &str = "xray.app.router.command.RoutingService";
pub const LEGACY_ROUTING_SERVICE: &str = "v2ray.core.app.router.command.RoutingService";

pub const CANONICAL_LOGGER_SERVICE: &str = "xray.app.log.command.LoggerService";
pub const LEGACY_LOGGER_SERVICE: &str = "v2ray.core.app.log.command.LoggerService";

pub const CANONICAL_OBSERVATORY_SERVICE: &str =
    "xray.core.app.observatory.command.ObservatoryService";
pub const LEGACY_OBSERVATORY_SERVICE: &str =
    "v2ray.core.app.observatory.command.ObservatoryService";

/// Rewrites legacy `/service/method` paths to canonical before dispatching.
#[derive(Clone)]
pub struct LegacyAliasService<S> {
    inner: S,
    legacy_prefix: &'static str,
    canonical_prefix: &'static str,
}

impl<S> LegacyAliasService<S> {
    pub fn new(
        inner: S,
        legacy_service_name: &'static str,
        canonical_service_name: &'static str,
    ) -> Self {
        Self {
            inner,
            legacy_prefix: legacy_service_name,
            canonical_prefix: canonical_service_name,
        }
    }

    fn rewrite_path(path: &str, legacy: &str, canonical: &str) -> Option<String> {
        let legacy_root = format!("/{legacy}/");
        let canonical_root = format!("/{canonical}/");
        path.strip_prefix(&legacy_root)
            .map(|method| format!("{canonical_root}{method}"))
    }
}

macro_rules! legacy_alias_type {
    ($alias:ident, $legacy:expr, $canonical:expr) => {
        #[derive(Clone)]
        pub struct $alias<S>(LegacyAliasService<S>);

        impl<S> $alias<S> {
            pub fn new(inner: S) -> Self {
                Self(LegacyAliasService::new(inner, $legacy, $canonical))
            }
        }

        impl<S> NamedService for $alias<S> {
            const NAME: &'static str = $legacy;
        }
    };
}

legacy_alias_type!(
    LegacyHandlerServiceAlias,
    LEGACY_HANDLER_SERVICE,
    CANONICAL_HANDLER_SERVICE
);
legacy_alias_type!(
    LegacyStatsServiceAlias,
    LEGACY_STATS_SERVICE,
    CANONICAL_STATS_SERVICE
);
legacy_alias_type!(
    LegacyRoutingServiceAlias,
    LEGACY_ROUTING_SERVICE,
    CANONICAL_ROUTING_SERVICE
);
legacy_alias_type!(
    LegacyLoggerServiceAlias,
    LEGACY_LOGGER_SERVICE,
    CANONICAL_LOGGER_SERVICE
);

impl<S, B> Service<Request<B>> for LegacyAliasService<S>
where
    S: Service<Request<B>, Response = Response<BoxBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: Body + Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(new_path) =
            Self::rewrite_path(req.uri().path(), self.legacy_prefix, self.canonical_prefix)
        {
            if let Ok(new_uri) = Uri::builder().path_and_query(new_path).build() {
                *req.uri_mut() = new_uri;
            }
        }
        let future = self.inner.call(req);
        Box::pin(future)
    }
}

macro_rules! legacy_alias_service_impl {
    ($alias:ident) => {
        impl<S, B> Service<Request<B>> for $alias<S>
        where
            S: Service<Request<B>, Response = Response<BoxBody>, Error = Infallible>
                + Clone
                + Send
                + 'static,
            S::Future: Send + 'static,
            B: Body + Send + 'static,
        {
            type Response = Response<BoxBody>;
            type Error = Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

            fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                self.0.poll_ready(cx)
            }

            fn call(&mut self, req: Request<B>) -> Self::Future {
                self.0.call(req)
            }
        }
    };
}

legacy_alias_service_impl!(LegacyHandlerServiceAlias);
legacy_alias_service_impl!(LegacyStatsServiceAlias);
legacy_alias_service_impl!(LegacyRoutingServiceAlias);
legacy_alias_service_impl!(LegacyLoggerServiceAlias);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_legacy_stats_path_to_canonical() {
        let rewritten = LegacyAliasService::<()>::rewrite_path(
            "/v2ray.core.app.stats.command.StatsService/GetSysStats",
            LEGACY_STATS_SERVICE,
            CANONICAL_STATS_SERVICE,
        )
        .expect("rewrite");
        assert_eq!(
            rewritten,
            "/xray.app.stats.command.StatsService/GetSysStats"
        );
    }
}
