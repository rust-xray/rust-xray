//! Accept `protocol = tunnel` inbounds and route byte-transparent streams to Commander.

use std::sync::Arc;

use tokio::net::UnixStream;
use tracing::{debug, error, info, warn};

use crate::config::{
    api_listen_kind, bind_api_listen, ApiInbound, ApiListenKind, BoundApiListener,
};
use crate::routing::{route_context_from_tunnel, RuntimeRouter};

/// Background accept loop for one tunnel inbound.
#[derive(Debug)]
pub struct TunnelInboundHandle {
    pub tag: String,
    pub listen_addr: String,
    task: tokio::task::JoinHandle<()>,
}

impl TunnelInboundHandle {
    pub fn abort(self) {
        self.task.abort();
    }
}

/// Bind and serve a tunnel inbound until the returned handle is dropped or aborted.
pub async fn start_tunnel_inbound(
    inbound: ApiInbound,
    router: Arc<RuntimeRouter>,
) -> std::io::Result<TunnelInboundHandle> {
    let listen = inbound.listen_addr.trim();
    if listen.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tunnel inbound listen address must not be empty",
        ));
    }

    let inbound_tag = inbound
        .tag
        .clone()
        .filter(|tag| !tag.is_empty())
        .unwrap_or_else(|| "api-tunnel".to_string());

    match api_listen_kind(Some(listen)) {
        ApiListenKind::InternalCommander | ApiListenKind::Tcp => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "tunnel inbound {inbound_tag} requires unix listen (@abstract or filesystem path), got {listen:?}"
                ),
            ));
        }
        #[cfg(unix)]
        ApiListenKind::UnixPath => {}
        #[cfg(all(unix, target_os = "linux"))]
        ApiListenKind::UnixAbstract => {}
        #[cfg(not(unix))]
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tunnel inbound requires a unix host",
            ));
        }
    }

    let bound = bind_api_listen(listen).await?;
    let BoundApiListener::Unix(listener, bound_label) = bound else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("tunnel inbound {inbound_tag} requires unix listen"),
        ));
    };

    info!(
        inbound_tag = %inbound_tag,
        listen = %bound_label,
        protocol = %inbound.protocol,
        "tunnel inbound listener bound"
    );
    crate::startup_log::eprintln_bootstrap(format!(
        "tunnel inbound started tag={inbound_tag} listen={bound_label}"
    ));

    let task_tag = inbound_tag.clone();
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let router = Arc::clone(&router);
                    let inbound_tag = task_tag.clone();
                    tokio::spawn(async move {
                        if let Err(err) =
                            dispatch_tunnel_connection(stream, &inbound_tag, router).await
                        {
                            debug!(
                                inbound_tag = %inbound_tag,
                                error = %err,
                                "tunnel inbound connection ended"
                            );
                        }
                    });
                }
                Err(err) => {
                    error!(
                        inbound_tag = %task_tag,
                        error = %err,
                        "tunnel inbound accept failed"
                    );
                    break;
                }
            }
        }
    });

    Ok(TunnelInboundHandle {
        tag: inbound_tag,
        listen_addr: bound_label,
        task,
    })
}

async fn dispatch_tunnel_connection(
    stream: UnixStream,
    inbound_tag: &str,
    router: Arc<RuntimeRouter>,
) -> std::io::Result<()> {
    let route_ctx = route_context_from_tunnel(inbound_tag);
    let decision = router
        .pick_route_with_default(route_ctx)
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    router.publish_route(&decision);

    debug!(
        inbound_tag = %inbound_tag,
        outbound_tag = %decision.outbound_tag,
        rule_tag = %decision.rule_tag,
        "tunnel inbound route selected"
    );

    let outbound_manager = router.outbound_manager();
    if !outbound_manager.is_commander_outbound(&decision.outbound_tag) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "tunnel inbound {inbound_tag} routed to non-commander outbound {}",
                decision.outbound_tag
            ),
        ));
    }

    let listener = outbound_manager.commander_listener().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "commander outbound listener is not active",
        )
    })?;

    if !listener.try_push_io(stream) {
        warn!(
            inbound_tag = %inbound_tag,
            "commander outbound connection queue full"
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "commander outbound connection queue full",
        ));
    }

    Ok(())
}
