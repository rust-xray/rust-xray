use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::mux::route_env::MuxRouteEnv;
use crate::outbound::freedom::{connect_udp_destination_with_runtime, resolve_udp_target};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::{
    connect_routed_outbound, route_context_from_vless, NetworkKind, RoutedOutbound,
};
use crate::vless::protocol::VlessDestination;

/// Per-association datagram queues shared by generic Mux UDP and XUDP.
pub(crate) const MUX_UDP_ASSOCIATION_QUEUE_CAPACITY: usize = 64;
/// Responses waiting for the sole parent-mux writer.
pub(crate) const MUX_UDP_RESPONSE_QUEUE_CAPACITY: usize = 64;

/// The routed packet-I/O portion shared by generic Mux UDP and XUDP.
///
/// Session identity, attachment, expiry, framing, and worker ownership stay in
/// their protocol-specific managers.
#[derive(Clone)]
pub(crate) enum RoutedUdpAssociation {
    Freedom {
        socket: Arc<UdpSocket>,
        runtime: Arc<OutboundConnectRuntime>,
        default_target: SocketAddr,
    },
    Blackhole,
}

impl RoutedUdpAssociation {
    pub(crate) async fn connect(
        destination: &VlessDestination,
        route_env: Option<&MuxRouteEnv>,
    ) -> std::io::Result<Self> {
        if let Some(route_env) = route_env {
            let route_ctx = route_context_from_vless(
                &route_env.inbound_tag,
                &route_env.auth,
                destination,
                &[],
                &route_env.socket_meta,
                route_env.sniffing_enabled,
                NetworkKind::Udp,
            );
            let decision = route_env
                .router
                .pick_route_with_default(route_ctx)
                .await
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            route_env.router.publish_route(&decision);

            #[cfg(test)]
            if let Some(counter) = &route_env.test_dispatch_counter {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }

            let runtime = OutboundConnectRuntime::shared();
            return match connect_routed_outbound(
                &decision.outbound_tag,
                destination,
                route_env.router.outbound_manager(),
                Arc::clone(&runtime),
                NetworkKind::Udp,
            )
            .await?
            {
                RoutedOutbound::Udp { socket, target } => Ok(Self::Freedom {
                    socket: Arc::new(socket),
                    runtime,
                    default_target: target,
                }),
                RoutedOutbound::Blackhole => Ok(Self::Blackhole),
                RoutedOutbound::Tcp(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "UDP association cannot use freedom TCP outbound",
                )),
            };
        }

        let runtime = OutboundConnectRuntime::shared();
        let (socket, default_target) =
            connect_udp_destination_with_runtime(destination, Arc::clone(&runtime)).await?;
        Ok(Self::Freedom {
            socket: Arc::new(socket),
            runtime,
            default_target,
        })
    }

    pub(crate) fn has_downlink(&self) -> bool {
        matches!(self, Self::Freedom { .. })
    }

    pub(crate) async fn send_to(
        &self,
        destination: Option<&VlessDestination>,
        payload: &[u8],
    ) -> std::io::Result<()> {
        match self {
            Self::Blackhole => Ok(()),
            Self::Freedom {
                socket,
                runtime,
                default_target,
            } => {
                // Xray's packet writer uses the association's connected target when
                // a Keep frame has no UDP destination metadata. An explicit packet
                // destination is a one-packet override and does not replace it.
                let target = match destination {
                    Some(destination) => {
                        resolve_udp_target(destination, Arc::clone(runtime)).await?
                    }
                    None => *default_target,
                };
                let sent = socket.send_to(payload, target).await?;
                if sent != payload.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!("partial UDP datagram send: {sent}/{} bytes", payload.len()),
                    ));
                }
                Ok(())
            }
        }
    }

    pub(crate) async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<Option<(usize, VlessDestination)>> {
        match self {
            Self::Blackhole => Ok(None),
            Self::Freedom { socket, .. } => {
                let (len, peer) = socket.recv_from(buf).await?;
                Ok(Some((len, VlessDestination::Ip(peer.ip(), peer.port()))))
            }
        }
    }
}
