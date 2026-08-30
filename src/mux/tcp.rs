use std::io::{Error, ErrorKind};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::mux::encoder::{encode_mux_end, encode_mux_keep_data};
use crate::mux::frame::{MuxCommand, MuxFrame, MuxSessionTrace};
use crate::mux::route_env::MuxRouteEnv;
use crate::mux::state::{mux_actions, MuxFrameActions};
use crate::outbound::freedom::{connect_tcp_destination, format_vless_destination};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::{
    connect_routed_outbound, route_context_from_vless, NetworkKind, RoutedOutbound,
};

pub(crate) async fn handle_mux_tcp_command(
    active: &mut Option<(u16, TcpStream)>,
    frame: MuxFrame,
    route_env: Option<&MuxRouteEnv>,
) -> std::io::Result<MuxFrameActions> {
    let id = frame.mux_id;
    match frame.command {
        MuxCommand::Tcp {
            destination,
            initial_payload,
        } => {
            if route_env.is_some_and(|env| env.vision_mux_udp_only) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "vision mux accepts only udp child substreams",
                ));
            }
            if active.is_some() {
                warn!(
                    mux_id = id,
                    "parallel mux substreams are not implemented yet"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            let destination_label = format_vless_destination(&destination.destination);
            debug!(
                mux_id = id,
                network = destination.network.as_str(),
                destination = %destination_label,
                "mux substream destination parsed"
            );
            let mut outbound = if let Some(env) = route_env {
                let route_ctx = route_context_from_vless(
                    &env.inbound_tag,
                    &env.auth,
                    &destination.destination,
                    &initial_payload,
                    &env.socket_meta,
                    env.sniffing_enabled,
                    NetworkKind::Tcp,
                );
                let decision = env
                    .router
                    .pick_route_with_default(route_ctx)
                    .await
                    .map_err(|err| Error::other(err.to_string()))?;
                env.router.publish_route(&decision);
                match connect_routed_outbound(
                    &decision.outbound_tag,
                    &destination.destination,
                    env.router.outbound_manager(),
                    OutboundConnectRuntime::shared(),
                    NetworkKind::Tcp,
                )
                .await?
                {
                    RoutedOutbound::Tcp(stream) => stream,
                    RoutedOutbound::Blackhole => {
                        debug!(
                            mux_id = id,
                            destination = %destination_label,
                            "mux substream routed to blackhole outbound"
                        );
                        return Ok(mux_actions(vec![encode_mux_end(id)]));
                    }
                    RoutedOutbound::Udp { .. } => {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "mux TCP substream cannot use freedom UDP outbound",
                        ));
                    }
                }
            } else {
                connect_tcp_destination(&destination.destination).await?
            };
            if !initial_payload.is_empty() {
                outbound.write_all(&initial_payload).await?;
            }
            debug!(mux_id = id, destination = %destination_label, "mux substream opened");
            *active = Some((id, outbound));
        }
        MuxCommand::Data { payload } => {
            let Some((active_id, outbound)) = active.as_mut() else {
                warn!(mux_id = id, "mux keep frame without active substream");
                return Ok(mux_actions(Vec::new()));
            };
            if *active_id != id {
                warn!(
                    mux_id = id,
                    active_mux_id = *active_id,
                    "mux frame for inactive substream"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            if !payload.is_empty() {
                outbound.write_all(&payload).await?;
            }
        }
        MuxCommand::Close { payload } => {
            let Some((active_id, mut outbound)) = active.take() else {
                debug!(mux_id = id, "mux end frame without active substream");
                return Ok(mux_actions(Vec::new()));
            };
            if active_id != id {
                warn!(
                    mux_id = id,
                    active_mux_id = active_id,
                    "mux end for inactive substream"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            if !payload.is_empty() {
                outbound.write_all(&payload).await?;
            }
            let _ = outbound.shutdown().await;
            debug!(mux_id = id, "mux substream close");
        }
        MuxCommand::KeepAlive => {
            debug!(mux_id = id, "mux keepalive");
        }
        MuxCommand::Udp { .. } => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "udp mux command must be handled by udp_dns module",
            ));
        }
    }
    Ok(mux_actions(Vec::new()))
}

#[cfg(test)]
#[path = "../../tests/unit/mux/tcp.rs"]
mod tests;
