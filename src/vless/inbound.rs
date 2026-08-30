use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::mux::{handle_mux_cool_inbound_with_env, MuxRouteEnv, MuxSessionTrace, XudpManager};
use crate::outbound::freedom::{
    connect_tcp_destination, connect_udp_destination_with_runtime, format_vless_destination,
    forward_tcp_initial_payload, relay_tcp_bidirectional,
};
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::reality::stages::{self, stage_error, RealityAcceptedStage};
use crate::reality::tls13::{
    relay_split_bidirectional_with_overflow_alert, relay_tls13_split_bidirectional,
    useless_record_overflow_limit, ApplicationStreamDirectRelay, RealityTls13ApplicationStream,
    RealityTls13RelaySplit, SplitMuxInbound,
};
use crate::routing::{connect_routed_outbound, NetworkKind, RouteSocketMeta, RuntimeRouter};
use crate::runtime::VlessInboundAuthContext;
use crate::stats::{StatsConnection, StatsState};
use crate::tls::PrefixedStream;
use crate::vless::protocol::{
    encode_vless_response_header, parse_vless_request, VlessCommand, VlessRequest,
};
use crate::vless::relay_debug::{
    log_outbound_stream_first_write, log_outbound_to_client_first_write,
    log_vless_request_diagnostics, log_vless_response_header_prefix,
};
use crate::vless::udp_relay::{
    relay_vless_udp_bidirectional, relay_vless_udp_split_with_overflow_alert,
};
use crate::vless::udp_session::VlessUdpRelayOptions;
use crate::vless::user_manager::{user_id_hint, VlessAuthenticatedClient, VlessUserManager};
use crate::vless::vision::{
    is_vision_flow, new_shared_traffic_state, parse_vless_request_flow, SharedTrafficState,
    VisionRelayReader, VisionRelayStream, VisionRelayWriter, FLOW_XTLS_RPRX_VISION,
};
use std::net::IpAddr;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use tracing::{debug, info, warn};

const MAX_VLESS_HEADER_SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessInboundRequest {
    pub request: VlessRequest,
    pub initial_payload: Vec<u8>,
}

pub async fn read_vless_request<S>(stream: &mut S) -> std::io::Result<VlessInboundRequest>
where
    S: AsyncRead + Unpin,
{
    read_vless_request_with_limit(stream, MAX_VLESS_HEADER_SIZE).await
}

pub(crate) async fn read_vless_request_with_limit<S>(
    stream: &mut S,
    max_header_size: usize,
) -> std::io::Result<VlessInboundRequest>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        match parse_vless_request(&buffer) {
            Ok((request, consumed)) => {
                return Ok(VlessInboundRequest {
                    request,
                    initial_payload: buffer[consumed..].to_vec(),
                });
            }
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                if buffer.len() >= max_header_size {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("vless request header exceeds {max_header_size} byte limit"),
                    ));
                }
            }
            Err(e) => return Err(e),
        }

        let remaining = max_header_size.saturating_sub(buffer.len());
        if remaining == 0 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("vless request header exceeds {max_header_size} byte limit"),
            ));
        }

        let to_read = remaining.min(chunk.len());
        let n = stream.read(&mut chunk[..to_read]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "stream closed before complete vless request header",
            ));
        }

        buffer.extend_from_slice(&chunk[..n]);
    }
}

pub fn is_supported_vless_flow(flow: Option<&str>) -> bool {
    matches!(flow, None | Some("") | Some("xtls-rprx-vision"))
}

pub fn authenticate_vless_client(
    request: &VlessRequest,
    users: &VlessUserManager,
) -> std::io::Result<VlessAuthenticatedClient> {
    users.authenticate(request)
}

pub fn validate_vless_flow_for_command(
    request_flow: Option<&str>,
    account_flow: Option<&str>,
    command: VlessCommand,
) -> std::io::Result<()> {
    let request_flow = request_flow
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let account_flow = account_flow
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (request_flow, account_flow) {
        (Some(FLOW_XTLS_RPRX_VISION), Some(FLOW_XTLS_RPRX_VISION)) => {
            if command == VlessCommand::Udp {
                return Err(std::io::Error::new(
                    ErrorKind::Unsupported,
                    format!("{FLOW_XTLS_RPRX_VISION} doesn't support UDP"),
                ));
            }
            Ok(())
        }
        (Some(FLOW_XTLS_RPRX_VISION), _) => Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!("account flow does not match request flow {FLOW_XTLS_RPRX_VISION}"),
        )),
        (None, Some(FLOW_XTLS_RPRX_VISION)) if command == VlessCommand::Tcp => {
            Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "account requires xtls-rprx-vision but client request flow is empty",
            ))
        }
        (Some(unknown), _) => Err(std::io::Error::new(
            ErrorKind::Unsupported,
            format!("unsupported VLESS request flow: {unknown}"),
        )),
        _ => Ok(()),
    }
}

fn unsupported_vless_command_error(
    command: VlessCommand,
    additional_info: &[u8],
) -> std::io::Error {
    let message = match command {
        VlessCommand::Udp if looks_like_xudp_request(additional_info) => {
            "XUDP unsupported".to_string()
        }
        VlessCommand::Udp => "UDP unsupported".to_string(),
        VlessCommand::Mux => "Mux unsupported".to_string(),
        other => format!("unsupported vless command: {:?}", other),
    };
    std::io::Error::new(ErrorKind::Unsupported, message)
}

fn looks_like_xudp_request(additional_info: &[u8]) -> bool {
    additional_info
        .windows(4)
        .any(|window| window.eq(b"xudp") || window.eq(b"XUDP"))
}

/// Writes and flushes the VLESS response header to the client stream.
pub async fn prepare_vless_tcp_response<W: AsyncWrite + Unpin>(
    client_stream: &mut W,
    version: u8,
) -> std::io::Result<()> {
    let header = encode_vless_response_header(version, None);
    let header_len = header.len();
    client_stream.write_all(&header).await?;
    client_stream.flush().await?;
    if crate::vless::relay_debug::debug_relay_prefix_enabled() {
        log_vless_response_header_prefix(&header, version, header_len);
    } else {
        debug!(
            stage = stages::VLESS_RESPONSE_HEADER_SENT,
            version, header_len, "sent VLESS response header"
        );
    }
    Ok(())
}

struct RelayClientWriteProbe<S> {
    inner: S,
    first_client_write_logged: bool,
}

impl<S> RelayClientWriteProbe<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            first_client_write_logged: false,
        }
    }
}

impl<S> AsyncRead for RelayClientWriteProbe<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for RelayClientWriteProbe<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            if !self.first_client_write_logged && written > 0 {
                log_outbound_to_client_first_write(buf, written);
                self.first_client_write_logged = true;
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn relay_vless_tcp_bidirectional<S>(
    client_stream: S,
    outbound: &mut tokio::net::TcpStream,
    vision: Option<(SharedTrafficState, [u8; 16])>,
    direct_relay: Option<ApplicationStreamDirectRelay>,
    _stats: Option<&StatsConnection>,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let probed_client = RelayClientWriteProbe::new(client_stream);
    let relay_result = if let Some((traffic, user_uuid)) = vision {
        let vision_client =
            VisionRelayStream::new(probed_client, traffic, user_uuid, direct_relay.clone());
        relay_tcp_bidirectional(vision_client, outbound, None).await
    } else {
        relay_tcp_bidirectional(probed_client, outbound, None).await
    };

    if direct_relay
        .as_ref()
        .is_some_and(ApplicationStreamDirectRelay::is_enabled)
    {
        debug!("vision direct relay completed");
    }

    relay_result
}

/// Writes a VLESS response header before relaying proxied target bytes to the client.
pub async fn write_vless_response_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
) -> std::io::Result<()> {
    prepare_vless_tcp_response(writer, version).await
}

struct VlessTcpRelayPrepared<S> {
    stream: S,
    outbound: tokio::net::TcpStream,
    vision: Option<(SharedTrafficState, [u8; 16])>,
    auth: VlessAuthenticatedClient,
    destination: String,
    command: VlessCommand,
}

struct VlessUdpRelayPrepared<S> {
    stream: S,
    udp: Option<Arc<tokio::net::UdpSocket>>,
    target: Option<std::net::SocketAddr>,
    blackhole: bool,
    initial_payload: Vec<u8>,
    auth: VlessAuthenticatedClient,
    destination: String,
    command: VlessCommand,
}

struct VlessMuxRelayPrepared<S> {
    stream: S,
    vision: Option<(SharedTrafficState, [u8; 16])>,
    auth: VlessAuthenticatedClient,
    initial_payload: Vec<u8>,
    version: u8,
}

enum VlessRelayPrepared<S> {
    Tcp(VlessTcpRelayPrepared<S>),
    Udp(VlessUdpRelayPrepared<S>),
    Mux(VlessMuxRelayPrepared<S>),
    Blackhole,
    Commander,
}

async fn prepare_reality_vless_relay<S>(
    stream: RealityTls13ApplicationStream<S>,
    auth_ctx: &VlessInboundAuthContext,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
) -> std::io::Result<(
    VlessRelayPrepared<RealityTls13ApplicationStream<S>>,
    Option<StatsConnection>,
)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    prepare_reality_vless_relay_with_hook(stream, auth_ctx, socket_meta, router, || async {
        Ok(())
    })
    .await
}

async fn prepare_reality_vless_relay_with_hook<S, F, Fut>(
    mut stream: RealityTls13ApplicationStream<S>,
    auth_ctx: &VlessInboundAuthContext,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
    on_ready_to_respond: F,
) -> std::io::Result<(
    VlessRelayPrepared<RealityTls13ApplicationStream<S>>,
    Option<StatsConnection>,
)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let inbound = match read_vless_request(&mut stream).await {
        Err(err) if useless_record_overflow_limit(&err).is_some() => {
            let _ = stream.send_useless_overflow_fatal_alert().await;
            return Err(stage_error(RealityAcceptedStage::Vless, err));
        }
        other => other.map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?,
    };

    prepare_vless_relay_from_inbound(
        stream,
        Some(auth_ctx),
        None,
        None,
        socket_meta,
        router,
        inbound,
        on_ready_to_respond,
    )
    .await
}

async fn prepare_vless_relay_with_router<S>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
) -> std::io::Result<(VlessRelayPrepared<S>, Option<StatsConnection>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    prepare_vless_relay_with_hook_and_router(
        stream,
        None,
        Some(users),
        stats_state,
        socket_meta,
        router,
        || async { Ok(()) },
    )
    .await
}

async fn prepare_vless_relay_with_hook<S, F, Fut>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
    on_ready_to_respond: F,
) -> std::io::Result<(VlessRelayPrepared<S>, Option<StatsConnection>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    prepare_vless_relay_with_hook_and_router(
        stream,
        None,
        Some(users),
        stats_state,
        socket_meta,
        router,
        on_ready_to_respond,
    )
    .await
}

async fn prepare_vless_relay_with_hook_and_router<S, F, Fut>(
    stream: S,
    auth_ctx: Option<&VlessInboundAuthContext>,
    users: Option<&VlessUserManager>,
    stats_state: Option<&StatsState>,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
    on_ready_to_respond: F,
) -> std::io::Result<(VlessRelayPrepared<S>, Option<StatsConnection>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let mut stream = stream;
    let inbound = read_vless_request(&mut stream)
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    prepare_vless_relay_from_inbound(
        stream,
        auth_ctx,
        users,
        stats_state,
        socket_meta,
        router,
        inbound,
        on_ready_to_respond,
    )
    .await
}

async fn prepare_vless_relay_from_inbound<S, F, Fut>(
    mut stream: S,
    auth_ctx: Option<&VlessInboundAuthContext>,
    users: Option<&VlessUserManager>,
    legacy_stats: Option<&StatsState>,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
    inbound: VlessInboundRequest,
    on_ready_to_respond: F,
) -> std::io::Result<(VlessRelayPrepared<S>, Option<StatsConnection>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let vless_started = Instant::now();
    enum AuthenticatedUsers<'a> {
        Shared(Arc<VlessUserManager>),
        Local(&'a VlessUserManager),
    }

    let (users, auth) = if let Some(auth_ctx) = auth_ctx {
        let (manager, auth) = auth_ctx
            .authenticate(&inbound.request)
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
        (AuthenticatedUsers::Shared(manager), auth)
    } else {
        let users = users.ok_or_else(|| {
            stage_error(
                RealityAcceptedStage::Vless,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "vless auth source missing",
                ),
            )
        })?;
        let auth = authenticate_vless_client(&inbound.request, users)
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
        (AuthenticatedUsers::Local(users), auth)
    };

    let users_ref: &VlessUserManager = match &users {
        AuthenticatedUsers::Shared(manager) => manager.as_ref(),
        AuthenticatedUsers::Local(manager) => manager,
    };

    let stats_state = if let Some(auth_ctx) = auth_ctx {
        auth_ctx.stats_for(&auth.inbound_tag)
    } else {
        legacy_stats.cloned().map(Arc::new)
    };
    debug!(
        stage = stages::VLESS_AUTH_OK,
        duration_ms = vless_started.elapsed().as_millis(),
        user_id = %auth.id,
        inbound_tag = %auth.inbound_tag,
        command = ?inbound.request.command,
        "VLESS auth completed"
    );
    let stats = stats_state.as_ref().and_then(|state| {
        state
            .session(auth.email.clone(), auth.level, socket_meta.source_ip)
            .map(StatsConnection::open)
    });
    let destination = format_vless_destination(&inbound.request.destination);

    let request_flow = parse_vless_request_flow(&inbound.request.additional_info);
    if let Err(err) = validate_vless_flow_for_command(
        request_flow.as_deref(),
        auth.flow.as_deref(),
        inbound.request.command,
    ) {
        warn!(
            request_flow = request_flow.as_deref().unwrap_or(""),
            account_flow = auth.flow.as_deref().unwrap_or(""),
            inbound_tag = %auth.inbound_tag,
            user_lookup_result = "matched",
            user_id_hint = user_id_hint(&auth.id),
            flow_distribution = %users_ref.flow_distribution_log_label(),
            error = %err,
            "VLESS flow mismatch"
        );
        return Err(stage_error(RealityAcceptedStage::Vless, err));
    }

    let vision_enabled =
        is_vision_flow(request_flow.as_deref()) && is_vision_flow(auth.flow.as_deref());
    let user_uuid = *auth.id.as_bytes();
    let raw_initial_payload = inbound.initial_payload;
    let mut initial_payload = raw_initial_payload.clone();
    let mut vision = None;

    if vision_enabled {
        let traffic = new_shared_traffic_state(user_uuid);
        initial_payload = {
            let mut state = traffic.lock().expect("vision traffic lock");
            state.unpad_uplink_chunk(&raw_initial_payload)?
        };
        vision = Some((traffic, user_uuid));
        debug!(
            stage = stages::VLESS_AUTH_OK,
            user_id = %auth.id,
            request_flow = request_flow.as_deref(),
            "vision enabled for vless tcp"
        );
    }

    log_vless_request_diagnostics(
        inbound.request.version,
        inbound.request.additional_info.len(),
        &raw_initial_payload,
        &initial_payload,
    );

    debug!(
        stage = stages::VLESS_AUTH_OK,
        user_id = %auth.id,
        email = auth.email.as_deref(),
        flow = auth.flow.as_deref(),
        request_flow = request_flow.as_deref(),
        command = ?inbound.request.command,
        %destination,
        "VLESS client authenticated"
    );

    if inbound.request.command == VlessCommand::Mux {
        on_ready_to_respond()
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

        prepare_vless_tcp_response(&mut stream, inbound.request.version)
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

        return Ok((
            VlessRelayPrepared::Mux(VlessMuxRelayPrepared {
                stream,
                vision,
                auth,
                initial_payload,
                version: inbound.request.version,
            }),
            stats,
        ));
    }

    if inbound.request.command == VlessCommand::Udp {
        if looks_like_xudp_request(&inbound.request.additional_info) {
            return Err(stage_error(
                RealityAcceptedStage::Vless,
                unsupported_vless_command_error(
                    inbound.request.command,
                    &inbound.request.additional_info,
                ),
            ));
        }

        let mut udp_socket = None;
        let mut udp_target = None;
        let mut blackhole = false;

        if let Some(router) = router {
            let route_ctx = crate::routing::route_context_from_vless(
                &auth.inbound_tag,
                &auth,
                &inbound.request.destination,
                &initial_payload,
                socket_meta,
                users_ref.sniffing_enabled(),
                NetworkKind::Udp,
            );
            match router.pick_route_with_default(route_ctx).await {
                Ok(decision) => {
                    router.publish_route(&decision);
                    debug!(
                        stage = stages::VLESS_AUTH_OK,
                        outbound_tag = %decision.outbound_tag,
                        rule_tag = %decision.rule_tag,
                        %destination,
                        "VLESS UDP route selected"
                    );
                    let outbound_manager = router.outbound_manager();
                    if outbound_manager.is_commander_outbound(&decision.outbound_tag) {
                        return Err(stage_error(
                            RealityAcceptedStage::Vless,
                            std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "commander outbound does not support native VLESS UDP",
                            ),
                        ));
                    }
                    match connect_routed_outbound(
                        &decision.outbound_tag,
                        &inbound.request.destination,
                        outbound_manager,
                        OutboundConnectRuntime::shared(),
                        NetworkKind::Udp,
                    )
                    .await
                    {
                        Ok(crate::routing::RoutedOutbound::Udp { socket, target }) => {
                            udp_socket = Some(Arc::new(socket));
                            udp_target = Some(target);
                        }
                        Ok(crate::routing::RoutedOutbound::Blackhole) => {
                            blackhole = true;
                        }
                        Ok(crate::routing::RoutedOutbound::Tcp(_)) => {
                            return Err(stage_error(
                                RealityAcceptedStage::Vless,
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "freedom TCP outbound selected for VLESS UDP request",
                                ),
                            ));
                        }
                        Err(err) => return Err(stage_error(RealityAcceptedStage::Vless, err)),
                    }
                }
                Err(err) => {
                    return Err(stage_error(
                        RealityAcceptedStage::Vless,
                        std::io::Error::other(err.to_string()),
                    ));
                }
            }
        } else {
            let (socket, target) = connect_udp_destination_with_runtime(
                &inbound.request.destination,
                OutboundConnectRuntime::shared(),
            )
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
            udp_socket = Some(Arc::new(socket));
            udp_target = Some(target);
        }

        debug!(
            stage = stages::VLESS_OUTBOUND_CONNECTED,
            %destination,
            blackhole,
            "VLESS outbound UDP ready"
        );

        on_ready_to_respond()
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

        prepare_vless_tcp_response(&mut stream, inbound.request.version)
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

        return Ok((
            VlessRelayPrepared::Udp(VlessUdpRelayPrepared {
                stream,
                udp: udp_socket,
                target: udp_target,
                blackhole,
                initial_payload,
                auth,
                destination,
                command: inbound.request.command,
            }),
            stats,
        ));
    }

    if inbound.request.command != VlessCommand::Tcp {
        return Err(stage_error(
            RealityAcceptedStage::Vless,
            unsupported_vless_command_error(
                inbound.request.command,
                &inbound.request.additional_info,
            ),
        ));
    }

    let mut outbound = if let Some(router) = router {
        let route_ctx = crate::routing::route_context_from_vless(
            &auth.inbound_tag,
            &auth,
            &inbound.request.destination,
            &initial_payload,
            socket_meta,
            users_ref.sniffing_enabled(),
            NetworkKind::Tcp,
        );
        match router.pick_route_with_default(route_ctx).await {
            Ok(decision) => {
                router.publish_route(&decision);
                debug!(
                    stage = stages::VLESS_AUTH_OK,
                    outbound_tag = %decision.outbound_tag,
                    rule_tag = %decision.rule_tag,
                    %destination,
                    "VLESS route selected"
                );
                let outbound_manager = router.outbound_manager();
                if outbound_manager.is_commander_outbound(&decision.outbound_tag) {
                    on_ready_to_respond()
                        .await
                        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
                    prepare_vless_tcp_response(&mut stream, inbound.request.version)
                        .await
                        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
                    if !initial_payload.is_empty() {
                        log_outbound_stream_first_write(&initial_payload);
                        stream
                            .write_all(&initial_payload)
                            .await
                            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
                        if let Some(stats) = stats.as_ref() {
                            stats.record_uplink(initial_payload.len() as u64);
                        }
                    }
                    let listener = outbound_manager.commander_listener().ok_or_else(|| {
                        stage_error(
                            RealityAcceptedStage::Vless,
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "commander outbound listener is not active",
                            ),
                        )
                    })?;
                    if !listener.try_push_io(stream) {
                        return Err(stage_error(
                            RealityAcceptedStage::Vless,
                            std::io::Error::new(
                                std::io::ErrorKind::WouldBlock,
                                "commander outbound connection queue full",
                            ),
                        ));
                    }
                    return Ok((VlessRelayPrepared::Commander, stats));
                }
                match connect_routed_outbound(
                    &decision.outbound_tag,
                    &inbound.request.destination,
                    router.outbound_manager(),
                    OutboundConnectRuntime::shared(),
                    NetworkKind::Tcp,
                )
                .await
                {
                    Ok(crate::routing::RoutedOutbound::Tcp(stream)) => stream,
                    Ok(crate::routing::RoutedOutbound::Udp { .. }) => {
                        return Err(stage_error(
                            RealityAcceptedStage::Vless,
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "freedom UDP outbound selected for VLESS TCP request",
                            ),
                        ));
                    }
                    Ok(crate::routing::RoutedOutbound::Blackhole) => {
                        on_ready_to_respond()
                            .await
                            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
                        prepare_vless_tcp_response(&mut stream, inbound.request.version)
                            .await
                            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
                        return Ok((VlessRelayPrepared::Blackhole, stats));
                    }
                    Err(err) => return Err(stage_error(RealityAcceptedStage::Vless, err)),
                }
            }
            Err(err) => {
                return Err(stage_error(
                    RealityAcceptedStage::Vless,
                    std::io::Error::other(err.to_string()),
                ));
            }
        }
    } else {
        connect_tcp_destination(&inbound.request.destination)
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?
    };

    debug!(
        stage = stages::VLESS_OUTBOUND_CONNECTED,
        %destination,
        "VLESS outbound TCP connected"
    );

    on_ready_to_respond()
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    prepare_vless_tcp_response(&mut stream, inbound.request.version)
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    if !initial_payload.is_empty() {
        log_outbound_stream_first_write(&initial_payload);
        forward_tcp_initial_payload(&mut outbound, &initial_payload)
            .await
            .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
        if let Some(stats) = stats.as_ref() {
            stats.record_uplink(initial_payload.len() as u64);
        }
        debug!(
            stage = stages::VLESS_INITIAL_PAYLOAD_FORWARDED,
            initial_payload_len = initial_payload.len(),
            "forwarded VLESS initial payload to outbound"
        );
    }

    Ok((
        VlessRelayPrepared::Tcp(VlessTcpRelayPrepared {
            stream,
            outbound,
            vision,
            auth,
            destination,
            command: inbound.request.command,
        }),
        stats,
    ))
}

struct VlessTcpRelayFinished {
    auth: VlessAuthenticatedClient,
    destination: String,
    command: VlessCommand,
}

fn finish_vless_tcp_relay(
    finished: VlessTcpRelayFinished,
    relay_result: std::io::Result<(u64, u64)>,
    stats: Option<&StatsConnection>,
    relay_started: Instant,
) -> std::io::Result<()> {
    let (inbound_to_outbound, outbound_to_inbound) =
        relay_result.map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    if let Some(stats) = stats {
        stats.record_relay(inbound_to_outbound, outbound_to_inbound);
    }

    debug!(
        stage = stages::VLESS_RELAY_DONE,
        email = finished.auth.email.as_deref(),
        flow = finished.auth.flow.as_deref(),
        command = ?finished.command,
        destination = %finished.destination,
        duration_ms = relay_started.elapsed().as_millis(),
        inbound_to_outbound,
        outbound_to_inbound,
        "vless relay completed"
    );

    info!(
        stage = stages::VLESS_RELAY_DONE,
        email = finished.auth.email.as_deref(),
        flow = finished.auth.flow.as_deref(),
        command = ?finished.command,
        destination = %finished.destination,
        inbound_to_outbound,
        outbound_to_inbound,
        "VLESS TCP relay completed"
    );

    Ok(())
}

struct VlessUdpRelayFinished {
    auth: VlessAuthenticatedClient,
    destination: String,
    command: VlessCommand,
}

fn finish_vless_udp_relay(
    finished: VlessUdpRelayFinished,
    relay_result: std::io::Result<(u64, u64)>,
    stats: Option<&StatsConnection>,
    relay_started: Instant,
) -> std::io::Result<()> {
    let (uplink, downlink) =
        relay_result.map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    if let Some(stats) = stats {
        stats.record_relay(uplink, downlink);
    }

    debug!(
        stage = stages::VLESS_RELAY_DONE,
        email = finished.auth.email.as_deref(),
        flow = finished.auth.flow.as_deref(),
        command = ?finished.command,
        destination = %finished.destination,
        duration_ms = relay_started.elapsed().as_millis(),
        uplink,
        downlink,
        "vless udp relay completed"
    );

    info!(
        stage = stages::VLESS_RELAY_DONE,
        email = finished.auth.email.as_deref(),
        flow = finished.auth.flow.as_deref(),
        command = ?finished.command,
        destination = %finished.destination,
        uplink,
        downlink,
        "VLESS UDP relay completed"
    );

    Ok(())
}

async fn run_prepared_udp_relay<S>(
    prepared: VlessUdpRelayPrepared<S>,
    stats: Option<&StatsConnection>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(
        stage = stages::VLESS_RELAY_STARTED,
        "VLESS UDP relay started"
    );
    let VlessUdpRelayPrepared {
        stream,
        udp,
        target,
        blackhole,
        initial_payload,
        auth,
        destination,
        command,
    } = prepared;
    let relay_started = Instant::now();
    let relay_result = relay_vless_udp_bidirectional(
        stream,
        udp,
        target,
        blackhole,
        initial_payload,
        stats,
        VlessUdpRelayOptions::from_env(),
    )
    .await;
    finish_vless_udp_relay(
        VlessUdpRelayFinished {
            auth,
            destination,
            command,
        },
        relay_result,
        stats,
        relay_started,
    )
}

async fn run_prepared_reality_udp_relay<S>(
    prepared: VlessUdpRelayPrepared<RealityTls13ApplicationStream<S>>,
    stats: Option<&StatsConnection>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(
        stage = stages::VLESS_RELAY_STARTED,
        "VLESS UDP relay started"
    );
    let VlessUdpRelayPrepared {
        stream,
        udp,
        target,
        blackhole,
        initial_payload,
        auth,
        destination,
        command,
    } = prepared;
    let RealityTls13RelaySplit { reader, writer, .. } = stream.split_for_relay()?;
    let relay_started = Instant::now();
    let relay_result = relay_vless_udp_split_with_overflow_alert(
        reader,
        writer,
        udp,
        target,
        blackhole,
        initial_payload,
        stats,
        VlessUdpRelayOptions::from_env(),
    )
    .await;
    finish_vless_udp_relay(
        VlessUdpRelayFinished {
            auth,
            destination,
            command,
        },
        relay_result,
        stats,
        relay_started,
    )
}

pub async fn handle_vless_tcp_inbound<S>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    source_ip: Option<IpAddr>,
    router: Option<&Arc<RuntimeRouter>>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let socket_meta = RouteSocketMeta {
        source_ip,
        ..Default::default()
    };
    handle_vless_tcp_inbound_with_socket_meta(stream, users, stats_state, &socket_meta, router)
        .await
}

pub async fn handle_vless_tcp_inbound_with_auth_context<S>(
    stream: S,
    auth_ctx: &VlessInboundAuthContext,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (prepared, stats) = prepare_vless_relay_with_hook_and_router(
        stream,
        Some(auth_ctx),
        None,
        None,
        socket_meta,
        router,
        || async { Ok(()) },
    )
    .await?;

    let prepared = match prepared {
        VlessRelayPrepared::Blackhole => return Ok(()),
        VlessRelayPrepared::Commander => return Ok(()),
        VlessRelayPrepared::Mux(prepared) => {
            let sniffing = auth_ctx
                .auth_set()
                .get_manager(&prepared.auth.inbound_tag)
                .map(|manager| manager.sniffing_enabled())
                .unwrap_or(false);
            let route_env = mux_route_env(
                router,
                &prepared.auth,
                prepared.vision.is_some(),
                stats.as_ref(),
                socket_meta,
                sniffing,
            );
            return run_prepared_mux_relay(prepared, None, stats.as_ref(), None, route_env).await;
        }
        VlessRelayPrepared::Udp(prepared) => {
            return run_prepared_udp_relay(prepared, stats.as_ref()).await;
        }
        VlessRelayPrepared::Tcp(prepared) => prepared,
    };

    info!(
        stage = stages::VLESS_RELAY_STARTED,
        "VLESS TCP relay started"
    );

    let VlessTcpRelayPrepared {
        stream,
        mut outbound,
        vision,
        auth,
        destination,
        command,
    } = prepared;

    let relay_started = Instant::now();
    let relay_result =
        relay_vless_tcp_bidirectional(stream, &mut outbound, vision, None, stats.as_ref()).await;

    finish_vless_tcp_relay(
        VlessTcpRelayFinished {
            auth,
            destination,
            command,
        },
        relay_result,
        stats.as_ref(),
        relay_started,
    )
}

pub async fn handle_vless_tcp_inbound_with_socket_meta<S>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (prepared, stats) =
        prepare_vless_relay_with_router(stream, users, stats_state, socket_meta, router).await?;

    let prepared = match prepared {
        VlessRelayPrepared::Blackhole => return Ok(()),
        VlessRelayPrepared::Commander => return Ok(()),
        VlessRelayPrepared::Mux(prepared) => {
            let route_env = mux_route_env(
                router,
                &prepared.auth,
                prepared.vision.is_some(),
                stats.as_ref(),
                socket_meta,
                users.sniffing_enabled(),
            );
            return run_prepared_mux_relay(prepared, None, stats.as_ref(), None, route_env).await;
        }
        VlessRelayPrepared::Udp(prepared) => {
            return run_prepared_udp_relay(prepared, stats.as_ref()).await;
        }
        VlessRelayPrepared::Tcp(prepared) => prepared,
    };

    info!(
        stage = stages::VLESS_RELAY_STARTED,
        "VLESS TCP relay started"
    );

    let VlessTcpRelayPrepared {
        stream,
        mut outbound,
        vision,
        auth,
        destination,
        command,
    } = prepared;

    let relay_started = Instant::now();
    let relay_result =
        relay_vless_tcp_bidirectional(stream, &mut outbound, vision, None, stats.as_ref()).await;

    finish_vless_tcp_relay(
        VlessTcpRelayFinished {
            auth,
            destination,
            command,
        },
        relay_result,
        stats.as_ref(),
        relay_started,
    )
}

pub async fn handle_vless_tcp_inbound_with_response_hook<S, F, Fut>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    source_ip: Option<IpAddr>,
    router: Option<&Arc<RuntimeRouter>>,
    on_ready_to_respond: F,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let socket_meta = RouteSocketMeta {
        source_ip,
        ..Default::default()
    };
    handle_vless_tcp_inbound_with_socket_meta_and_response_hook(
        stream,
        users,
        stats_state,
        &socket_meta,
        router,
        on_ready_to_respond,
    )
    .await
}

pub async fn handle_vless_tcp_inbound_with_socket_meta_and_response_hook<S, F, Fut>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
    on_ready_to_respond: F,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let (prepared, stats) = prepare_vless_relay_with_hook(
        stream,
        users,
        stats_state,
        socket_meta,
        router,
        on_ready_to_respond,
    )
    .await?;

    let prepared = match prepared {
        VlessRelayPrepared::Blackhole => return Ok(()),
        VlessRelayPrepared::Commander => return Ok(()),
        VlessRelayPrepared::Tcp(prepared) => prepared,
        VlessRelayPrepared::Mux(prepared) => {
            let route_env = mux_route_env(
                router,
                &prepared.auth,
                prepared.vision.is_some(),
                stats.as_ref(),
                socket_meta,
                users.sniffing_enabled(),
            );
            return run_prepared_mux_relay(prepared, None, stats.as_ref(), None, route_env).await;
        }
        VlessRelayPrepared::Udp(prepared) => {
            return run_prepared_udp_relay(prepared, stats.as_ref()).await;
        }
    };

    info!(
        stage = stages::VLESS_RELAY_STARTED,
        "VLESS TCP relay started"
    );

    let VlessTcpRelayPrepared {
        stream,
        mut outbound,
        vision,
        auth,
        destination,
        command,
    } = prepared;

    let relay_started = Instant::now();
    let relay_result =
        relay_vless_tcp_bidirectional(stream, &mut outbound, vision, None, stats.as_ref()).await;

    finish_vless_tcp_relay(
        VlessTcpRelayFinished {
            auth,
            destination,
            command,
        },
        relay_result,
        stats.as_ref(),
        relay_started,
    )
}

async fn prepare_reality_vless_relay_legacy<S>(
    stream: RealityTls13ApplicationStream<S>,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
) -> std::io::Result<(
    VlessRelayPrepared<RealityTls13ApplicationStream<S>>,
    Option<StatsConnection>,
)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = stream;
    let inbound = match read_vless_request(&mut stream).await {
        Err(err) if useless_record_overflow_limit(&err).is_some() => {
            let _ = stream.send_useless_overflow_fatal_alert().await;
            return Err(stage_error(RealityAcceptedStage::Vless, err));
        }
        other => other.map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?,
    };
    prepare_vless_relay_from_inbound(
        stream,
        None,
        Some(users),
        stats_state,
        socket_meta,
        router,
        inbound,
        || async { Ok(()) },
    )
    .await
}

pub async fn handle_reality_vless_tcp_inbound<S>(
    stream: RealityTls13ApplicationStream<S>,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_reality_vless_tcp_inbound_traced(
        stream,
        None,
        Some(users),
        stats_state,
        None,
        &RouteSocketMeta::default(),
        None,
    )
    .await
}

pub async fn handle_reality_vless_tcp_inbound_traced<S>(
    stream: RealityTls13ApplicationStream<S>,
    auth_ctx: Option<&VlessInboundAuthContext>,
    users: Option<&VlessUserManager>,
    stats_state: Option<&StatsState>,
    mux_trace: Option<MuxSessionTrace>,
    socket_meta: &RouteSocketMeta,
    router: Option<&Arc<RuntimeRouter>>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (prepared, stats) = if let Some(auth_ctx) = auth_ctx {
        prepare_reality_vless_relay(stream, auth_ctx, socket_meta, router).await?
    } else {
        prepare_reality_vless_relay_legacy(
            stream,
            users.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "vless auth source missing",
                )
            })?,
            stats_state,
            socket_meta,
            router,
        )
        .await?
    };

    let prepared = match prepared {
        VlessRelayPrepared::Blackhole => return Ok(()),
        VlessRelayPrepared::Commander => return Ok(()),
        VlessRelayPrepared::Tcp(prepared) => prepared,
        VlessRelayPrepared::Mux(prepared) => {
            let sniffing = if let Some(auth_ctx) = auth_ctx {
                auth_ctx
                    .auth_set()
                    .get_manager(&prepared.auth.inbound_tag)
                    .map(|manager| manager.sniffing_enabled())
                    .unwrap_or(false)
            } else {
                users
                    .map(VlessUserManager::sniffing_enabled)
                    .unwrap_or(false)
            };
            let route_env = mux_route_env(
                router,
                &prepared.auth,
                prepared.vision.is_some(),
                stats.as_ref(),
                socket_meta,
                sniffing,
            );
            return run_prepared_reality_mux_relay(prepared, stats.as_ref(), mux_trace, route_env)
                .await;
        }
        VlessRelayPrepared::Udp(prepared) => {
            return run_prepared_reality_udp_relay(prepared, stats.as_ref()).await;
        }
    };

    info!(
        stage = stages::VLESS_RELAY_STARTED,
        "VLESS TCP relay started"
    );

    let VlessTcpRelayPrepared {
        stream,
        outbound,
        vision,
        auth,
        destination,
        command,
    } = prepared;

    let RealityTls13RelaySplit {
        reader,
        writer,
        direct_relay,
    } = stream.split_for_relay()?;
    let relay_started = Instant::now();
    let relay_result = if let Some((traffic, user_uuid)) = vision {
        let vision_reader = VisionRelayReader::new(reader, Arc::clone(&traffic));
        let vision_writer =
            VisionRelayWriter::new(writer, traffic, user_uuid, Some(direct_relay.clone()));
        relay_split_bidirectional_with_overflow_alert(vision_reader, vision_writer, outbound).await
    } else {
        relay_tls13_split_bidirectional(reader, writer, outbound).await
    };

    finish_vless_tcp_relay(
        VlessTcpRelayFinished {
            auth,
            destination,
            command,
        },
        relay_result,
        stats.as_ref(),
        relay_started,
    )
}

async fn run_reality_split_mux_inbound<R, W>(
    mux_stream: &mut SplitMuxInbound<R, W>,
    mux_trace: Option<MuxSessionTrace>,
    route_env: Option<MuxRouteEnv>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + crate::reality::tls13::Tls13OverflowAlertWriter,
{
    let result = handle_mux_cool_inbound_with_env(
        mux_stream,
        crate::dns::DnsEngine::shared(),
        mux_trace,
        route_env,
    )
    .await;
    if let Err(err) = result {
        if useless_record_overflow_limit(&err).is_some() {
            let _ = mux_stream.send_useless_overflow_fatal_alert().await;
        }
        return Err(err);
    }
    Ok(())
}

async fn run_prepared_reality_mux_relay<S>(
    prepared: VlessMuxRelayPrepared<RealityTls13ApplicationStream<S>>,
    _stats: Option<&StatsConnection>,
    mux_trace: Option<MuxSessionTrace>,
    route_env: Option<MuxRouteEnv>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(
        stage = stages::VLESS_RELAY_STARTED,
        email = prepared.auth.email.as_deref(),
        flow = prepared.auth.flow.as_deref(),
        command = ?VlessCommand::Mux,
        version = prepared.version,
        "VLESS mux relay started"
    );

    let mux_started = Instant::now();
    let RealityTls13RelaySplit {
        reader,
        writer,
        direct_relay,
    } = prepared.stream.split_for_relay()?;

    let mux_result = if let Some((traffic, user_uuid)) = prepared.vision {
        let mut mux_stream = SplitMuxInbound::new(
            VisionRelayReader::new(reader, Arc::clone(&traffic)),
            VisionRelayWriter::new(writer, traffic, user_uuid, Some(direct_relay)),
            prepared.initial_payload,
        );
        run_reality_split_mux_inbound(&mut mux_stream, mux_trace, route_env.clone()).await
    } else {
        let mut mux_stream = SplitMuxInbound::new(reader, writer, prepared.initial_payload);
        run_reality_split_mux_inbound(&mut mux_stream, mux_trace, route_env).await
    };

    mux_result.map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    debug!(
        stage = stages::VLESS_RELAY_DONE,
        email = prepared.auth.email.as_deref(),
        flow = prepared.auth.flow.as_deref(),
        command = ?VlessCommand::Mux,
        duration_ms = mux_started.elapsed().as_millis(),
        "vless mux relay completed"
    );
    info!(
        stage = stages::VLESS_RELAY_DONE,
        email = prepared.auth.email.as_deref(),
        flow = prepared.auth.flow.as_deref(),
        command = ?VlessCommand::Mux,
        "VLESS mux relay completed"
    );

    Ok(())
}

async fn run_prepared_mux_relay<S>(
    prepared: VlessMuxRelayPrepared<S>,
    direct_relay: Option<ApplicationStreamDirectRelay>,
    _stats: Option<&StatsConnection>,
    mux_trace: Option<MuxSessionTrace>,
    route_env: Option<MuxRouteEnv>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(
        stage = stages::VLESS_RELAY_STARTED,
        email = prepared.auth.email.as_deref(),
        flow = prepared.auth.flow.as_deref(),
        command = ?VlessCommand::Mux,
        version = prepared.version,
        "VLESS mux relay started"
    );

    let mux_started = Instant::now();
    let result = if let Some((traffic, user_uuid)) = prepared.vision {
        let vision_stream =
            VisionRelayStream::new(prepared.stream, traffic, user_uuid, direct_relay);
        let mut prefixed = PrefixedStream::new(vision_stream, prepared.initial_payload);
        handle_mux_cool_inbound_with_env(
            &mut prefixed,
            crate::dns::DnsEngine::shared(),
            mux_trace,
            route_env,
        )
        .await
    } else {
        let mut prefixed = PrefixedStream::new(prepared.stream, prepared.initial_payload);
        handle_mux_cool_inbound_with_env(
            &mut prefixed,
            crate::dns::DnsEngine::shared(),
            mux_trace,
            route_env,
        )
        .await
    };

    result.map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    debug!(
        stage = stages::VLESS_RELAY_DONE,
        email = prepared.auth.email.as_deref(),
        flow = prepared.auth.flow.as_deref(),
        command = ?VlessCommand::Mux,
        duration_ms = mux_started.elapsed().as_millis(),
        "vless mux relay completed"
    );
    info!(
        stage = stages::VLESS_RELAY_DONE,
        email = prepared.auth.email.as_deref(),
        flow = prepared.auth.flow.as_deref(),
        command = ?VlessCommand::Mux,
        "VLESS mux relay completed"
    );

    Ok(())
}

fn mux_route_env(
    router: Option<&Arc<RuntimeRouter>>,
    auth: &VlessAuthenticatedClient,
    vision_mux_udp_only: bool,
    stats: Option<&StatsConnection>,
    socket_meta: &RouteSocketMeta,
    sniffing_enabled: bool,
) -> Option<MuxRouteEnv> {
    router.map(|router| MuxRouteEnv {
        router: Arc::clone(router),
        inbound_tag: auth.inbound_tag.clone(),
        auth: auth.clone(),
        socket_meta: socket_meta.clone(),
        sniffing_enabled,
        vision_mux_udp_only,
        stats: stats.map(|connection| connection.session().clone()),
        xudp: XudpManager::shared(),
        #[cfg(test)]
        test_dispatch_counter: None,
    })
}

/// Placeholder entry point for future VLESS inbound handling.
pub async fn handle_vless_inbound<S>(stream: S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _ = stream;

    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "VLESS inbound is not implemented yet",
    ))
}

#[cfg(test)]
#[path = "../../tests/unit/vless/inbound.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/vless/inbound_read_vless_request_tests.rs"]
mod read_vless_request_tests;

#[cfg(test)]
#[path = "../../tests/unit/vless/inbound_handle_vless_tcp_inbound_tests.rs"]
mod handle_vless_tcp_inbound_tests;
