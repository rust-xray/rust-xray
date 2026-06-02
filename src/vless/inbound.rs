use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::mux::{handle_mux_cool_inbound, handle_mux_cool_inbound_traced, MuxSessionTrace};
use crate::outbound::freedom::{
    connect_tcp_destination, format_vless_destination, forward_tcp_initial_payload,
    relay_tcp_bidirectional,
};
use crate::reality::stages::{self, stage_error, RealityAcceptedStage};
use crate::reality::tls13::{
    ApplicationStreamDirectRelay, RealityTls13ApplicationStream, RealityTls13RelayClient,
    RealityTls13RelaySplit,
};
use crate::stats::{StatsSession, StatsState};
use crate::tls::PrefixedStream;
use crate::vless::protocol::{
    encode_vless_response_header, parse_vless_request, VlessCommand, VlessRequest,
};
use crate::vless::relay_debug::{
    log_outbound_stream_first_write, log_outbound_to_client_first_write,
    log_vless_request_diagnostics, log_vless_response_header_prefix,
};
use crate::vless::user_manager::{user_id_hint, VlessAuthenticatedClient, VlessUserManager};
use crate::vless::vision::{
    is_vision_flow, new_shared_traffic_state, parse_vless_request_flow, SharedTrafficState,
    VisionRelayStream, FLOW_XTLS_RPRX_VISION,
};
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
    _stats: Option<&StatsSession>,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
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

struct VlessMuxRelayPrepared<S> {
    stream: S,
    vision: Option<(SharedTrafficState, [u8; 16])>,
    auth: VlessAuthenticatedClient,
    initial_payload: Vec<u8>,
    version: u8,
}

enum VlessRelayPrepared<S> {
    Tcp(VlessTcpRelayPrepared<S>),
    Mux(VlessMuxRelayPrepared<S>),
}

async fn prepare_vless_relay<S>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> std::io::Result<(VlessRelayPrepared<S>, Option<StatsSession>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    prepare_vless_relay_with_hook(stream, users, stats_state, || async { Ok(()) }).await
}

async fn prepare_vless_relay_with_hook<S, F, Fut>(
    mut stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    on_ready_to_respond: F,
) -> std::io::Result<(VlessRelayPrepared<S>, Option<StatsSession>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let vless_started = Instant::now();
    let inbound = read_vless_request(&mut stream)
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    let auth = authenticate_vless_client(&inbound.request, users)
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
    debug!(
        stage = stages::VLESS_AUTH_OK,
        duration_ms = vless_started.elapsed().as_millis(),
        user_id = %auth.id,
        command = ?inbound.request.command,
        "VLESS auth completed"
    );
    let stats = stats_state.and_then(|state| state.session(auth.email.clone(), auth.level));
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
            inbound_tag = users.inbound_tag(),
            user_lookup_result = "matched",
            user_id_hint = user_id_hint(&auth.id),
            flow_distribution = %users.flow_distribution_log_label(),
            error = %err,
            "VLESS flow mismatch"
        );
        return Err(stage_error(RealityAcceptedStage::Vless, err));
    }

    if let Some(stats) = stats.as_ref() {
        stats.ensure_registered();
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

    if inbound.request.command != VlessCommand::Tcp {
        return Err(stage_error(
            RealityAcceptedStage::Vless,
            unsupported_vless_command_error(
                inbound.request.command,
                &inbound.request.additional_info,
            ),
        ));
    }

    let mut outbound = connect_tcp_destination(&inbound.request.destination)
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

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
    stats: Option<&StatsSession>,
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

pub async fn handle_vless_tcp_inbound<S>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (prepared, stats) = prepare_vless_relay(stream, users, stats_state).await?;

    let prepared = match prepared {
        VlessRelayPrepared::Tcp(prepared) => prepared,
        VlessRelayPrepared::Mux(prepared) => {
            return run_prepared_mux_relay(prepared, None, stats.as_ref(), None).await;
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

pub async fn handle_vless_tcp_inbound_with_response_hook<S, F, Fut>(
    stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    on_ready_to_respond: F,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    let (prepared, stats) =
        prepare_vless_relay_with_hook(stream, users, stats_state, on_ready_to_respond).await?;

    let prepared = match prepared {
        VlessRelayPrepared::Tcp(prepared) => prepared,
        VlessRelayPrepared::Mux(prepared) => {
            return run_prepared_mux_relay(prepared, None, stats.as_ref(), None).await;
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

pub async fn handle_reality_vless_tcp_inbound<S>(
    stream: RealityTls13ApplicationStream<S>,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_reality_vless_tcp_inbound_traced(stream, users, stats_state, None).await
}

pub async fn handle_reality_vless_tcp_inbound_traced<S>(
    stream: RealityTls13ApplicationStream<S>,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
    mux_trace: Option<MuxSessionTrace>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (prepared, stats) = prepare_vless_relay(stream, users, stats_state).await?;

    let prepared = match prepared {
        VlessRelayPrepared::Tcp(prepared) => prepared,
        VlessRelayPrepared::Mux(prepared) => {
            return run_prepared_mux_relay(prepared, None, stats.as_ref(), mux_trace).await;
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

    let RealityTls13RelaySplit {
        reader,
        writer,
        direct_relay,
    } = stream.split_for_relay()?;
    let relay = RealityTls13RelayClient::new(reader, writer, direct_relay.clone());
    let relay_started = Instant::now();
    let relay_result = relay_vless_tcp_bidirectional(
        relay,
        &mut outbound,
        vision,
        Some(direct_relay),
        stats.as_ref(),
    )
    .await;

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

async fn run_prepared_mux_relay<S>(
    prepared: VlessMuxRelayPrepared<S>,
    direct_relay: Option<ApplicationStreamDirectRelay>,
    _stats: Option<&StatsSession>,
    mux_trace: Option<MuxSessionTrace>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
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
        let prefixed = PrefixedStream::new(vision_stream, prepared.initial_payload);
        if let Some(trace) = mux_trace {
            handle_mux_cool_inbound_traced(prefixed, trace).await
        } else {
            handle_mux_cool_inbound(prefixed).await
        }
    } else {
        let prefixed = PrefixedStream::new(prepared.stream, prepared.initial_payload);
        if let Some(trace) = mux_trace {
            handle_mux_cool_inbound_traced(prefixed, trace).await
        } else {
            handle_mux_cool_inbound(prefixed).await
        }
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
