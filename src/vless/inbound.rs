use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

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
use crate::vless::protocol::{
    encode_vless_response_header, parse_vless_request, VlessCommand, VlessRequest,
};
use crate::vless::relay_debug::{
    log_outbound_stream_first_write, log_outbound_to_client_first_write,
    log_vless_request_diagnostics, log_vless_response_header_prefix,
};
use crate::vless::user_manager::{VlessAuthenticatedClient, VlessUserManager};
use crate::vless::vision::{
    is_vision_flow, new_shared_traffic_state, parse_vless_request_flow, SharedTrafficState,
    VisionRelayStream, FLOW_XTLS_RPRX_VISION,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::info;

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
        info!(
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
        info!("vision direct relay completed");
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

async fn prepare_vless_tcp_relay<S>(
    mut stream: S,
    users: &VlessUserManager,
    stats_state: Option<&StatsState>,
) -> std::io::Result<(VlessTcpRelayPrepared<S>, Option<StatsSession>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let inbound = read_vless_request(&mut stream)
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    let auth = authenticate_vless_client(&inbound.request, users)
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
    let stats = stats_state.and_then(|state| state.session(auth.email.clone(), auth.level));
    let destination = format_vless_destination(&inbound.request.destination);

    let request_flow = parse_vless_request_flow(&inbound.request.additional_info);
    validate_vless_flow_for_command(
        request_flow.as_deref(),
        auth.flow.as_deref(),
        inbound.request.command,
    )
    .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

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
        info!(
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

    info!(
        stage = stages::VLESS_AUTH_OK,
        user_id = %auth.id,
        email = auth.email.as_deref(),
        flow = auth.flow.as_deref(),
        request_flow = request_flow.as_deref(),
        command = ?inbound.request.command,
        %destination,
        "VLESS client authenticated"
    );

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

    info!(
        stage = stages::VLESS_OUTBOUND_CONNECTED,
        %destination,
        "VLESS outbound TCP connected"
    );

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
        info!(
            stage = stages::VLESS_INITIAL_PAYLOAD_FORWARDED,
            initial_payload_len = initial_payload.len(),
            "forwarded VLESS initial payload to outbound"
        );
    }

    Ok((
        VlessTcpRelayPrepared {
            stream,
            outbound,
            vision,
            auth,
            destination,
            command: inbound.request.command,
        },
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
) -> std::io::Result<()> {
    let (inbound_to_outbound, outbound_to_inbound) =
        relay_result.map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    if let Some(stats) = stats {
        stats.record_relay(inbound_to_outbound, outbound_to_inbound);
    }

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
    let (prepared, stats) = prepare_vless_tcp_relay(stream, users, stats_state).await?;

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
    let (prepared, stats) = prepare_vless_tcp_relay(stream, users, stats_state).await?;

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
    )
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
mod tests {
    use super::*;
    use crate::vless::config::VlessClient;
    use crate::vless::protocol::{VlessCommand, VlessDestination};
    use std::net::{IpAddr, Ipv4Addr};

    const USER_ID: uuid::Uuid =
        uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    const UNKNOWN_ID: uuid::Uuid =
        uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    fn vless_client(email: Option<&str>, flow: Option<&str>) -> VlessClient {
        VlessClient {
            id: USER_ID,
            email: email.map(str::to_string),
            flow: flow.map(str::to_string),
            level: None,
        }
    }

    fn test_users(clients: Vec<VlessClient>) -> VlessUserManager {
        VlessUserManager::new("test-in", clients)
    }

    fn vless_request(user_id: uuid::Uuid) -> VlessRequest {
        VlessRequest {
            version: 0,
            user_id,
            command: VlessCommand::Tcp,
            destination: VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            additional_info: Vec::new(),
        }
    }

    #[test]
    fn authenticate_vless_client_known_uuid() {
        let users = test_users(vec![vless_client(
            Some("user@example.com"),
            Some("xtls-rprx-vision"),
        )]);
        let request = vless_request(USER_ID);

        let auth = authenticate_vless_client(&request, &users).unwrap();

        assert_eq!(auth.id, USER_ID);
        assert_eq!(auth.email.as_deref(), Some("user@example.com"));
        assert_eq!(auth.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn authenticate_vless_client_unknown_uuid_is_permission_denied() {
        let users = test_users(vec![vless_client(None, None)]);
        let request = vless_request(UNKNOWN_ID);

        let err = authenticate_vless_client(&request, &users).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn authenticate_vless_client_flow_none_ok() {
        let users = test_users(vec![vless_client(Some("user@example.com"), None)]);
        let request = vless_request(USER_ID);

        authenticate_vless_client(&request, &users).unwrap();
    }

    #[test]
    fn authenticate_vless_client_flow_empty_ok() {
        let users = test_users(vec![vless_client(Some("user@example.com"), Some(""))]);
        let request = vless_request(USER_ID);

        authenticate_vless_client(&request, &users).unwrap();
    }

    #[test]
    fn authenticate_vless_client_flow_vision_ok() {
        let users = test_users(vec![vless_client(None, Some("xtls-rprx-vision"))]);
        let request = vless_request(USER_ID);

        authenticate_vless_client(&request, &users).unwrap();
    }

    #[test]
    fn authenticate_vless_client_unsupported_flow_is_unsupported() {
        let users = test_users(vec![vless_client(None, Some("xtls-rprx-direct"))]);
        let request = vless_request(USER_ID);

        let err = authenticate_vless_client(&request, &users).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), "unsupported VLESS flow: xtls-rprx-direct");
    }

    #[test]
    fn is_supported_vless_flow_accepts_none_empty_and_vision() {
        assert!(is_supported_vless_flow(None));
        assert!(is_supported_vless_flow(Some("")));
        assert!(is_supported_vless_flow(Some("xtls-rprx-vision")));
        assert!(!is_supported_vless_flow(Some("xtls-rprx-direct")));
    }

    #[test]
    fn validate_flow_rejects_empty_account_with_vision_request() {
        let err = validate_vless_flow_for_command(
            Some(FLOW_XTLS_RPRX_VISION),
            Some(""),
            VlessCommand::Tcp,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn validate_flow_rejects_vision_account_with_empty_request() {
        let err =
            validate_vless_flow_for_command(None, Some(FLOW_XTLS_RPRX_VISION), VlessCommand::Tcp)
                .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn validate_flow_rejects_vision_udp() {
        let err = validate_vless_flow_for_command(
            Some(FLOW_XTLS_RPRX_VISION),
            Some(FLOW_XTLS_RPRX_VISION),
            VlessCommand::Udp,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("UDP"));
    }

    #[test]
    fn validate_flow_rejects_unknown_flow() {
        let err = validate_vless_flow_for_command(
            Some("xtls-rprx-direct"),
            Some("xtls-rprx-direct"),
            VlessCommand::Tcp,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn validate_flow_empty_regression_unchanged() {
        validate_vless_flow_for_command(None, None, VlessCommand::Tcp).unwrap();
        validate_vless_flow_for_command(Some(""), Some(""), VlessCommand::Tcp).unwrap();
    }
}

#[cfg(test)]
mod read_vless_request_tests {
    use super::*;
    use crate::vless::protocol::{VlessCommand, VlessDestination};
    use std::future::Future;
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    const USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    fn build_vless_request_bytes(
        additional_info: &[u8],
        command: u8,
        port: u16,
        address: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(&USER_ID);
        buf.push(additional_info.len() as u8);
        buf.extend_from_slice(additional_info);
        buf.push(command);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(address);
        buf
    }

    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
        index: usize,
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.index >= self.chunks.len() {
                return Poll::Ready(Ok(()));
            }

            let chunk = &self.chunks[self.index];
            buf.put_slice(chunk);
            self.index += 1;
            Poll::Ready(Ok(()))
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    #[test]
    fn read_vless_request_header_only_has_empty_initial_payload() {
        let data = build_vless_request_bytes(&[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
        let mut cursor = std::io::Cursor::new(data);

        let inbound = block_on(read_vless_request(&mut cursor)).unwrap();

        assert!(inbound.initial_payload.is_empty());
        assert_eq!(inbound.request.command, VlessCommand::Tcp);
        assert_eq!(
            inbound.request.destination,
            VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)
        );
    }

    #[test]
    fn read_vless_request_preserves_initial_payload() {
        let mut data = build_vless_request_bytes(&[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
        data.extend_from_slice(b"POST / HTTP/1.1\r\n");
        let mut cursor = std::io::Cursor::new(data);

        let inbound = block_on(read_vless_request(&mut cursor)).unwrap();

        assert_eq!(inbound.initial_payload, b"POST / HTTP/1.1\r\n");
    }

    #[test]
    fn read_vless_request_reads_incrementally() {
        let header = build_vless_request_bytes(&[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
        let payload = b"hello";
        let mut data = header.clone();
        data.extend_from_slice(payload);

        let split_at = header.len() - 5;
        let mut reader = ChunkedReader {
            chunks: vec![data[..split_at].to_vec(), data[split_at..].to_vec()],
            index: 0,
        };

        let inbound = block_on(read_vless_request(&mut reader)).unwrap();

        assert_eq!(inbound.initial_payload, payload);
    }

    #[test]
    fn read_vless_request_truncated_header_is_unexpected_eof() {
        let mut data = build_vless_request_bytes(&[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
        data.truncate(10);
        let mut cursor = std::io::Cursor::new(data);

        let err = block_on(read_vless_request(&mut cursor)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_vless_request_over_limit_header_is_invalid_data() {
        let mut data = build_vless_request_bytes(&[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
        data.truncate(10);
        data.resize(20, 0);

        let mut cursor = std::io::Cursor::new(data);
        let err = block_on(read_vless_request_with_limit(&mut cursor, 20)).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("20"));
    }
}

#[cfg(test)]
mod handle_vless_tcp_inbound_tests {
    use super::*;
    use crate::vless::config::VlessClient;
    use crate::vless::user_manager::VlessUserManager;
    use std::future::Future;
    use std::io::ErrorKind;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    const UNKNOWN_USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];

    fn build_vless_request_bytes(user_id: &[u8; 16], command: u8, port: u16) -> Vec<u8> {
        build_vless_request_with_addons(user_id, &[], command, port)
    }

    fn build_vless_request_with_addons(
        user_id: &[u8; 16],
        addons: &[u8],
        command: u8,
        port: u16,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(user_id);
        buf.push(addons.len() as u8);
        buf.extend_from_slice(addons);
        buf.push(command);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(&[0x01, 127, 0, 0, 1]);
        buf
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    fn test_clients() -> Vec<VlessClient> {
        vec![VlessClient {
            id: uuid::Uuid::from_bytes(USER_ID),
            email: Some("user@example.com".to_string()),
            flow: None,
            level: None,
        }]
    }

    fn test_users() -> VlessUserManager {
        VlessUserManager::new("test-in", test_clients())
    }

    #[test]
    fn handle_vless_tcp_inbound_udp_command_is_unsupported() {
        let data = build_vless_request_bytes(&USER_ID, 0x02, 443);
        let cursor = std::io::Cursor::new(data);

        let err = block_on(handle_vless_tcp_inbound(cursor, &test_users(), None)).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("UDP unsupported"));
    }

    #[test]
    fn handle_vless_tcp_inbound_mux_command_is_unsupported() {
        let data = build_vless_request_bytes(&USER_ID, 0x03, 443);
        let cursor = std::io::Cursor::new(data);

        let err = block_on(handle_vless_tcp_inbound(cursor, &test_users(), None)).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("Mux unsupported"));
    }

    #[test]
    fn handle_vless_tcp_inbound_xudp_marker_addons_are_rejected() {
        let data = build_vless_request_with_addons(&USER_ID, b"xudp", 0x02, 443);
        let cursor = std::io::Cursor::new(data);

        let err = block_on(handle_vless_tcp_inbound(cursor, &test_users(), None)).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("XUDP unsupported"));
    }

    #[test]
    fn handle_vless_tcp_inbound_unknown_client_is_permission_denied() {
        let data = build_vless_request_bytes(&UNKNOWN_USER_ID, 0x01, 443);
        let cursor = std::io::Cursor::new(data);

        let err = block_on(handle_vless_tcp_inbound(cursor, &test_users(), None)).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn handle_vless_tcp_inbound_writes_response_header_before_outbound_bytes() {
        block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind outbound listener");
            let outbound_port = listener.local_addr().expect("local addr").port();
            let outbound_response = [0x16, 0x03, 0x03, 0x00, 0x05, 0x02];

            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept outbound");
                socket
                    .write_all(&outbound_response)
                    .await
                    .expect("write outbound response");
            });

            let (mut client_io, server_io) = duplex(8192);
            let request = build_vless_request_bytes(&USER_ID, 0x01, outbound_port);
            client_io
                .write_all(&request)
                .await
                .expect("send vless request");

            let users = test_users();
            let handle =
                tokio::spawn(
                    async move { handle_vless_tcp_inbound(server_io, &users, None).await },
                );

            let mut received = [0u8; 16];
            let read = client_io
                .read(&mut received)
                .await
                .expect("read client response");
            assert!(read >= 2);
            assert_eq!(
                &received[..2],
                encode_vless_response_header(0, None).as_slice()
            );

            if read > 2 {
                assert_eq!(received[2], outbound_response[0]);
            } else {
                let read_more = client_io
                    .read(&mut received[2..])
                    .await
                    .expect("read outbound relay bytes");
                assert!(read_more > 0);
                assert_eq!(received[2], outbound_response[0]);
            }

            handle.abort();
        });
    }

    #[test]
    fn prepare_vless_tcp_response_writes_header_to_client_stream() {
        block_on(async {
            let (mut client_io, mut server_io) = duplex(256);
            prepare_vless_tcp_response(&mut server_io, 0)
                .await
                .expect("write response header");

            let mut received = [0u8; 8];
            let read = client_io
                .read(&mut received)
                .await
                .expect("read response header");
            assert_eq!(read, 2);
            assert_eq!(
                &received[..2],
                encode_vless_response_header(0, None).as_slice()
            );
        });
    }

    #[test]
    fn handle_vless_tcp_inbound_unpads_vision_initial_payload() {
        use crate::vless::vision::{encode_vision_flow_addons_protobuf, wrap_vision_uplink_block};
        use std::sync::{Arc, Mutex};

        block_on(async {
            let user_id = [0x11; 16];
            let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02];
            let vision_payload = wrap_vision_uplink_block(&user_id, &tls_client_hello);
            let outbound_response = [0x16, 0x03, 0x03, 0x00, 0x05, 0x02];

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind outbound listener");
            let outbound_port = listener.local_addr().expect("local addr").port();
            let outbound_received = Arc::new(Mutex::new(Vec::new()));
            let outbound_received_task = Arc::clone(&outbound_received);

            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept outbound");
                let mut buf = [0u8; 512];
                let n = socket.read(&mut buf).await.expect("read initial payload");
                outbound_received_task
                    .lock()
                    .expect("lock outbound capture")
                    .extend_from_slice(&buf[..n]);
                socket
                    .write_all(&outbound_response)
                    .await
                    .expect("write outbound response");
            });

            let (mut client_io, server_io) = duplex(8192);
            let addons = encode_vision_flow_addons_protobuf();
            let mut request =
                build_vless_request_with_addons(&user_id, &addons, 0x01, outbound_port);
            request.extend_from_slice(&vision_payload);
            client_io
                .write_all(&request)
                .await
                .expect("send vless request");

            let users = VlessUserManager::new(
                "test-in",
                vec![VlessClient {
                    id: uuid::Uuid::from_bytes(user_id),
                    email: Some("user@example.com".to_string()),
                    flow: Some("xtls-rprx-vision".to_string()),
                    level: None,
                }],
            );

            let handle =
                tokio::spawn(
                    async move { handle_vless_tcp_inbound(server_io, &users, None).await },
                );

            let mut received = [0u8; 32];
            let read = client_io
                .read(&mut received)
                .await
                .expect("read client response header");
            assert!(read >= 2);

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            assert_eq!(
                *outbound_received.lock().expect("lock outbound capture"),
                tls_client_hello.to_vec()
            );

            handle.abort();
        });
    }

    #[test]
    fn empty_flow_existing_smoke_path_not_changed() {
        block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind outbound listener");
            let outbound_port = listener.local_addr().expect("local addr").port();

            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept outbound");
                let _ = socket.write_all(b"ok").await;
            });

            let (mut client_io, server_io) = duplex(8192);
            let request = build_vless_request_bytes(&USER_ID, 0x01, outbound_port);
            client_io
                .write_all(&request)
                .await
                .expect("send vless request");

            let handle = tokio::spawn(async move {
                handle_vless_tcp_inbound(server_io, &test_users(), None).await
            });

            let mut received = [0u8; 8];
            let read = client_io.read(&mut received).await.expect("read response");
            assert!(read >= 2);
            handle.abort();
        });
    }

    #[test]
    fn handle_vless_tcp_inbound_forwards_initial_payload_once_after_response_header() {
        use std::sync::{Arc, Mutex};

        block_on(async {
            let initial_payload = b"CLIENT-TLS-CLIENTHELLO-BYTES";
            let outbound_response = [0x16, 0x03, 0x03, 0x00, 0x05, 0x02];

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind outbound listener");
            let outbound_port = listener.local_addr().expect("local addr").port();
            let expected_initial_payload = initial_payload.to_vec();
            let outbound_received = Arc::new(Mutex::new(Vec::new()));
            let outbound_received_task = Arc::clone(&outbound_received);

            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept outbound");
                let mut buf = [0u8; 512];
                let n = socket.read(&mut buf).await.expect("read initial payload");
                outbound_received_task
                    .lock()
                    .expect("lock outbound capture")
                    .extend_from_slice(&buf[..n]);
                socket
                    .write_all(&outbound_response)
                    .await
                    .expect("write outbound response");
            });

            let (mut client_io, server_io) = duplex(8192);
            let mut request = build_vless_request_bytes(&USER_ID, 0x01, outbound_port);
            request.extend_from_slice(initial_payload);
            client_io
                .write_all(&request)
                .await
                .expect("send vless request");

            let handle = tokio::spawn(async move {
                handle_vless_tcp_inbound(server_io, &test_users(), None).await
            });

            let mut received = [0u8; 32];
            let read = client_io
                .read(&mut received)
                .await
                .expect("read client response header");
            assert!(read >= 2);
            assert_eq!(
                &received[..2],
                encode_vless_response_header(0, None).as_slice()
            );

            if read <= 2 {
                let read_more = client_io
                    .read(&mut received[read..])
                    .await
                    .expect("read outbound relay bytes");
                assert!(read_more > 0);
                assert_eq!(received[read], outbound_response[0]);
            } else {
                assert_eq!(received[2], outbound_response[0]);
            }

            assert_eq!(
                *outbound_received.lock().expect("lock outbound capture"),
                expected_initial_payload
            );

            handle.abort();
        });
    }
}
