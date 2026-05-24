use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::outbound::freedom::{
    connect_tcp_destination, format_vless_destination, forward_tcp_initial_payload,
    relay_tcp_bidirectional,
};
use crate::reality::stages::{self, stage_error, RealityAcceptedStage};
use crate::reality::tls13::{RealityTls13ApplicationStream, RealityTls13RelayClient};
use crate::vless::config::VlessClient;
use crate::vless::protocol::{
    encode_vless_response_header, parse_vless_request, VlessCommand, VlessRequest,
};
use crate::vless::relay_debug::{
    log_outbound_stream_first_write, log_outbound_to_client_first_write,
    log_vless_request_diagnostics, log_vless_response_header_prefix,
};
use crate::vless::vision::{
    is_vision_client_flow, unsupported_vision_relay_error, vision_direct_copy_relay_supported,
    VisionUnpadState,
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

#[derive(Debug, Clone)]
pub struct VlessAuthenticatedClient {
    pub id: uuid::Uuid,
    pub email: Option<String>,
    pub flow: Option<String>,
}

pub fn is_supported_vless_flow(flow: Option<&str>) -> bool {
    matches!(flow, None | Some("") | Some("xtls-rprx-vision"))
}

pub fn authenticate_vless_client(
    request: &VlessRequest,
    clients: &[VlessClient],
) -> std::io::Result<VlessAuthenticatedClient> {
    let client = clients
        .iter()
        .find(|client| client.id == request.user_id)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unknown vless client id",
            )
        })?;

    if !is_supported_vless_flow(client.flow.as_deref()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "unsupported vless flow {:?}",
                client.flow.as_deref().unwrap_or("")
            ),
        ));
    }

    Ok(VlessAuthenticatedClient {
        id: client.id,
        email: client.email.clone(),
        flow: client.flow.clone(),
    })
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

struct VisionUplinkReader<S> {
    inner: S,
    state: VisionUnpadState,
    pending: Vec<u8>,
}

impl<S> VisionUplinkReader<S> {
    fn new(inner: S, state: VisionUnpadState) -> Self {
        Self {
            inner,
            state,
            pending: Vec::new(),
        }
    }
}

impl<S> AsyncRead for VisionUplinkReader<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let to_copy = self.pending.len().min(buf.remaining());
                buf.put_slice(&self.pending[..to_copy]);
                self.pending.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }

            if !self.state.within_padding() {
                return Pin::new(&mut self.inner).poll_read(cx, buf);
            }

            let mut chunk = [0u8; 4096];
            let mut read_buf = tokio::io::ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(())) => match self.state.unpad(read_buf.filled()) {
                    Ok(unpadded) if unpadded.is_empty() => continue,
                    Ok(unpadded) => {
                        let to_copy = unpadded.len().min(buf.remaining());
                        buf.put_slice(&unpadded[..to_copy]);
                        self.pending.extend_from_slice(&unpadded[to_copy..]);
                        return Poll::Ready(Ok(()));
                    }
                    Err(err) => return Poll::Ready(Err(err)),
                },
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for VisionUplinkReader<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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
    vision_state: Option<VisionUnpadState>,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let probed_client = RelayClientWriteProbe::new(client_stream);
    if let Some(state) = vision_state {
        let vision_client = VisionUplinkReader::new(probed_client, state);
        relay_tcp_bidirectional(vision_client, outbound).await
    } else {
        relay_tcp_bidirectional(probed_client, outbound).await
    }
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
    vision_state: Option<VisionUnpadState>,
    auth: VlessAuthenticatedClient,
    destination: String,
    command: VlessCommand,
}

async fn prepare_vless_tcp_relay<S>(
    mut stream: S,
    clients: &[VlessClient],
) -> std::io::Result<VlessTcpRelayPrepared<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let inbound = read_vless_request(&mut stream)
        .await
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

    let auth = authenticate_vless_client(&inbound.request, clients)
        .map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;
    let destination = format_vless_destination(&inbound.request.destination);

    if is_vision_client_flow(auth.flow.as_deref()) && !vision_direct_copy_relay_supported() {
        return Err(stage_error(
            RealityAcceptedStage::Vless,
            unsupported_vision_relay_error(),
        ));
    }

    let raw_initial_payload = inbound.initial_payload;
    let initial_payload = raw_initial_payload.clone();
    let vision_state = None;

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
        command = ?inbound.request.command,
        %destination,
        "VLESS client authenticated"
    );

    if inbound.request.command != VlessCommand::Tcp {
        return Err(stage_error(
            RealityAcceptedStage::Vless,
            std::io::Error::new(
                ErrorKind::Unsupported,
                format!("unsupported vless command: {:?}", inbound.request.command),
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
        info!(
            stage = stages::VLESS_INITIAL_PAYLOAD_FORWARDED,
            initial_payload_len = initial_payload.len(),
            "forwarded VLESS initial payload to outbound"
        );
    }

    Ok(VlessTcpRelayPrepared {
        stream,
        outbound,
        vision_state,
        auth,
        destination,
        command: inbound.request.command,
    })
}

struct VlessTcpRelayFinished {
    auth: VlessAuthenticatedClient,
    destination: String,
    command: VlessCommand,
}

fn finish_vless_tcp_relay(
    finished: VlessTcpRelayFinished,
    relay_result: std::io::Result<(u64, u64)>,
) -> std::io::Result<()> {
    let (inbound_to_outbound, outbound_to_inbound) =
        relay_result.map_err(|err| stage_error(RealityAcceptedStage::Vless, err))?;

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

pub async fn handle_vless_tcp_inbound<S>(stream: S, clients: &[VlessClient]) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let prepared = prepare_vless_tcp_relay(stream, clients).await?;

    info!(
        stage = stages::VLESS_RELAY_STARTED,
        "VLESS TCP relay started"
    );

    let VlessTcpRelayPrepared {
        stream,
        mut outbound,
        vision_state,
        auth,
        destination,
        command,
    } = prepared;

    let relay_result = relay_vless_tcp_bidirectional(stream, &mut outbound, vision_state).await;

    finish_vless_tcp_relay(
        VlessTcpRelayFinished {
            auth,
            destination,
            command,
        },
        relay_result,
    )
}

pub async fn handle_reality_vless_tcp_inbound(
    stream: RealityTls13ApplicationStream<tokio::net::TcpStream>,
    clients: &[VlessClient],
) -> std::io::Result<()> {
    let prepared = prepare_vless_tcp_relay(stream, clients).await?;

    info!(
        stage = stages::VLESS_RELAY_STARTED,
        "VLESS TCP relay started"
    );

    let VlessTcpRelayPrepared {
        stream,
        mut outbound,
        vision_state,
        auth,
        destination,
        command,
    } = prepared;

    let (reader, writer) = stream.split_for_relay()?;
    let relay = RealityTls13RelayClient::new(reader, writer);
    let relay_result = relay_vless_tcp_bidirectional(relay, &mut outbound, vision_state).await;

    finish_vless_tcp_relay(
        VlessTcpRelayFinished {
            auth,
            destination,
            command,
        },
        relay_result,
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
        }
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
        let clients = vec![vless_client(
            Some("user@example.com"),
            Some("xtls-rprx-vision"),
        )];
        let request = vless_request(USER_ID);

        let auth = authenticate_vless_client(&request, &clients).unwrap();

        assert_eq!(auth.id, USER_ID);
        assert_eq!(auth.email.as_deref(), Some("user@example.com"));
        assert_eq!(auth.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn authenticate_vless_client_unknown_uuid_is_permission_denied() {
        let clients = vec![vless_client(None, None)];
        let request = vless_request(UNKNOWN_ID);

        let err = authenticate_vless_client(&request, &clients).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn authenticate_vless_client_flow_none_ok() {
        let clients = vec![vless_client(Some("user@example.com"), None)];
        let request = vless_request(USER_ID);

        authenticate_vless_client(&request, &clients).unwrap();
    }

    #[test]
    fn authenticate_vless_client_flow_empty_ok() {
        let clients = vec![vless_client(Some("user@example.com"), Some(""))];
        let request = vless_request(USER_ID);

        authenticate_vless_client(&request, &clients).unwrap();
    }

    #[test]
    fn authenticate_vless_client_flow_vision_ok() {
        let clients = vec![vless_client(None, Some("xtls-rprx-vision"))];
        let request = vless_request(USER_ID);

        authenticate_vless_client(&request, &clients).unwrap();
    }

    #[test]
    fn authenticate_vless_client_unsupported_flow_is_invalid_input() {
        let clients = vec![vless_client(None, Some("xtls-rprx-direct"))];
        let request = vless_request(USER_ID);

        let err = authenticate_vless_client(&request, &clients).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn is_supported_vless_flow_accepts_none_empty_and_vision() {
        assert!(is_supported_vless_flow(None));
        assert!(is_supported_vless_flow(Some("")));
        assert!(is_supported_vless_flow(Some("xtls-rprx-vision")));
        assert!(!is_supported_vless_flow(Some("xtls-rprx-direct")));
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
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(user_id);
        buf.push(0);
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
        }]
    }

    #[test]
    fn handle_vless_tcp_inbound_udp_command_is_unsupported() {
        let data = build_vless_request_bytes(&USER_ID, 0x02, 443);
        let mut cursor = std::io::Cursor::new(data);

        let err = block_on(handle_vless_tcp_inbound(cursor, &test_clients())).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn handle_vless_tcp_inbound_unknown_client_is_permission_denied() {
        let data = build_vless_request_bytes(&UNKNOWN_USER_ID, 0x01, 443);
        let mut cursor = std::io::Cursor::new(data);

        let err = block_on(handle_vless_tcp_inbound(cursor, &test_clients())).unwrap_err();

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

            let (mut client_io, mut server_io) = duplex(8192);
            let request = build_vless_request_bytes(&USER_ID, 0x01, outbound_port);
            client_io
                .write_all(&request)
                .await
                .expect("send vless request");

            let clients = test_clients();
            let handle =
                tokio::spawn(async move { handle_vless_tcp_inbound(server_io, &clients).await });

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
    fn handle_vless_tcp_inbound_rejects_vision_flow_before_relay() {
        use crate::vless::vision::wrap_vision_uplink_block;

        block_on(async {
            let user_id = [0x11; 16];
            let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02];
            let vision_payload = wrap_vision_uplink_block(&user_id, &tls_client_hello);

            let (mut client_io, server_io) = duplex(8192);
            let mut request = build_vless_request_bytes(&user_id, 0x01, 443);
            request.extend_from_slice(&vision_payload);
            client_io
                .write_all(&request)
                .await
                .expect("send vless request");

            let clients = vec![VlessClient {
                id: uuid::Uuid::from_bytes(user_id),
                email: Some("user@example.com".to_string()),
                flow: Some("xtls-rprx-vision".to_string()),
            }];

            let err = handle_vless_tcp_inbound(server_io, &clients)
                .await
                .expect_err("vision flow should be rejected before relay");
            assert_eq!(err.kind(), ErrorKind::Unsupported);
            assert!(err.to_string().contains("xtls-rprx-vision not implemented"));
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

            let (mut client_io, mut server_io) = duplex(8192);
            let mut request = build_vless_request_bytes(&USER_ID, 0x01, outbound_port);
            request.extend_from_slice(initial_payload);
            client_io
                .write_all(&request)
                .await
                .expect("send vless request");

            let handle =
                tokio::spawn(
                    async move { handle_vless_tcp_inbound(server_io, &test_clients()).await },
                );

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
