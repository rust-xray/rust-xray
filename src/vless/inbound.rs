use std::io::ErrorKind;

use crate::outbound::freedom::{connect_tcp_destination, format_vless_destination, relay_tcp};
use crate::vless::config::VlessClient;
use crate::vless::protocol::{parse_vless_request, VlessCommand, VlessRequest};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
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
    match flow {
        None => true,
        Some("") => true,
        Some("xtls-rprx-vision") => true,
        _ => false,
    }
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

pub async fn handle_vless_tcp_inbound<S>(
    stream: &mut S,
    clients: &[VlessClient],
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let inbound = read_vless_request(stream).await?;
    let auth = authenticate_vless_client(&inbound.request, clients)?;
    let destination = format_vless_destination(&inbound.request.destination);

    info!(
        user_id = %auth.id,
        email = auth.email.as_deref(),
        flow = auth.flow.as_deref(),
        command = ?inbound.request.command,
        %destination,
        "vless client authenticated"
    );

    if inbound.request.command != VlessCommand::Tcp {
        return Err(std::io::Error::new(
            ErrorKind::Unsupported,
            format!("unsupported vless command: {:?}", inbound.request.command),
        ));
    }

    // TODO: implement exact VLESS response header semantics.

    let mut outbound = connect_tcp_destination(&inbound.request.destination).await?;

    let (inbound_to_outbound, outbound_to_inbound) =
        relay_tcp(stream, &mut outbound, &inbound.initial_payload).await?;

    info!(
        email = auth.email.as_deref(),
        flow = auth.flow.as_deref(),
        command = ?inbound.request.command,
        %destination,
        inbound_to_outbound,
        outbound_to_inbound,
        "vless tcp inbound relay completed"
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

    const USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    const UNKNOWN_USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];

    fn build_vless_request_bytes(user_id: &[u8; 16], command: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0);
        buf.extend_from_slice(user_id);
        buf.push(0);
        buf.push(command);
        buf.extend_from_slice(&443u16.to_be_bytes());
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
        let data = build_vless_request_bytes(&USER_ID, 0x02);
        let mut cursor = std::io::Cursor::new(data);

        let err = block_on(handle_vless_tcp_inbound(&mut cursor, &test_clients())).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn handle_vless_tcp_inbound_unknown_client_is_permission_denied() {
        let data = build_vless_request_bytes(&UNKNOWN_USER_ID, 0x01);
        let mut cursor = std::io::Cursor::new(data);

        let err = block_on(handle_vless_tcp_inbound(&mut cursor, &test_clients())).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }
}
