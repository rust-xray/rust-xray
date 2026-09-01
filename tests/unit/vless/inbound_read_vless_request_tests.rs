use super::*;
use crate::vless::policy::VlessInboundPolicy;
use crate::vless::protocol::{VlessCommand, VlessDestination};
use std::future::Future;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

const USER_ID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
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

struct StalledReader;

impl AsyncRead for StalledReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[tokio::test]
async fn read_vless_request_handshake_timeout_on_stalled_header() {
    let policy = VlessInboundPolicy {
        handshake_timeout: Duration::from_millis(50),
    };
    let mut reader = StalledReader;
    let err = read_vless_request_with_policy(&mut reader, policy)
        .await
        .expect_err("stalled header should time out");
    assert_eq!(err.kind(), ErrorKind::TimedOut);
}

#[tokio::test]
async fn read_vless_request_completes_before_handshake_deadline() {
    let data = build_vless_request_bytes(&[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
    let mut cursor = std::io::Cursor::new(data);
    let policy = VlessInboundPolicy {
        handshake_timeout: Duration::from_secs(2),
    };
    read_vless_request_with_policy(&mut cursor, policy)
        .await
        .expect("accepted before deadline");
}
