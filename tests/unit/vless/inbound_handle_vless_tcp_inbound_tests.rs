use super::*;
use crate::vless::config::VlessClient;
use crate::vless::user_manager::VlessUserManager;
use std::future::Future;
use std::io::ErrorKind;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const USER_ID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

const UNKNOWN_USER_ID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
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

    let err = block_on(handle_vless_tcp_inbound(
        cursor,
        &test_users(),
        None,
        None,
        None,
    ))
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.to_string().contains("UDP unsupported"));
}

fn build_vless_mux_request_bytes(user_id: &[u8; 16], initial_payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(0);
    buf.push(0x03);
    buf.extend_from_slice(initial_payload);
    buf
}

#[test]
fn handle_vless_tcp_inbound_mux_command_is_not_rejected_as_unsupported() {
    let data = build_vless_mux_request_bytes(&USER_ID, &[]);
    let cursor = std::io::Cursor::new(data);

    block_on(handle_vless_tcp_inbound(
        cursor,
        &test_users(),
        None,
        None,
        None,
    ))
    .unwrap();
}

#[test]
fn handle_vless_tcp_inbound_mux_single_tcp_substream_roundtrip() {
    use crate::mux::{
        encode_mux_new_tcp, read_mux_frame, MuxCommand, MuxFrame, MuxOption, MuxStatus,
    };
    use crate::vless::protocol::VlessDestination;
    use std::net::{IpAddr, Ipv4Addr};

    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind outbound listener");
        let outbound_port = listener.local_addr().expect("local addr").port();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept outbound");
            let mut received = [0u8; 4];
            socket
                .read_exact(&mut received)
                .await
                .expect("read outbound payload");
            assert_eq!(&received, b"PING");
            socket.write_all(b"PONG").await.expect("write response");
            socket.shutdown().await.expect("shutdown outbound");
        });

        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), outbound_port);
        let mux_open = encode_mux_new_tcp(1, &destination, b"PING");
        let request = build_vless_mux_request_bytes(&USER_ID, &mux_open);
        let (mut client_io, server_io) = duplex(8192);
        client_io
            .write_all(&request)
            .await
            .expect("send mux vless request");

        let users = test_users();
        let handle = tokio::spawn(async move {
            handle_vless_tcp_inbound(server_io, &users, None, None, None).await
        });

        let mut response_header = [0u8; 2];
        client_io
            .read_exact(&mut response_header)
            .await
            .expect("read vless response header");
        assert_eq!(
            response_header,
            encode_vless_response_header(0, None).as_slice()
        );

        let frame = read_mux_frame(&mut client_io)
            .await
            .expect("read mux response");
        assert_eq!(
            frame,
            MuxFrame {
                mux_id: 1,
                status: MuxStatus::Keep,
                option: MuxOption { has_data: true },
                command: MuxCommand::Data {
                    payload: b"PONG".to_vec()
                }
            }
        );

        let frame = read_mux_frame(&mut client_io).await.expect("read mux end");
        assert_eq!(
            frame,
            MuxFrame {
                mux_id: 1,
                status: MuxStatus::End,
                option: MuxOption { has_data: false },
                command: MuxCommand::Close {
                    payload: Vec::new()
                }
            }
        );

        drop(client_io);
        handle.await.expect("join mux handler").unwrap();
    });
}

#[test]
fn handle_vless_tcp_inbound_xudp_marker_addons_are_rejected() {
    let data = build_vless_request_with_addons(&USER_ID, b"xudp", 0x02, 443);
    let cursor = std::io::Cursor::new(data);

    let err = block_on(handle_vless_tcp_inbound(
        cursor,
        &test_users(),
        None,
        None,
        None,
    ))
    .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.to_string().contains("XUDP unsupported"));
}

#[test]
fn handle_vless_tcp_inbound_unknown_client_is_permission_denied() {
    let data = build_vless_request_bytes(&UNKNOWN_USER_ID, 0x01, 443);
    let cursor = std::io::Cursor::new(data);

    let err = block_on(handle_vless_tcp_inbound(
        cursor,
        &test_users(),
        None,
        None,
        None,
    ))
    .unwrap_err();

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
        let handle = tokio::spawn(async move {
            handle_vless_tcp_inbound(server_io, &users, None, None, None).await
        });

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
        let mut request = build_vless_request_with_addons(&user_id, &addons, 0x01, outbound_port);
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

        let handle = tokio::spawn(async move {
            handle_vless_tcp_inbound(server_io, &users, None, None, None).await
        });

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
            handle_vless_tcp_inbound(server_io, &test_users(), None, None, None).await
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
            handle_vless_tcp_inbound(server_io, &test_users(), None, None, None).await
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
