use super::*;
use crate::dns::config::parse_dns_server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn example_query() -> Vec<u8> {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    packet.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    packet
}

fn example_response() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

#[tokio::test]
async fn stack_queries_udp_server() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    let expected_query = example_query();
    let expected_response = example_response();
    let response_for_task = expected_response.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (read, peer) = udp.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..read], expected_query.as_slice());
        udp.send_to(&response_for_task, peer).await.unwrap();
    });

    let stack = DnsTransportStack::default();
    let server = parse_dns_server(&format!("127.0.0.1:{port}")).unwrap();
    let response = stack
        .query(&example_query(), &server, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(response, expected_response);
}

#[tokio::test]
async fn stack_queries_tcp_server() {
    use crate::dns::tcp_codec::encode_dns_tcp_frame;

    let expected_query = example_query();
    let expected_response = example_response();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let query_task = expected_query.clone();
    let response_task = expected_response.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 512];
        let read = stream.read(&mut buf).await.unwrap();
        let frame = encode_dns_tcp_frame(&query_task).unwrap();
        assert_eq!(&buf[..read], frame.as_slice());
        stream
            .write_all(&encode_dns_tcp_frame(&response_task).unwrap())
            .await
            .unwrap();
    });

    let stack = DnsTransportStack::default();
    let server = parse_dns_server(&format!("tcp://127.0.0.1:{}", addr.port())).unwrap();
    let response = stack
        .query(&expected_query, &server, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(response, expected_response);
}

#[tokio::test]
async fn doh_returns_explicit_unsupported_error() {
    let stack = DnsTransportStack::default();
    let server = parse_dns_server("https://dns.google/dns-query").unwrap();
    let err = stack
        .query(&example_query(), &server, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(
        matches!(err, DnsError::UnsupportedTransport(message) if message.contains("not implemented"))
    );
}

#[tokio::test]
async fn server_failover_after_timeout() {
    let good = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good_port = good.local_addr().unwrap().port();
    let expected_query = example_query();
    let expected_response = example_response();
    let query_task = expected_query.clone();
    let response_task = expected_response.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (read, peer) = good.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..read], query_task.as_slice());
        good.send_to(&response_task, peer).await.unwrap();
    });

    let stack = DnsTransportStack::default();
    let servers = [
        parse_dns_server("127.0.0.1:9").unwrap(),
        parse_dns_server(&format!("127.0.0.1:{good_port}")).unwrap(),
    ];
    let mut last_err = None;
    let mut response = None;
    for server in &servers {
        match stack
            .query(&expected_query, server, Duration::from_millis(150))
            .await
        {
            Ok(raw) => {
                response = Some(raw);
                break;
            }
            Err(err @ DnsError::Timeout) => last_err = Some(err),
            Err(err) => {
                last_err = Some(err);
            }
        }
    }
    assert_eq!(response.unwrap(), expected_response);
    assert!(matches!(last_err, Some(DnsError::Timeout)));
}
