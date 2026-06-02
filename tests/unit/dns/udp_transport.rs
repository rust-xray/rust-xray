use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn query_with_id(id: u16) -> Vec<u8> {
    let mut packet = vec![
        (id >> 8) as u8,
        (id & 0xff) as u8,
        0x01,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    packet.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    packet
}

fn response_with_id(id: u16) -> Vec<u8> {
    vec![
        (id >> 8) as u8,
        (id & 0xff) as u8,
        0x81,
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
}

#[tokio::test]
async fn concurrent_queries_with_different_ids() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let query_a = query_with_id(0x1111);
    let query_b = query_with_id(0x2222);
    let response_a = response_with_id(0x1111);
    let response_b = response_with_id(0x2222);

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        for _ in 0..2 {
            let (read, peer) = server.recv_from(&mut buf).await.unwrap();
            let id = dns_query_id(&buf[..read]).unwrap();
            let response = response_with_id(id);
            server.send_to(&response, peer).await.unwrap();
        }
    });

    let transport = UdpDnsTransport::default();
    let (first, second) = tokio::join!(
        transport.query_at(server_addr, &query_a, Duration::from_secs(2)),
        transport.query_at(server_addr, &query_b, Duration::from_secs(2)),
    );
    assert_eq!(first.unwrap(), response_a);
    assert_eq!(second.unwrap(), response_b);
}

#[tokio::test]
async fn timeout_does_not_block_concurrent_query() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();

    let responsive = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let responsive_addr = responsive.local_addr().unwrap();
    let query_ok = query_with_id(0x3333);
    let response_ok = response_with_id(0x3333);
    let query_task = query_ok.clone();
    let response_task = response_ok.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (read, peer) = responsive.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..read], query_task.as_slice());
        responsive.send_to(&response_task, peer).await.unwrap();
    });

    let transport = UdpDnsTransport::default();
    let query_slow = query_with_id(0x4444);
    let slow = transport.query_at(silent_addr, &query_slow, Duration::from_millis(100));
    let fast = transport.query_at(responsive_addr, &query_ok, Duration::from_secs(2));
    let (slow_result, fast_result) = tokio::join!(slow, fast);
    assert_eq!(slow_result.unwrap_err(), DnsError::Timeout);
    assert_eq!(fast_result.unwrap(), response_ok);
}

#[tokio::test]
async fn unexpected_peer_response_is_ignored_until_timeout() {
    let expected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let expected_addr = expected.local_addr().unwrap();
    let wrong_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = query_with_id(0x5555);

    tokio::spawn(async move {
        wrong_peer
            .send_to(&response_with_id(0x5555), expected_addr)
            .await
            .unwrap();
    });

    let transport = UdpDnsTransport::default();
    let err = transport
        .query_at(expected_addr, &query, Duration::from_millis(150))
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
}

#[tokio::test]
async fn mismatched_transaction_id_is_ignored_until_timeout() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let query = query_with_id(0x6666);

    tokio::spawn(async move {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&response_with_id(0x9999), server_addr)
            .await
            .unwrap();
    });

    let transport = UdpDnsTransport::default();
    let err = transport
        .query_at(server_addr, &query, Duration::from_millis(200))
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
}

#[tokio::test]
async fn pending_entry_removed_on_timeout() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let transport = UdpDnsTransport::default();
    let query = query_with_id(0x7777);
    let key = (server_addr, 0x7777);

    let err = transport
        .query_at(server_addr, &query, Duration::from_millis(80))
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Timeout);

    let dispatcher = transport.dispatcher_for(server_addr).await.unwrap();
    assert!(!dispatcher.pending.lock().await.contains_key(&key));
}

#[tokio::test]
async fn duplicate_pending_id_returns_upstream() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let transport = UdpDnsTransport::default();
    let dispatcher = transport.dispatcher_for(server_addr).await.unwrap();
    let key = (server_addr, 0x8888);
    let (tx, _rx) = oneshot::channel();
    dispatcher.pending.lock().await.insert(key, tx);

    let err = transport
        .query_at(
            server_addr,
            &query_with_id(0x8888),
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Upstream);
    dispatcher.pending.lock().await.remove(&key);
}

#[tokio::test]
async fn fake_server_handles_concurrent_upstream_queries() {
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let upstream_task = Arc::clone(&upstream_count);
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (read, peer) = match server.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(_) => break,
            };
            upstream_task.fetch_add(1, Ordering::SeqCst);
            let id = dns_query_id(&buf[..read]).unwrap();
            server.send_to(&response_with_id(id), peer).await.unwrap();
        }
    });

    let transport = UdpDnsTransport::default();
    let query_a = query_with_id(0xaaaa);
    let query_b = query_with_id(0xbbbb);
    let (a, b) = tokio::join!(
        transport.query_at(server_addr, &query_a, Duration::from_secs(2)),
        transport.query_at(server_addr, &query_b, Duration::from_secs(2)),
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(upstream_count.load(Ordering::SeqCst), 2);
}
