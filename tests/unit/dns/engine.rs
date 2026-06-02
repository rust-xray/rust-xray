use super::*;
use crate::dns::options::MuxDnsUpstreamMode;
use crate::dns::packet::dns_query_id;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

fn example_query_aaaa() -> Vec<u8> {
    let mut packet = example_query();
    let len = packet.len();
    packet[len - 2] = 0;
    packet[len - 1] = 28;
    packet
}

fn example_response() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

fn query_with_id(id: u16) -> Vec<u8> {
    let mut packet = example_query();
    packet[0] = (id >> 8) as u8;
    packet[1] = (id & 0xff) as u8;
    packet
}

fn response_with_id(id: u16) -> Vec<u8> {
    let mut packet = example_response();
    packet[0] = (id >> 8) as u8;
    packet[1] = (id & 0xff) as u8;
    packet
}

fn response_with_a(ip: [u8; 4]) -> Vec<u8> {
    let mut packet = example_query();
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet[6] = 0x00;
    packet[7] = 0x01;
    packet.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
    ]);
    packet.extend_from_slice(&ip);
    packet
}

fn response_with_aaaa(ip: [u8; 16]) -> Vec<u8> {
    let mut packet = example_query_aaaa();
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet[6] = 0x00;
    packet[7] = 0x01;
    packet.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
    ]);
    packet.extend_from_slice(&ip);
    packet
}

#[tokio::test]
async fn cache_hit_by_qname_qtype() {
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions::default(),
    );
    let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
    let key = parse_dns_question_key(&example_query(), format!("mux:{destination}")).unwrap();
    engine
        .cache
        .insert(key, example_response(), Duration::from_secs(60));

    let response = engine
        .query_raw(DnsQueryRequest {
            raw_query: example_query(),
            destination: Some(destination),
            inbound_tag: None,
            source: DnsQuerySource::MuxUdp,
            trace: None,
        })
        .await
        .unwrap();
    assert!(response.cached);
    assert_eq!(response.raw_response, example_response());
}

#[tokio::test]
async fn cache_hit_rewrites_transaction_id_for_current_query() {
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions::default(),
    );
    let first_query = query_with_id(0x1234);
    let second_query = query_with_id(0xabcd);
    let key = parse_dns_question_key(&first_query, "127.0.0.1").unwrap();
    assert_eq!(
        key,
        parse_dns_question_key(&second_query, "127.0.0.1").unwrap()
    );

    engine
        .cache
        .insert(key, response_with_id(0x1234), Duration::from_secs(60));

    let response = engine
        .query_raw(DnsQueryRequest {
            raw_query: second_query,
            destination: None,
            inbound_tag: None,
            source: DnsQuerySource::MuxUdp,
            trace: None,
        })
        .await
        .unwrap();

    assert!(response.cached);
    assert_eq!(dns_query_id(&response.raw_response), Some(0xabcd));
    assert_ne!(response.raw_response[0], 0x12);
    assert_ne!(response.raw_response[1], 0x34);
}

#[tokio::test]
async fn first_query_populates_cache_second_query_rewrites_id() {
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let upstream_task = Arc::clone(&upstream_count);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    let first_query = query_with_id(0x1234);
    let second_query = query_with_id(0xabcd);
    let first_response = response_with_id(0x1234);
    let query_task = first_query.clone();
    let response_task = first_response.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (read, peer) = udp.recv_from(&mut buf).await.unwrap();
        upstream_task.fetch_add(1, Ordering::SeqCst);
        assert_eq!(&buf[..read], query_task.as_slice());
        udp.send_to(&response_task, peer).await.unwrap();
    });

    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server(&format!("127.0.0.1:{port}")).unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions {
            mux_udp_dns_timeout: Duration::from_secs(2),
            max_retries: 0,
            mux_udp_dns_max_retries: 0,
            ..DnsEngineOptions::for_test()
        },
    );

    let first = engine
        .query_raw(DnsQueryRequest {
            raw_query: first_query,
            destination: None,
            inbound_tag: None,
            source: DnsQuerySource::MuxUdp,
            trace: None,
        })
        .await
        .unwrap();
    assert!(!first.cached);
    assert_eq!(dns_query_id(&first.raw_response), Some(0x1234));
    assert_eq!(upstream_count.load(Ordering::SeqCst), 1);

    let second = engine
        .query_raw(DnsQueryRequest {
            raw_query: second_query,
            destination: None,
            inbound_tag: None,
            source: DnsQuerySource::MuxUdp,
            trace: None,
        })
        .await
        .unwrap();
    assert!(second.cached);
    assert_eq!(dns_query_id(&second.raw_response), Some(0xabcd));
    assert_eq!(upstream_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cache_isolated_per_qtype() {
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions::default(),
    );
    let a_query = build_dns_query("example.com", 1).unwrap();
    let aaaa_query = build_dns_query("example.com", 28).unwrap();
    let a_key = parse_dns_question_key(&a_query, "127.0.0.1").unwrap();
    let aaaa_key = parse_dns_question_key(&aaaa_query, "127.0.0.1").unwrap();
    engine.cache.insert(
        a_key,
        response_with_a([1, 1, 1, 1]),
        Duration::from_secs(60),
    );
    engine.cache.insert(
        aaaa_key,
        response_with_aaaa([0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Duration::from_secs(60),
    );

    let a_response = engine
        .lookup_ip("example.com", QueryStrategy::UseIPv4)
        .await
        .unwrap();
    assert_eq!(a_response, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);

    let aaaa_response = engine
        .lookup_ip("example.com", QueryStrategy::UseIPv6)
        .await
        .unwrap();
    assert_eq!(
        aaaa_response,
        vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1))]
    );
}

#[tokio::test]
async fn lookup_ip_use_ip_queries_both_types() {
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions::default(),
    );
    let a_query = build_dns_query("example.com", 1).unwrap();
    let aaaa_query = build_dns_query("example.com", 28).unwrap();
    let a_key = parse_dns_question_key(&a_query, "127.0.0.1").unwrap();
    let aaaa_key = parse_dns_question_key(&aaaa_query, "127.0.0.1").unwrap();
    engine.cache.insert(
        a_key,
        response_with_a([1, 0, 0, 1]),
        Duration::from_secs(60),
    );
    engine.cache.insert(
        aaaa_key,
        response_with_aaaa([0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        Duration::from_secs(60),
    );

    let ips = engine
        .lookup_ip("example.com", QueryStrategy::UseIP)
        .await
        .unwrap();
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))));
    assert!(ips.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 2))));
}

#[tokio::test]
async fn disable_cache_bypasses_cache() {
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: true,
            extra: Default::default(),
        },
        DnsEngineOptions {
            mux_udp_dns_timeout: Duration::from_millis(200),
            mux_udp_dns_total_timeout: Duration::from_millis(200),
            mux_dns_upstream_mode: MuxDnsUpstreamMode::DestinationOnly,
            max_retries: 0,
            mux_udp_dns_max_retries: 0,
            ..DnsEngineOptions::for_test()
        },
    );
    let key = parse_dns_question_key(&example_query(), "127.0.0.1").unwrap();
    engine
        .cache
        .insert(key, example_response(), Duration::from_secs(60));

    let err = engine
        .query_raw(DnsQueryRequest {
            raw_query: example_query(),
            destination: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
            inbound_tag: None,
            source: DnsQuerySource::MuxUdp,
            trace: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
}

#[tokio::test]
async fn fake_udp_server_returns_response() {
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let upstream_task = Arc::clone(&upstream_count);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    let expected_query = example_query();
    let expected_response = example_response();
    let query_task = expected_query.clone();
    let response_task = expected_response.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (read, peer) = udp.recv_from(&mut buf).await.unwrap();
        upstream_task.fetch_add(1, Ordering::SeqCst);
        assert_eq!(&buf[..read], query_task.as_slice());
        udp.send_to(&response_task, peer).await.unwrap();
    });

    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions {
            mux_udp_dns_timeout: Duration::from_secs(2),
            max_retries: 0,
            mux_udp_dns_max_retries: 0,
            ..DnsEngineOptions::for_test()
        },
    );

    let response = engine
        .resolve_mux_udp_dns(
            3,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            &expected_query,
        )
        .await
        .unwrap();
    assert_eq!(response.raw_response, expected_response);
    assert_eq!(upstream_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn tcp_dns_server_returns_response() {
    use crate::dns::tcp_codec::encode_dns_tcp_frame;

    let expected_query = example_query();
    let expected_response = example_response();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let query_task = expected_query.clone();
    let response_task = expected_response.clone();
    let want_response = expected_response.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 512];
        let read = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..read], encode_dns_tcp_frame(&query_task).unwrap());
        stream
            .write_all(&encode_dns_tcp_frame(&response_task).unwrap())
            .await
            .unwrap();
    });

    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![
                config::parse_dns_server(&format!("tcp://127.0.0.1:{}", addr.port())).unwrap(),
            ],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions {
            default_timeout: Duration::from_secs(2),
            max_retries: 0,
            ..DnsEngineOptions::for_test()
        },
    );

    let response = engine
        .query_raw(DnsQueryRequest {
            raw_query: example_query(),
            destination: None,
            inbound_tag: None,
            source: DnsQuerySource::BuiltinDns,
            trace: None,
        })
        .await
        .unwrap();
    assert_eq!(response.raw_response, want_response);
}

#[tokio::test]
async fn server_failover_after_timeout() {
    let good = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good_port = good.local_addr().unwrap().port();
    let expected_query = example_query();
    let want_response = example_response();
    let response_for_task = want_response.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (read, peer) = good.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..read], expected_query.as_slice());
        good.send_to(&response_for_task, peer).await.unwrap();
    });

    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![
                config::parse_dns_server("127.0.0.1:9").unwrap(),
                config::parse_dns_server(&format!("127.0.0.1:{good_port}")).unwrap(),
            ],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions {
            default_timeout: Duration::from_millis(150),
            max_retries: 0,
            ..DnsEngineOptions::for_test()
        },
    );

    let response = engine
        .query_raw(DnsQueryRequest {
            raw_query: example_query(),
            destination: None,
            inbound_tag: None,
            source: DnsQuerySource::BuiltinDns,
            trace: None,
        })
        .await
        .unwrap();
    assert_eq!(response.raw_response, want_response);
}

#[tokio::test]
async fn doh_server_returns_explicit_unsupported() {
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("https://dns.google/dns-query").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions::default(),
    );
    let err = engine
        .query_raw(DnsQueryRequest {
            raw_query: example_query(),
            destination: None,
            inbound_tag: None,
            source: DnsQuerySource::BuiltinDns,
            trace: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        DnsError::UnsupportedTransport(message) if message.contains("not implemented")
    ));
}

#[tokio::test]
async fn concurrent_identical_queries_deduplicate_upstream() {
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let upstream_task = Arc::clone(&upstream_count);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    let expected_query = example_query();
    let expected_response = example_response();
    let query_task = expected_query.clone();
    let response_task = expected_response.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (read, peer) = match udp.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(_) => break,
            };
            upstream_task.fetch_add(1, Ordering::SeqCst);
            assert_eq!(&buf[..read], query_task.as_slice());
            udp.send_to(&response_task, peer).await.unwrap();
        }
    });

    let engine = Arc::new(DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: true,
            extra: Default::default(),
        },
        DnsEngineOptions {
            mux_udp_dns_timeout: Duration::from_secs(2),
            max_retries: 0,
            mux_udp_dns_max_retries: 0,
            cache_enabled: false,
            ..DnsEngineOptions::for_test()
        },
    ));

    let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let engine = Arc::clone(&engine);
        let query = expected_query.clone();
        handles.push(tokio::spawn(async move {
            engine.resolve_mux_udp_dns(1, destination, &query).await
        }));
    }
    for handle in handles {
        assert_eq!(
            handle.await.unwrap().unwrap().raw_response,
            expected_response
        );
    }
    assert_eq!(upstream_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn timeout_returns_dns_error_timeout() {
    let started = Instant::now();
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions {
            default_timeout: Duration::from_secs(5),
            mux_udp_dns_timeout: Duration::from_millis(100),
            max_retries: 0,
            mux_udp_dns_max_retries: 0,
            mux_dns_upstream_mode: MuxDnsUpstreamMode::DestinationOnly,
            ..DnsEngineOptions::for_test()
        },
    );
    let err = engine
        .resolve_mux_udp_dns(
            1,
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
            &example_query(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(1));
    assert!(elapsed >= Duration::from_millis(80));
}

#[tokio::test]
async fn mux_udp_request_uses_mux_timeout_not_default() {
    let started = Instant::now();
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions {
            default_timeout: Duration::from_secs(5),
            mux_udp_dns_timeout: Duration::from_millis(200),
            max_retries: 0,
            mux_udp_dns_max_retries: 0,
            mux_dns_upstream_mode: MuxDnsUpstreamMode::DestinationOnly,
            ..DnsEngineOptions::for_test()
        },
    );
    let err = engine
        .resolve_mux_udp_dns(
            1,
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
            &example_query(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn mux_fallback_destination_silent_config_server_responds() {
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let upstream_task = Arc::clone(&upstream_count);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good_port = udp.local_addr().unwrap().port();
    let expected_query = example_query();
    let expected_response = example_response();
    let query_task = expected_query.clone();
    let response_task = expected_response.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (read, peer) = match udp.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(_) => break,
            };
            upstream_task.fetch_add(1, Ordering::SeqCst);
            assert_eq!(&buf[..read], query_task.as_slice());
            udp.send_to(&response_task, peer).await.unwrap();
        }
    });

    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server(&format!("127.0.0.1:{good_port}")).unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions {
            mux_udp_dns_timeout: Duration::from_millis(150),
            mux_dns_upstream_mode: MuxDnsUpstreamMode::DestinationThenConfigFallback,
            ..DnsEngineOptions::for_test()
        },
    );

    let started = Instant::now();
    let response = engine
        .resolve_mux_udp_dns(
            1,
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
            &expected_query,
        )
        .await
        .unwrap();
    assert_eq!(response.raw_response, expected_response);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(upstream_count.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn mux_fallback_uses_destination_when_it_responds() {
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let upstream_task = Arc::clone(&upstream_count);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest_port = udp.local_addr().unwrap().port();
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    let _silent_hold = silent;
    let expected_query = example_query();
    let expected_response = example_response();
    let query_task = expected_query.clone();
    let response_task = expected_response.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (read, peer) = match udp.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(_) => break,
            };
            upstream_task.fetch_add(1, Ordering::SeqCst);
            assert_eq!(&buf[..read], query_task.as_slice());
            udp.send_to(&response_task, peer).await.unwrap();
        }
    });

    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server(&format!("127.0.0.1:{silent_port}")).unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        },
        DnsEngineOptions {
            mux_udp_dns_timeout: Duration::from_millis(200),
            mux_dns_upstream_mode: MuxDnsUpstreamMode::DestinationThenConfigFallback,
            ..DnsEngineOptions::for_test()
        },
    );

    let response = engine
        .resolve_mux_udp_dns(
            1,
            SocketAddr::from((Ipv4Addr::LOCALHOST, dest_port)),
            &expected_query,
        )
        .await
        .unwrap();
    assert_eq!(response.raw_response, expected_response);
    assert_eq!(upstream_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mux_fallback_all_silent_times_out_near_mux_timeout_per_candidate() {
    let started = Instant::now();
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![
                config::parse_dns_server("127.0.0.1:8").unwrap(),
                config::parse_dns_server("127.0.0.1:7").unwrap(),
            ],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: true,
            extra: Default::default(),
        },
        DnsEngineOptions {
            mux_udp_dns_timeout: Duration::from_millis(750),
            mux_udp_dns_total_timeout: Duration::from_millis(1000),
            mux_dns_upstream_mode: MuxDnsUpstreamMode::DestinationThenConfigFallback,
            ..DnsEngineOptions::for_test()
        },
    );
    let err = engine
        .resolve_mux_udp_dns(
            1,
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
            &example_query(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(900));
    assert!(elapsed < Duration::from_millis(1200));
}

#[test]
fn mux_dns_for_test_defaults_to_race_mode() {
    let opts = DnsEngineOptions::for_test();
    assert_eq!(
        opts.mux_dns_upstream_mode,
        MuxDnsUpstreamMode::RaceDestinationAndConfig
    );
    assert_eq!(opts.mux_udp_dns_total_timeout, Duration::from_millis(1000));
}

#[tokio::test]
async fn builtin_dns_request_uses_default_timeout_policy() {
    let started = Instant::now();
    let engine = DnsEngine::new(
        DnsConfig {
            servers: vec![config::parse_dns_server("127.0.0.1:9").unwrap()],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: true,
            extra: Default::default(),
        },
        DnsEngineOptions {
            default_timeout: Duration::from_millis(200),
            mux_udp_dns_timeout: Duration::from_secs(5),
            max_retries: 0,
            mux_udp_dns_max_retries: 0,
            ..DnsEngineOptions::for_test()
        },
    );
    let err = engine
        .query_raw(DnsQueryRequest {
            raw_query: example_query(),
            destination: None,
            inbound_tag: None,
            source: DnsQuerySource::BuiltinDns,
            trace: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(started.elapsed() >= Duration::from_millis(150));
}

#[tokio::test]
async fn malformed_query_rejected() {
    let engine = DnsEngine::with_mux_defaults();
    let err = engine
        .resolve_mux_udp_dns(
            1,
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
            &[0x00, 0x01],
        )
        .await
        .unwrap_err();
    assert_eq!(err, DnsError::MalformedQuery);
}

fn custom_dns_config() -> DnsConfig {
    DnsConfig {
        servers: vec![
            config::parse_dns_server("8.8.8.8").unwrap(),
            config::parse_dns_server("1.0.0.1").unwrap(),
        ],
        query_strategy: QueryStrategy::UseIPv4,
        disable_cache: true,
        extra: Default::default(),
    }
}

fn alternate_dns_config() -> DnsConfig {
    DnsConfig {
        servers: vec![config::parse_dns_server("9.9.9.9").unwrap()],
        query_strategy: QueryStrategy::UseIPv6,
        disable_cache: false,
        extra: Default::default(),
    }
}

#[test]
fn init_shared_and_shared_use_same_singleton() {
    let custom = custom_dns_config();
    let alternate = alternate_dns_config();

    let initialized = DnsEngine::init_shared(Some(&custom));
    let from_shared = DnsEngine::shared();
    assert!(Arc::ptr_eq(&initialized, &from_shared));

    let second_init = DnsEngine::init_shared(Some(&alternate));
    assert!(Arc::ptr_eq(&initialized, &second_init));
    assert_eq!(
        initialized.dns_servers_count(),
        from_shared.dns_servers_count()
    );

    if initialized.dns_servers_count() == custom.servers.len() {
        assert!(initialized.disable_cache());
        assert_eq!(initialized.query_strategy(), QueryStrategy::UseIPv4);
        assert_eq!(initialized.config_snapshot().servers[0].host, "8.8.8.8");
    }
}

#[test]
fn mux_path_uses_process_shared_dns_engine() {
    let custom = custom_dns_config();
    let initialized = DnsEngine::init_shared(Some(&custom));
    let mux_engine = DnsEngine::shared();
    assert!(Arc::ptr_eq(&initialized, &mux_engine));
}

#[test]
fn from_xray_config_applies_top_level_dns_block() {
    let json =
        r#"{"dns":{"servers":["tcp://1.1.1.1:53"],"queryStrategy":"UseIPv4","disableCache":true}}"#;
    let xray: crate::config::XrayConfig = serde_json::from_str(json).expect("parse config");
    let dns = xray.dns.expect("dns block");
    let engine = DnsEngine::from_xray_config(Some(&dns));
    assert_eq!(engine.dns_servers_count(), 1);
    assert_eq!(engine.config_snapshot().servers[0].host, "1.1.1.1");
    assert_eq!(engine.query_strategy(), QueryStrategy::UseIPv4);
    assert!(engine.disable_cache());
}
