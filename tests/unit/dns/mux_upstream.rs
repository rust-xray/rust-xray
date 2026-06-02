use super::*;
use crate::dns::config::parse_dns_server;
use crate::dns::options::MuxDnsUpstreamMode;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

fn example_query() -> Vec<u8> {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

#[test]
fn deduplicates_destination_when_same_as_config_server() {
    let destination = SocketAddr::from(([1, 1, 1, 1], 53));
    let config = DnsConfig {
        servers: vec![parse_dns_server("1.1.1.1").unwrap()],
        query_strategy: Default::default(),
        disable_cache: false,
        extra: Default::default(),
    };
    let candidates = build_mux_udp_candidates(
        destination,
        &config,
        MuxDnsUpstreamMode::DestinationThenConfigFallback,
    );
    assert_eq!(candidates[0].addr, destination);
    assert!(candidates
        .iter()
        .any(|c| c.server_id == "mux-emergency:8.8.8.8:53"));
    assert!(candidates
        .iter()
        .any(|c| c.server_id == "mux-emergency:9.9.9.9:53"));
}

#[test]
fn destination_only_returns_single_candidate() {
    let destination = SocketAddr::from(([1, 1, 1, 1], 53));
    let config = DnsConfig {
        servers: vec![parse_dns_server("8.8.8.8").unwrap()],
        query_strategy: Default::default(),
        disable_cache: false,
        extra: Default::default(),
    };
    let candidates =
        build_mux_udp_candidates(destination, &config, MuxDnsUpstreamMode::DestinationOnly);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].server_id, "mux:1.1.1.1:53");
}

#[test]
fn fallback_includes_destination_and_config_udp_servers() {
    let destination = SocketAddr::from(([1, 1, 1, 1], 53));
    let config = DnsConfig {
        servers: vec![parse_dns_server("8.8.8.8").unwrap()],
        query_strategy: Default::default(),
        disable_cache: false,
        extra: Default::default(),
    };
    let candidates = build_mux_udp_candidates(
        destination,
        &config,
        MuxDnsUpstreamMode::DestinationThenConfigFallback,
    );
    assert_eq!(candidates[0].addr, destination);
    assert_eq!(candidates[1].server_id, "8.8.8.8");
}

#[tokio::test]
async fn race_avoids_slow_destination() {
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let upstream_task = Arc::clone(&upstream_count);
    let good = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good_port = good.local_addr().unwrap().port();
    let query = example_query();
    let response = response_with_id(0x1234);
    let query_task = query.clone();
    let response_task = response.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (read, peer) = match good.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(_) => break,
            };
            upstream_task.fetch_add(1, Ordering::SeqCst);
            assert_eq!(&buf[..read], query_task.as_slice());
            good.send_to(&response_task, peer).await.unwrap();
        }
    });

    let candidates = vec![
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
            server_id: "mux:127.0.0.1:9".to_string(),
        },
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, good_port)),
            server_id: format!("127.0.0.1:{good_port}"),
        },
    ];

    let started = std::time::Instant::now();
    let udp = UdpDnsTransport::default();
    let (raw, _) = execute_mux_udp_upstream(
        &udp,
        &query,
        &candidates,
        MuxDnsUpstreamMode::RaceDestinationAndConfig,
        Duration::from_millis(500),
        Duration::from_millis(1000),
    )
    .await
    .unwrap();
    assert_eq!(raw, response);
    assert!(started.elapsed() < Duration::from_millis(300));
}

#[tokio::test]
async fn fallback_is_bounded_by_total_timeout() {
    let candidates = vec![
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
            server_id: "mux:127.0.0.1:9".to_string(),
        },
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8)),
            server_id: "127.0.0.1:8".to_string(),
        },
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 7)),
            server_id: "127.0.0.1:7".to_string(),
        },
    ];
    let started = std::time::Instant::now();
    let udp = UdpDnsTransport::default();
    let err = execute_mux_udp_upstream(
        &udp,
        &example_query(),
        &candidates,
        MuxDnsUpstreamMode::DestinationThenConfigFallback,
        Duration::from_millis(750),
        Duration::from_millis(1000),
    )
    .await
    .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(1200));
    assert!(elapsed >= Duration::from_millis(900));
}

#[tokio::test]
async fn race_total_timeout_when_all_silent() {
    let candidates = vec![
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
            server_id: "mux:127.0.0.1:9".to_string(),
        },
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8)),
            server_id: "127.0.0.1:8".to_string(),
        },
    ];
    let started = std::time::Instant::now();
    let udp = UdpDnsTransport::default();
    let err = execute_mux_udp_upstream(
        &udp,
        &example_query(),
        &candidates,
        MuxDnsUpstreamMode::RaceDestinationAndConfig,
        Duration::from_millis(750),
        Duration::from_millis(500),
    )
    .await
    .unwrap_err();
    assert_eq!(err, DnsError::Timeout);
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(700));
    assert!(elapsed >= Duration::from_millis(450));
}

#[tokio::test]
async fn race_ignores_wrong_transaction_id_and_wins_on_correct() {
    let wrong = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wrong_port = wrong.local_addr().unwrap().port();
    let correct = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let correct_port = correct.local_addr().unwrap().port();
    let query = example_query();
    let wrong_response = response_with_id(0xabcd);
    let correct_response = response_with_id(0x1234);
    let want_correct = correct_response.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (_read, peer) = match wrong.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(_) => break,
            };
            wrong.send_to(&wrong_response, peer).await.unwrap();
        }
    });

    let query_task = query.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (read, peer) = match correct.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(_) => break,
            };
            assert_eq!(&buf[..read], query_task.as_slice());
            correct.send_to(&correct_response, peer).await.unwrap();
        }
    });

    let candidates = vec![
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, wrong_port)),
            server_id: "wrong".to_string(),
        },
        MuxDnsCandidate {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, correct_port)),
            server_id: "correct".to_string(),
        },
    ];

    let udp = UdpDnsTransport::default();
    let (raw, server_id) = execute_mux_udp_upstream(
        &udp,
        &query,
        &candidates,
        MuxDnsUpstreamMode::RaceDestinationAndConfig,
        Duration::from_millis(500),
        Duration::from_millis(1000),
    )
    .await
    .unwrap();
    assert_eq!(server_id, "correct");
    assert_eq!(raw, want_correct);
}
