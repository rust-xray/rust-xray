use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::dns::packet::dns_query_id;
use crate::dns::{DnsEngine, DnsEngineOptions, DnsError, DnsQueryResponse, DnsQueryTrace};
use crate::mux::encoder::{
    append_mux_udp_dns_close, encode_mux_end, encode_mux_udp_packet,
    mux_udp_send_close_after_response_enabled,
};
use crate::mux::frame::{
    MuxSessionTrace, MuxUdpDnsLatencyTrace, ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE,
};
use crate::mux::state::{mux_actions, mux_dns_actions, MuxFrameActions, MuxOutTx};
use crate::mux::tcp;
use crate::outbound::freedom::format_vless_destination;
use crate::vless::protocol::VlessDestination;

pub(crate) fn mux_dns_legacy_direct_enabled() -> bool {
    crate::dns::options::mux_dns_legacy_direct_enabled()
}

fn mux_dns_non_fatal_error(err: &DnsError) -> bool {
    matches!(
        err,
        DnsError::Timeout
            | DnsError::MalformedQuery
            | DnsError::Upstream
            | DnsError::ServerFailed
            | DnsError::UnsupportedTransport(_)
            | DnsError::Io(_, _)
    )
}

async fn resolve_mux_udp_dns_packet(
    dns: &Arc<DnsEngine>,
    mux_id: u16,
    target: SocketAddr,
    data: &[u8],
    trace: Option<DnsQueryTrace>,
) -> Result<DnsQueryResponse, DnsError> {
    if mux_dns_legacy_direct_enabled() {
        warn!(
            mux_id,
            %target,
            payload_len = data.len(),
            "legacy mux direct DNS path enabled; DNS engine bypassed"
        );
        let timeout = DnsEngineOptions::from_env().mux_udp_dns_timeout;
        let raw = relay_mux_udp_dns_legacy_direct(target, data, timeout).await?;
        return Ok(DnsQueryResponse {
            raw_response: raw,
            server: target,
            cached: false,
            latency: Duration::ZERO,
        });
    }
    dns.resolve_mux_udp_dns_with_trace(mux_id, target, data, trace)
        .await
}

async fn relay_mux_udp_dns_legacy_direct(
    target: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, DnsError> {
    let expected_id = dns_query_id(query).ok_or(DnsError::MalformedQuery)?;
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|err| DnsError::Io(err.kind(), err.to_string()))?;
    socket
        .send_to(query, target)
        .await
        .map_err(|err| DnsError::Io(err.kind(), err.to_string()))?;
    let mut buf = vec![0u8; 512];
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(DnsError::Timeout);
        }
        let recv = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|err| DnsError::Io(err.kind(), err.to_string()))?;
        let (len, _) = recv;
        if dns_query_id(&buf[..len]) == Some(expected_id) {
            return Ok(buf[..len].to_vec());
        }
    }
}

pub(crate) async fn handle_udp_mux_packet(
    id: u16,
    destination: VlessDestination,
    data: Vec<u8>,
    dns: &Arc<DnsEngine>,
    trace: Option<MuxSessionTrace>,
    udp_tx: MuxOutTx,
) -> std::io::Result<MuxFrameActions> {
    let received_at = Instant::now();
    let destination_label = format_vless_destination(&destination);
    let target = udp_socket_addr_without_dns(&destination);
    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %destination_label,
        destination = ?target,
        payload_len = data.len(),
        dns_id = dns_query_id(&data),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux udp packet received"
    );

    if !is_mux_udp_dns_request(&destination, &data) {
        tcp::spawn_generic_udp_relay(id, destination, data, trace, received_at, udp_tx);
        return Ok(mux_actions(Vec::new()));
    }
    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %destination_label,
        destination = ?target,
        payload_len = data.len(),
        dns_id = dns_query_id(&data),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux udp dns received"
    );

    let Some(target) = target else {
        warn!(
            mux_id = id,
            network = "udp",
            destination = %destination_label,
            payload_len = data.len(),
            "UDP mux DNS domain destination requires resolver support; closing substream"
        );
        return Ok(mux_actions(vec![append_mux_udp_dns_close(id, None)]));
    };

    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %target,
        destination = %destination_label,
        payload_len = data.len(),
        engine_elapsed_ms = received_at.elapsed().as_millis(),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux udp dns engine query started"
    );
    let dns_trace = trace.map(|trace| DnsQueryTrace {
        conn_id: trace.conn_id,
        mux_id: Some(id),
        conn_started: trace.conn_started,
        dns_started: received_at,
    });
    match resolve_mux_udp_dns_packet(dns, id, target, &data, dns_trace).await {
        Ok(response) => {
            let encode_started = Instant::now();
            let frame = encode_mux_udp_packet(id, &destination, &response.raw_response)?;
            debug!(
                conn_id = trace.map(|trace| trace.conn_id),
                mux_id = id,
                destination = %destination_label,
                response_len = response.raw_response.len(),
                cache_hit = response.cached,
                encode_ms = encode_started.elapsed().as_millis(),
                engine_latency_ms = response.latency.as_millis(),
                elapsed_ms = received_at.elapsed().as_millis(),
                elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                "mux udp dns response frame encoded"
            );
            debug!(
                conn_id = trace.map(|trace| trace.conn_id),
                mux_id = id,
                destination = %destination_label,
                response_len = response.raw_response.len(),
                cache_hit = response.cached,
                latency_ms = received_at.elapsed().as_millis(),
                elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                "mux udp dns engine response sent"
            );
            let close_frame = mux_udp_send_close_after_response_enabled().then(|| {
                debug!(
                    conn_id = trace.map(|trace| trace.conn_id),
                    mux_id = id,
                    destination = %destination_label,
                    env = ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE,
                    "mux udp dns close after response enabled"
                );
                encode_mux_end(id)
            });
            Ok(mux_dns_actions(
                frame,
                close_frame,
                MuxUdpDnsLatencyTrace {
                    conn_id: trace.map(|trace| trace.conn_id),
                    conn_started: trace.map(|trace| trace.conn_started),
                    mux_id: id,
                    received_at,
                },
            ))
        }
        Err(err) if mux_dns_non_fatal_error(&err) => {
            if matches!(err, DnsError::Timeout) {
                debug!(
                    conn_id = trace.map(|trace| trace.conn_id),
                    mux_id = id,
                    destination = %destination_label,
                    error = %err,
                    total_latency_ms = received_at.elapsed().as_millis(),
                    elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                    "mux udp dns engine timeout"
                );
            } else {
                warn!(
                    mux_id = id,
                    destination = %destination_label,
                    error = %err,
                    total_latency_ms = received_at.elapsed().as_millis(),
                    "mux udp dns engine error"
                );
            }
            Ok(mux_actions(vec![append_mux_udp_dns_close(id, None)]))
        }
        Err(err) => Err(err.into()),
    }
}

fn destination_port(destination: &VlessDestination) -> u16 {
    match destination {
        VlessDestination::Ip(_, port) | VlessDestination::Domain(_, port) => *port,
    }
}

fn is_mux_udp_dns_request(destination: &VlessDestination, data: &[u8]) -> bool {
    if destination_port(destination) == 53 {
        return true;
    }
    is_test_mux_dns_request(data)
}

#[cfg(test)]
fn is_test_mux_dns_request(data: &[u8]) -> bool {
    crate::dns::packet::parse_dns_question_key(data, "mux-test").is_ok()
}

#[cfg(not(test))]
fn is_test_mux_dns_request(_data: &[u8]) -> bool {
    false
}

pub(crate) fn udp_socket_addr_without_dns(destination: &VlessDestination) -> Option<SocketAddr> {
    match destination {
        VlessDestination::Ip(ip, port) => Some(SocketAddr::new(*ip, *port)),
        VlessDestination::Domain(_, _) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use crate::dns::{DnsEngine, DnsEngineOptions};
    use crate::mux::encoder::encode_mux_new_udp;
    use crate::mux::frame::{
        MuxCommand, MuxDestination, MuxFrame, MuxNetwork, MuxOption, MuxStatus,
        ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE,
    };
    use crate::mux::parser::read_mux_frame;
    use crate::mux::session::handle_mux_cool_inbound_with_dns;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env test lock")
    }

    fn set_mux_udp_close_after_response_for_test(value: &str) -> Option<String> {
        let previous = std::env::var(ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE).ok();
        std::env::set_var(ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE, value);
        previous
    }

    fn restore_mux_udp_close_after_response_for_test(previous: Option<String>) {
        match previous {
            Some(value) => std::env::set_var(ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE, value),
            None => std::env::remove_var(ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE),
        }
    }

    async fn assert_no_mux_frame_within<R>(reader: &mut R, duration: Duration)
    where
        R: AsyncRead + Unpin,
    {
        assert!(
            tokio::time::timeout(duration, read_mux_frame(reader))
                .await
                .is_err(),
            "unexpected mux frame received"
        );
    }

    fn example_mux_dns_query() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        packet
    }

    fn example_mux_dns_response() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn mux_dns_legacy_direct_disabled_by_default() {
        assert!(!mux_dns_legacy_direct_enabled());
    }

    #[test]
    fn udp_dns_relay_with_fake_udp_server_returns_mux_response() {
        block_on(async {
            let _guard = env_lock();
            let previous_close = set_mux_udp_close_after_response_for_test("0");
            let udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind fake udp dns");
            let udp_port = udp.local_addr().expect("udp local addr").port();
            let expected_query = example_mux_dns_query();
            let expected_response = example_mux_dns_response();
            let query_for_task = expected_query.clone();
            let response_for_task = expected_response.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let (read, peer) = udp.recv_from(&mut buf).await.expect("fake dns recv");
                assert_eq!(&buf[..read], query_for_task.as_slice());
                udp.send_to(&response_for_task, peer)
                    .await
                    .expect("fake dns send");
            });

            let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
            let open = encode_mux_new_udp(15, &destination, &expected_query);
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io
                .write_all(&open)
                .await
                .expect("write mux udp open");

            let dns = Arc::new(DnsEngine::with_mux_defaults());
            let handle =
                tokio::spawn(async move { handle_mux_cool_inbound_with_dns(server_io, dns).await });

            let frame = read_mux_frame(&mut client_io)
                .await
                .expect("read mux udp response");
            assert_eq!(
                frame,
                MuxFrame {
                    mux_id: 15,
                    status: MuxStatus::Keep,
                    option: MuxOption { has_data: true },
                    command: MuxCommand::Udp {
                        destination: MuxDestination {
                            network: MuxNetwork::Udp,
                            destination,
                        },
                        packet: expected_response
                    }
                }
            );

            assert_no_mux_frame_within(&mut client_io, Duration::from_millis(50)).await;

            drop(client_io);
            handle.await.expect("join mux handler").unwrap();
            restore_mux_udp_close_after_response_for_test(previous_close);
        });
    }

    #[test]
    fn udp_dns_success_close_frame_enabled_by_env() {
        block_on(async {
            let _guard = env_lock();
            let previous_close = set_mux_udp_close_after_response_for_test("1");
            let udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind fake udp dns");
            let udp_port = udp.local_addr().expect("udp local addr").port();
            let expected_query = example_mux_dns_query();
            let expected_response = example_mux_dns_response();
            let query_for_task = expected_query.clone();
            let response_for_task = expected_response.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let (read, peer) = udp.recv_from(&mut buf).await.expect("fake dns recv");
                assert_eq!(&buf[..read], query_for_task.as_slice());
                udp.send_to(&response_for_task, peer)
                    .await
                    .expect("fake dns send");
            });

            let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
            let open = encode_mux_new_udp(19, &destination, &expected_query);
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io
                .write_all(&open)
                .await
                .expect("write mux udp open");

            let dns = Arc::new(DnsEngine::with_mux_defaults());
            let handle =
                tokio::spawn(async move { handle_mux_cool_inbound_with_dns(server_io, dns).await });

            let frame = read_mux_frame(&mut client_io)
                .await
                .expect("read mux udp response");
            assert!(matches!(frame.command, MuxCommand::Udp { .. }));
            assert_eq!(
                read_mux_frame(&mut client_io).await.expect("read mux end"),
                MuxFrame {
                    mux_id: 19,
                    status: MuxStatus::End,
                    option: MuxOption { has_data: false },
                    command: MuxCommand::Close {
                        payload: Vec::new()
                    }
                }
            );

            drop(client_io);
            handle.await.expect("join mux handler").unwrap();
            restore_mux_udp_close_after_response_for_test(previous_close);
        });
    }

    #[test]
    fn udp_dns_multiple_packets_same_mux_id_zero_without_close() {
        block_on(async {
            use crate::dns::config::{DnsConfig, QueryStrategy};
            use crate::dns::MuxDnsUpstreamMode;

            let _guard = env_lock();
            let previous_close = set_mux_udp_close_after_response_for_test("0");
            let udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind fake udp dns");
            let udp_port = udp.local_addr().expect("udp local addr").port();
            let expected_query = example_mux_dns_query();
            let expected_response = example_mux_dns_response();
            let query_for_task = expected_query.clone();
            let response_for_task = expected_response.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                for _ in 0..2 {
                    let (read, peer) = udp.recv_from(&mut buf).await.expect("fake dns recv");
                    assert_eq!(&buf[..read], query_for_task.as_slice());
                    udp.send_to(&response_for_task, peer)
                        .await
                        .expect("fake dns send");
                }
            });

            let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
            let first = encode_mux_new_udp(0, &destination, &expected_query);
            let second = crate::mux::encoder::encode_mux_keep_udp(0, &destination, &expected_query);
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io.write_all(&first).await.expect("write first dns");

            let dns = Arc::new(DnsEngine::new(
                DnsConfig {
                    servers: vec![crate::dns::config::parse_dns_server("127.0.0.1").unwrap()],
                    query_strategy: QueryStrategy::UseIP,
                    disable_cache: true,
                    extra: Default::default(),
                },
                DnsEngineOptions {
                    mux_udp_dns_timeout: Duration::from_secs(1),
                    mux_udp_dns_total_timeout: Duration::from_secs(1),
                    mux_dns_upstream_mode: MuxDnsUpstreamMode::DestinationOnly,
                    max_retries: 0,
                    mux_udp_dns_max_retries: 0,
                    ..DnsEngineOptions::for_test()
                },
            ));
            let handle =
                tokio::spawn(async move { handle_mux_cool_inbound_with_dns(server_io, dns).await });

            assert_eq!(
                read_mux_frame(&mut client_io)
                    .await
                    .expect("read first response"),
                MuxFrame {
                    mux_id: 0,
                    status: MuxStatus::Keep,
                    option: MuxOption { has_data: true },
                    command: MuxCommand::Udp {
                        destination: MuxDestination {
                            network: MuxNetwork::Udp,
                            destination: destination.clone(),
                        },
                        packet: expected_response.clone()
                    }
                }
            );
            assert_no_mux_frame_within(&mut client_io, Duration::from_millis(50)).await;

            client_io
                .write_all(&second)
                .await
                .expect("write second dns");
            assert_eq!(
                read_mux_frame(&mut client_io)
                    .await
                    .expect("read second response"),
                MuxFrame {
                    mux_id: 0,
                    status: MuxStatus::Keep,
                    option: MuxOption { has_data: true },
                    command: MuxCommand::Udp {
                        destination: MuxDestination {
                            network: MuxNetwork::Udp,
                            destination,
                        },
                        packet: expected_response
                    }
                }
            );
            assert_no_mux_frame_within(&mut client_io, Duration::from_millis(50)).await;

            drop(client_io);
            handle.await.expect("join mux handler").unwrap();
            restore_mux_udp_close_after_response_for_test(previous_close);
        });
    }

    #[test]
    fn udp_dns_timeout_closes_substream_without_killing_session() {
        block_on(async {
            use crate::dns::config::{DnsConfig, QueryStrategy};
            use crate::dns::MuxDnsUpstreamMode;

            let udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind silent udp dns");
            let udp_port = udp.local_addr().expect("udp local addr").port();
            let expected_query = example_mux_dns_query();
            let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let received_task = std::sync::Arc::clone(&received);

            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let (read, _peer) = udp.recv_from(&mut buf).await.expect("silent dns recv");
                received_task
                    .lock()
                    .expect("lock received")
                    .extend_from_slice(&buf[..read]);
            });

            let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
            let open = encode_mux_new_udp(17, &destination, &expected_query);
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io
                .write_all(&open)
                .await
                .expect("write mux udp open");

            let dns = Arc::new(DnsEngine::new(
                DnsConfig {
                    servers: vec![crate::dns::config::parse_dns_server("127.0.0.1").unwrap()],
                    query_strategy: QueryStrategy::UseIP,
                    disable_cache: false,
                    extra: Default::default(),
                },
                DnsEngineOptions {
                    mux_udp_dns_timeout: Duration::from_millis(100),
                    mux_udp_dns_total_timeout: Duration::from_millis(100),
                    mux_dns_upstream_mode: MuxDnsUpstreamMode::DestinationOnly,
                    max_retries: 0,
                    mux_udp_dns_max_retries: 0,
                    ..DnsEngineOptions::for_test()
                },
            ));
            let handle =
                tokio::spawn(async move { handle_mux_cool_inbound_with_dns(server_io, dns).await });
            assert_eq!(
                read_mux_frame(&mut client_io)
                    .await
                    .expect("read timeout mux end"),
                MuxFrame {
                    mux_id: 17,
                    status: MuxStatus::End,
                    option: MuxOption { has_data: false },
                    command: MuxCommand::Close {
                        payload: Vec::new()
                    }
                }
            );
            assert_eq!(*received.lock().expect("lock received"), expected_query);

            drop(client_io);
            handle.await.expect("join mux handler").unwrap();
        });
    }

    #[test]
    fn mux_udp_dns_repeat_query_hits_engine_cache() {
        block_on(async {
            use crate::dns::config::{DnsConfig, QueryStrategy};
            use std::sync::atomic::{AtomicUsize, Ordering};

            let _guard = env_lock();
            let previous_close = set_mux_udp_close_after_response_for_test("0");
            let upstream_count = Arc::new(AtomicUsize::new(0));
            let upstream_task = Arc::clone(&upstream_count);
            let udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind fake udp dns");
            let udp_port = udp.local_addr().expect("udp local addr").port();
            let expected_query = example_mux_dns_query();
            let expected_response = example_mux_dns_response();
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
                    udp.send_to(&response_task, peer)
                        .await
                        .expect("fake dns send");
                }
            });

            let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
            let dns = Arc::new(DnsEngine::new(
                DnsConfig {
                    servers: vec![crate::dns::config::parse_dns_server("127.0.0.1").unwrap()],
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
            ));

            for mux_id in [21u16, 22u16] {
                let open = encode_mux_new_udp(mux_id, &destination, &expected_query);
                let (mut client_io, server_io) = tokio::io::duplex(8192);
                client_io
                    .write_all(&open)
                    .await
                    .expect("write mux udp open");
                let dns_task = Arc::clone(&dns);
                let handle = tokio::spawn(async move {
                    handle_mux_cool_inbound_with_dns(server_io, dns_task).await
                });
                let frame = read_mux_frame(&mut client_io)
                    .await
                    .expect("read mux udp response");
                assert_eq!(
                    frame,
                    MuxFrame {
                        mux_id,
                        status: MuxStatus::Keep,
                        option: MuxOption { has_data: true },
                        command: MuxCommand::Udp {
                            destination: MuxDestination {
                                network: MuxNetwork::Udp,
                                destination: destination.clone(),
                            },
                            packet: expected_response.clone()
                        }
                    }
                );
                assert_no_mux_frame_within(&mut client_io, Duration::from_millis(50)).await;
                drop(client_io);
                handle.await.expect("join mux handler").unwrap();
            }

            assert_eq!(upstream_count.load(Ordering::SeqCst), 1);
            restore_mux_udp_close_after_response_for_test(previous_close);
        });
    }
}
