use std::io::{Error, ErrorKind};
use std::time::Instant;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, warn};

use crate::dns::DnsEngineOptions;
use crate::mux::encoder::mux_udp_send_close_after_response_enabled;
use crate::mux::encoder::{encode_mux_end, encode_mux_udp_packet};
use crate::mux::frame::{MuxCommand, MuxFrame, MuxSessionTrace, MAX_MUX_DATA_LEN};
use crate::mux::state::{mux_actions, MuxFrameActions, MuxOutTx};
use crate::mux::udp_dns::udp_socket_addr_without_dns;
use crate::outbound::freedom::{connect_tcp_destination, format_vless_destination};

pub(crate) async fn handle_mux_tcp_command(
    active: &mut Option<(u16, TcpStream)>,
    frame: MuxFrame,
) -> std::io::Result<MuxFrameActions> {
    let id = frame.mux_id;
    match frame.command {
        MuxCommand::Tcp {
            destination,
            initial_payload,
        } => {
            if active.is_some() {
                warn!(
                    mux_id = id,
                    "parallel mux substreams are not implemented yet"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            let destination_label = format_vless_destination(&destination.destination);
            debug!(
                mux_id = id,
                network = destination.network.as_str(),
                destination = %destination_label,
                "mux substream destination parsed"
            );
            let mut outbound = connect_tcp_destination(&destination.destination).await?;
            if !initial_payload.is_empty() {
                outbound.write_all(&initial_payload).await?;
            }
            debug!(mux_id = id, destination = %destination_label, "mux substream opened");
            *active = Some((id, outbound));
        }
        MuxCommand::Data { payload } => {
            let Some((active_id, outbound)) = active.as_mut() else {
                warn!(mux_id = id, "mux keep frame without active substream");
                return Ok(mux_actions(Vec::new()));
            };
            if *active_id != id {
                warn!(
                    mux_id = id,
                    active_mux_id = *active_id,
                    "mux frame for inactive substream"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            if !payload.is_empty() {
                outbound.write_all(&payload).await?;
            }
        }
        MuxCommand::Close { payload } => {
            let Some((active_id, mut outbound)) = active.take() else {
                debug!(mux_id = id, "mux end frame without active substream");
                return Ok(mux_actions(Vec::new()));
            };
            if active_id != id {
                warn!(
                    mux_id = id,
                    active_mux_id = active_id,
                    "mux end for inactive substream"
                );
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "parallel mux substreams are not implemented yet",
                ));
            }
            if !payload.is_empty() {
                outbound.write_all(&payload).await?;
            }
            let _ = outbound.shutdown().await;
            debug!(mux_id = id, "mux substream close");
        }
        MuxCommand::KeepAlive => {
            debug!(mux_id = id, "mux keepalive");
        }
        MuxCommand::Udp { .. } => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "udp mux command must be handled by udp_dns module",
            ));
        }
    }
    Ok(mux_actions(Vec::new()))
}

pub(crate) fn spawn_generic_udp_relay(
    id: u16,
    destination: crate::vless::protocol::VlessDestination,
    data: Vec<u8>,
    trace: Option<MuxSessionTrace>,
    received_at: Instant,
    udp_tx: MuxOutTx,
) {
    tokio::spawn(async move {
        let destination_label = format_vless_destination(&destination);
        let actions =
            match relay_generic_udp_packet(id, &destination, &data, trace, received_at).await {
                Ok(actions) => actions,
                Err(err) => {
                    warn!(
                        mux_id = id,
                        destination = %destination_label,
                        error = %err,
                        "mux generic udp relay error; closing substream"
                    );
                    mux_actions(vec![encode_mux_end(id)])
                }
            };
        if udp_tx.send(actions).is_err() {
            debug!(
                mux_id = id,
                destination = %destination_label,
                "mux generic udp response dropped because session writer is closed"
            );
        }
    });
}

async fn relay_generic_udp_packet(
    id: u16,
    destination: &crate::vless::protocol::VlessDestination,
    data: &[u8],
    trace: Option<MuxSessionTrace>,
    received_at: Instant,
) -> std::io::Result<MuxFrameActions> {
    let destination_label = format_vless_destination(destination);
    let Some(target) = udp_socket_addr_without_dns(destination) else {
        warn!(
            mux_id = id,
            network = "udp",
            destination = %destination_label,
            payload_len = data.len(),
            "UDP mux domain destination requires resolver support; closing substream"
        );
        return Ok(mux_actions(vec![encode_mux_end(id)]));
    };

    let timeout = DnsEngineOptions::from_env().mux_udp_dns_timeout;
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(target).await?;
    socket.send(data).await?;
    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %target,
        destination = %destination_label,
        payload_len = data.len(),
        timeout_ms = timeout.as_millis(),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux generic udp packet sent"
    );

    let mut buf = vec![0u8; MAX_MUX_DATA_LEN];
    let read = match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(read)) => read,
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            debug!(
                conn_id = trace.map(|trace| trace.conn_id),
                mux_id = id,
                %target,
                destination = %destination_label,
                timeout_ms = timeout.as_millis(),
                total_latency_ms = received_at.elapsed().as_millis(),
                elapsed_ms_since_conn_start =
                    trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                "mux generic udp response timeout"
            );
            return Ok(mux_actions(vec![encode_mux_end(id)]));
        }
    };
    buf.truncate(read);
    let frame = encode_mux_udp_packet(id, destination, &buf)?;
    let close_frame = mux_udp_send_close_after_response_enabled().then(|| encode_mux_end(id));
    debug!(
        conn_id = trace.map(|trace| trace.conn_id),
        mux_id = id,
        %target,
        destination = %destination_label,
        response_len = buf.len(),
        total_latency_ms = received_at.elapsed().as_millis(),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux generic udp response frame encoded"
    );
    let mut frames = vec![frame];
    if let Some(close_frame) = close_frame {
        frames.push(close_frame);
    }
    Ok(mux_actions(frames))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use crate::mux::encoder::encode_mux_new_udp;
    use crate::mux::frame::{
        MuxCommand, MuxDestination, MuxFrame, MuxNetwork, MuxOption, MuxStatus,
        ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE,
    };
    use crate::mux::parser::read_mux_frame;
    use crate::mux::session::handle_mux_cool_inbound;
    use crate::vless::protocol::VlessDestination;

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

    fn set_mux_udp_timeout_for_test(value: &str) -> Option<String> {
        let previous = std::env::var(crate::dns::options::ENV_MUX_DNS_TIMEOUT_MS).ok();
        std::env::set_var(crate::dns::options::ENV_MUX_DNS_TIMEOUT_MS, value);
        previous
    }

    fn restore_mux_udp_timeout_for_test(previous: Option<String>) {
        match previous {
            Some(value) => std::env::set_var(crate::dns::options::ENV_MUX_DNS_TIMEOUT_MS, value),
            None => std::env::remove_var(crate::dns::options::ENV_MUX_DNS_TIMEOUT_MS),
        }
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

    #[test]
    fn unsupported_udp_non_dns_closes_substream_without_panic() {
        block_on(async {
            let destination = VlessDestination::Domain("udp.example".to_string(), 54);
            let open = encode_mux_new_udp(16, &destination, b"not-dns");
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io
                .write_all(&open)
                .await
                .expect("write mux udp open");

            let handle = tokio::spawn(async move { handle_mux_cool_inbound(server_io).await });
            assert_eq!(
                read_mux_frame(&mut client_io).await.expect("read mux end"),
                MuxFrame {
                    mux_id: 16,
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
    fn generic_udp_relay_returns_mux_response_for_arbitrary_destination() {
        block_on(async {
            let _guard = env_lock();
            let previous_close = set_mux_udp_close_after_response_for_test("0");
            let udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind generic udp");
            let udp_port = udp.local_addr().expect("udp local addr").port();

            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let (read, peer) = udp.recv_from(&mut buf).await.expect("generic udp recv");
                assert_eq!(&buf[..read], b"hello");
                udp.send_to(b"world", peer).await.expect("generic udp send");
            });

            let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port);
            let open = encode_mux_new_udp(18, &destination, b"hello");
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io
                .write_all(&open)
                .await
                .expect("write generic udp open");

            let handle = tokio::spawn(async move { handle_mux_cool_inbound(server_io).await });
            assert_eq!(
                read_mux_frame(&mut client_io)
                    .await
                    .expect("read generic udp response"),
                MuxFrame {
                    mux_id: 18,
                    status: MuxStatus::Keep,
                    option: MuxOption { has_data: true },
                    command: MuxCommand::Udp {
                        destination: MuxDestination {
                            network: MuxNetwork::Udp,
                            destination,
                        },
                        packet: b"world".to_vec()
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
    fn generic_udp_slow_destination_does_not_block_next_mux_frame() {
        block_on(async {
            let _guard = env_lock();
            let previous = set_mux_udp_timeout_for_test("100");
            let previous_close = set_mux_udp_close_after_response_for_test("0");

            let silent_udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind silent udp");
            let silent_port = silent_udp.local_addr().expect("silent addr").port();
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = silent_udp.recv_from(&mut buf).await.expect("silent recv");
            });

            let fast_udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind fast udp");
            let fast_port = fast_udp.local_addr().expect("fast addr").port();
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let (read, peer) = fast_udp.recv_from(&mut buf).await.expect("fast recv");
                assert_eq!(&buf[..read], b"fast");
                fast_udp.send_to(b"ok", peer).await.expect("fast send");
            });

            let slow_destination =
                VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), silent_port);
            let fast_destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), fast_port);
            let slow_open = encode_mux_new_udp(30, &slow_destination, b"slow");
            let fast_open = encode_mux_new_udp(31, &fast_destination, b"fast");
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io
                .write_all(&slow_open)
                .await
                .expect("write slow udp open");
            client_io
                .write_all(&fast_open)
                .await
                .expect("write fast udp open");

            let handle = tokio::spawn(async move { handle_mux_cool_inbound(server_io).await });
            assert_eq!(
                read_mux_frame(&mut client_io)
                    .await
                    .expect("read fast response before slow timeout"),
                MuxFrame {
                    mux_id: 31,
                    status: MuxStatus::Keep,
                    option: MuxOption { has_data: true },
                    command: MuxCommand::Udp {
                        destination: MuxDestination {
                            network: MuxNetwork::Udp,
                            destination: fast_destination,
                        },
                        packet: b"ok".to_vec()
                    }
                }
            );
            assert_eq!(
                read_mux_frame(&mut client_io)
                    .await
                    .expect("read slow timeout end"),
                MuxFrame {
                    mux_id: 30,
                    status: MuxStatus::End,
                    option: MuxOption { has_data: false },
                    command: MuxCommand::Close {
                        payload: Vec::new()
                    }
                }
            );

            drop(client_io);
            handle.await.expect("join mux handler").unwrap();
            restore_mux_udp_timeout_for_test(previous);
            restore_mux_udp_close_after_response_for_test(previous_close);
        });
    }
}
