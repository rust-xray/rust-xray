use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::AsRawFd;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::config::{LimitFallback, XrayConfig};
use crate::proxy::{relay_fallback_with_options, relay_fallback_with_xver, FallbackRelayOptions};
use crate::stats::{StatsRegistry, StatsSession, StatsState};

use super::write_all_counted;

struct PartialThenErrorWriter {
    remaining_before_error: usize,
    max_write: usize,
}

impl AsyncWrite for PartialThenErrorWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.remaining_before_error == 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected write failure",
            )));
        }
        let written = buf
            .len()
            .min(self.max_write)
            .min(self.remaining_before_error);
        self.remaining_before_error -= written;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn connected_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = TcpStream::connect(addr).await.expect("connect");
    let (server, _) = listener.accept().await.expect("accept");
    (client, server)
}

async fn read_until_contains(socket: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buf = [0_u8; 1024];
    while !received
        .windows(needle.len())
        .any(|window| window == needle)
    {
        let n = timeout(Duration::from_secs(2), socket.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read response");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    received
}

async fn bind_echo_target() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target addr").to_string();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept target");
        let mut buf = [0u8; 4096];
        loop {
            let n = socket.read(&mut buf).await.expect("target read");
            if n == 0 {
                break;
            }
            socket.write_all(&buf[..n]).await.expect("target echo");
        }
    });
    (addr, task)
}

fn test_stats_setup() -> (StatsSession, Arc<StatsRegistry>) {
    let registry = Arc::new(StatsRegistry::new());
    let xray: XrayConfig = serde_json::from_str(r#"{"stats": {}}"#).expect("parse stats config");
    let state = StatsState::from_xray_config_with_registry(
        &xray,
        Arc::clone(&registry),
        "reality-in".to_string(),
    );
    let session = StatsSession::new(
        Arc::clone(&registry),
        state.base_policy,
        state.policy_config.as_deref(),
        "reality-in".to_string(),
        "direct".to_string(),
        None,
        None,
        None,
    );
    (session, registry)
}

fn relay_options(xver: u8, upload: LimitFallback, download: LimitFallback) -> FallbackRelayOptions {
    FallbackRelayOptions::with_reality_limits(xver, upload, download)
}

#[cfg(unix)]
fn reset_tcp_stream_on_drop(stream: &std::net::TcpStream) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `stream` owns a valid socket fd and `linger` has the exact platform C layout.
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(
        result,
        0,
        "configure target RST: {}",
        std::io::Error::last_os_error()
    );
}

#[tokio::test]
async fn partial_write_before_error_is_retained_in_relay_count() {
    let mut writer = PartialThenErrorWriter {
        remaining_before_error: 5,
        max_write: 3,
    };
    let mut total = 0;

    let err = write_all_counted(&mut writer, b"ten-bytes!", &mut total)
        .await
        .expect_err("writer must fail after partial progress");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(total, 5);
}

#[tokio::test]
async fn upload_limit_only_slows_client_to_target() {
    let initial = b"INIT";
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("addr").to_string();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let started = Instant::now();
        let mut total = 0_usize;
        let mut buf = [0u8; 4096];
        while total < 20 * 1024 {
            let n = socket.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            total += n;
        }
        (total, started.elapsed())
    });

    let (mut client, server) = connected_pair().await;
    let relay = tokio::spawn(async move {
        relay_fallback_with_options(
            server,
            &addr,
            initial,
            relay_options(
                0,
                LimitFallback {
                    after_bytes: 0,
                    bytes_per_sec: 4_096,
                    burst_bytes_per_sec: 4_096,
                },
                LimitFallback::default(),
            ),
            None,
        )
        .await
        .expect("relay")
    });

    client
        .write_all(&[b'X'; 20 * 1024])
        .await
        .expect("write payload");

    drop(client);
    relay.await.expect("relay join");
    let (received, elapsed) = target_task.await.expect("target");
    assert!(received >= 20 * 1024);
    assert!(
        elapsed >= Duration::from_secs(3),
        "upload limit should throttle client->target delivery"
    );
}

#[tokio::test]
async fn download_limit_only_slows_target_to_client() {
    let initial = b"INIT";
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("addr").to_string();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        socket
            .write_all(&[b'Y'; 24 * 1024])
            .await
            .expect("write bulk");
        socket.shutdown().await.expect("target half-close");
        let mut buf = [0_u8; 256];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    });

    let (mut client, server) = connected_pair().await;
    let relay = tokio::spawn(async move {
        relay_fallback_with_options(
            server,
            &addr,
            initial,
            relay_options(
                0,
                LimitFallback::default(),
                LimitFallback {
                    after_bytes: 0,
                    bytes_per_sec: 4_096,
                    burst_bytes_per_sec: 4_096,
                },
            ),
            None,
        )
        .await
        .expect("relay")
    });

    client.write_all(b"trigger").await.expect("write trigger");
    let started = Instant::now();
    let mut buf = vec![0_u8; 64 * 1024];
    let mut total = 0_usize;
    while total < 20 * 1024 {
        let n = timeout(Duration::from_secs(10), client.read(&mut buf[total..]))
            .await
            .expect("read timeout")
            .expect("read bulk");
        if n == 0 {
            break;
        }
        total += n;
    }
    assert!(total >= 20 * 1024);

    drop(client);
    relay.await.expect("relay join");
    target_task.await.expect("target");
    assert!(
        started.elapsed() >= Duration::from_secs(3),
        "download limit should throttle target->client delivery"
    );
}

#[tokio::test]
async fn after_bytes_applies_after_initial_bytes_not_consuming_grace() {
    let initial = vec![b'A'; 32 * 1024];
    let payload = vec![b'B'; 8 * 1024];
    let expected_len = initial.len() + payload.len();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target addr").to_string();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept target");
        let mut received = vec![0_u8; expected_len];
        timeout(Duration::from_secs(2), socket.read_exact(&mut received))
            .await
            .expect("initial and grace bytes must not be rate limited")
            .expect("read initial and grace bytes");
        received
    });
    let (mut client, server) = connected_pair().await;
    let relay_initial = initial.clone();

    let relay = tokio::spawn(async move {
        relay_fallback_with_options(
            server,
            &addr,
            &relay_initial,
            relay_options(
                0,
                LimitFallback {
                    after_bytes: 16 * 1024,
                    bytes_per_sec: 1,
                    burst_bytes_per_sec: 1,
                },
                LimitFallback::default(),
            ),
            None,
        )
        .await
        .expect("relay")
    });

    client
        .write_all(&payload)
        .await
        .expect("write grace payload");
    client.shutdown().await.expect("client half-close");
    let received = target_task.await.expect("target");
    assert_eq!(&received[..initial.len()], initial.as_slice());
    assert_eq!(&received[initial.len()..], payload.as_slice());
    drop(client);
    relay.await.expect("relay join");
}

#[tokio::test]
async fn proxy_v1_and_v2_still_work_with_limits() {
    for xver in [1_u8, 2] {
        let initial = b"CLIENT";
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let target_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            read_until_contains(&mut socket, initial).await
        });

        let (client, server) = connected_pair().await;
        let (session, registry) = test_stats_setup();
        let relay = tokio::spawn(async move {
            relay_fallback_with_options(
                server,
                &addr,
                initial,
                relay_options(
                    xver,
                    LimitFallback {
                        after_bytes: 0,
                        bytes_per_sec: 1,
                        burst_bytes_per_sec: 1,
                    },
                    LimitFallback::default(),
                ),
                Some(&session),
            )
            .await
        });

        drop(client);
        relay.await.expect("relay").expect("relay ok");
        let received = target_task.await.expect("target");
        if xver == 1 {
            assert!(received.starts_with(b"PROXY TCP4 "));
        } else {
            assert_eq!(
                &received[..12],
                [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]
            );
        }
        assert!(received.ends_with(initial));
        assert_eq!(
            registry
                .get("inbound>>>reality-in>>>traffic>>>uplink", false)
                .expect("uplink stat"),
            initial.len() as i64,
            "PROXY header bytes must not enter application stats"
        );
    }
}

#[tokio::test]
async fn client_fin_allows_target_response() {
    let initial = b"INIT";
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0_u8; 64];
        let _ = socket.read(&mut buf).await.expect("read client");
        socket.write_all(b"response").await.expect("write response");
        let _ = socket.read(&mut buf).await;
    });

    let (mut client, server) = connected_pair().await;
    let relay = tokio::spawn(async move {
        relay_fallback_with_options(
            server,
            &addr,
            initial,
            relay_options(
                0,
                LimitFallback {
                    after_bytes: 0,
                    bytes_per_sec: 1_000_000,
                    burst_bytes_per_sec: 1_000_000,
                },
                LimitFallback {
                    after_bytes: 0,
                    bytes_per_sec: 1_000_000,
                    burst_bytes_per_sec: 1_000_000,
                },
            ),
            None,
        )
        .await
    });

    client.write_all(b"ping").await.expect("write");
    client.shutdown().await.expect("client fin");
    let mut response = [0_u8; 8];
    timeout(Duration::from_secs(2), client.read_exact(&mut response))
        .await
        .expect("timeout")
        .expect("read response");
    assert_eq!(&response, b"response");

    relay.await.expect("relay").expect("relay ok");
    target_task.await.expect("target");
}

#[tokio::test]
async fn target_fin_allows_later_client_upload() {
    let initial = b"INIT";
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut initial_buf = [0_u8; 4];
        socket
            .read_exact(&mut initial_buf)
            .await
            .expect("read initial");
        socket.write_all(b"response").await.expect("write response");
        socket.shutdown().await.expect("target write half-close");
        let mut later = [0_u8; 5];
        socket
            .read_exact(&mut later)
            .await
            .expect("read later upload");
        later
    });

    let (mut client, server) = connected_pair().await;
    let relay = tokio::spawn(async move {
        relay_fallback_with_options(
            server,
            &addr,
            initial,
            relay_options(
                0,
                LimitFallback::default(),
                LimitFallback {
                    after_bytes: 0,
                    bytes_per_sec: 1_000_000,
                    burst_bytes_per_sec: 1_000_000,
                },
            ),
            None,
        )
        .await
    });

    let mut response = [0_u8; 8];
    client
        .read_exact(&mut response)
        .await
        .expect("read response");
    assert_eq!(&response, b"response");
    let mut eof = [0_u8; 1];
    assert_eq!(client.read(&mut eof).await.expect("read target FIN"), 0);

    client
        .write_all(b"later")
        .await
        .expect("write after target FIN");
    client.shutdown().await.expect("client FIN");
    assert_eq!(target_task.await.expect("target"), *b"later");
    timeout(Duration::from_secs(2), relay)
        .await
        .expect("relay must finish")
        .expect("relay task")
        .expect("relay result");
}

#[cfg(unix)]
#[tokio::test]
async fn stats_count_initial_bytes_exactly_once_including_benign_disconnect() {
    let initial = b"INITIAL-BYTES";
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = [0_u8; 256];
        let _ = socket.read(&mut buf).await;
    });

    let (client, server) = connected_pair().await;
    let (session, registry) = test_stats_setup();
    let relay = tokio::spawn(async move {
        relay_fallback_with_xver(server, &addr, initial, 0, Some(&session)).await
    });

    let std_client = client.into_std().expect("convert client socket");
    reset_tcp_stream_on_drop(&std_client);
    drop(std_client);
    relay.await.expect("relay").expect("relay ok");
    target_task.abort();

    assert_eq!(
        registry
            .get("inbound>>>reality-in>>>traffic>>>uplink", false)
            .expect("uplink stat"),
        initial.len() as i64
    );
    assert_eq!(
        registry
            .get("inbound>>>reality-in>>>traffic>>>downlink", false)
            .unwrap_or(0),
        0
    );
}

#[cfg(unix)]
#[tokio::test]
async fn real_target_error_cancels_idle_upload_and_preserves_completed_stats() {
    let initial = b"INITIAL";
    let payload = b"relayed-upload";
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut received = vec![0_u8; initial.len() + payload.len()];
        socket
            .read_exact(&mut received)
            .await
            .expect("read forwarded bytes");
        let std_socket = socket.into_std().expect("convert target socket");
        reset_tcp_stream_on_drop(&std_socket);
        drop(std_socket);
        received
    });

    let (mut client, server) = connected_pair().await;
    let (session, registry) = test_stats_setup();
    let relay = tokio::spawn(async move {
        relay_fallback_with_options(
            server,
            &addr,
            initial,
            relay_options(
                0,
                LimitFallback {
                    after_bytes: 0,
                    bytes_per_sec: 1_000_000,
                    burst_bytes_per_sec: 1_000_000,
                },
                LimitFallback::default(),
            ),
            Some(&session),
        )
        .await
    });

    client.write_all(payload).await.expect("write upload");
    let received = target_task.await.expect("target");
    assert_eq!(received, [initial.as_slice(), payload.as_slice()].concat());

    let relay_error = timeout(Duration::from_secs(2), relay)
        .await
        .expect("target error must cancel idle upload")
        .expect("relay task")
        .expect_err("target RST is a real relay error");
    assert!(matches!(
        relay_error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    ));
    assert_eq!(
        registry
            .get("inbound>>>reality-in>>>traffic>>>uplink", false)
            .expect("uplink stat"),
        (initial.len() + payload.len()) as i64
    );
    assert_eq!(
        registry
            .get("inbound>>>reality-in>>>traffic>>>downlink", false)
            .unwrap_or(0),
        0
    );
}

#[tokio::test]
async fn disabled_limits_use_fast_path_like_unlimited() {
    let initial = b"INIT";
    let (addr, target_task) = bind_echo_target().await;
    let (mut client, server) = connected_pair().await;
    let (session, registry) = test_stats_setup();

    let relay = tokio::spawn(async move {
        relay_fallback_with_options(
            server,
            &addr,
            initial,
            relay_options(0, LimitFallback::default(), LimitFallback::default()),
            Some(&session),
        )
        .await
    });

    client.write_all(b"hello").await.expect("write");
    let received = read_until_contains(&mut client, b"hello").await;
    assert!(received.windows(5).any(|window| window == b"hello"));

    client.shutdown().await.expect("client FIN");
    drop(client);
    relay.await.expect("relay").expect("relay ok");
    target_task.await.expect("target");
    let expected = (initial.len() + b"hello".len()) as i64;
    assert_eq!(
        registry
            .get("inbound>>>reality-in>>>traffic>>>uplink", false)
            .expect("uplink stat"),
        expected
    );
    assert_eq!(
        registry
            .get("inbound>>>reality-in>>>traffic>>>downlink", false)
            .expect("downlink stat"),
        expected
    );
}
