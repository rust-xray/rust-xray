use std::time::Duration;

use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use crate::vless::{build_proxy_protocol_v1, build_proxy_protocol_v2, validate_fallback_xver};

const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn is_benign_fallback_client_disconnect(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

pub async fn relay_fallback(
    client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
) -> std::io::Result<()> {
    relay_fallback_with_xver(client, dest_addr, initial_client_bytes, 0).await
}

pub async fn relay_fallback_with_xver(
    mut client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
    xver: u8,
) -> std::io::Result<()> {
    validate_fallback_xver(xver)?;

    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        "fallback relay started"
    );

    info!(%dest_addr, xver, "fallback target connect started");
    let mut dest = timeout(FALLBACK_CONNECT_TIMEOUT, TcpStream::connect(dest_addr))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "fallback connect to {dest_addr} timed out after {:?}",
                    FALLBACK_CONNECT_TIMEOUT
                ),
            )
        })??;
    info!(%dest_addr, xver, "fallback target connected");

    if xver == 1 || xver == 2 {
        let peer = client.peer_addr()?;
        let local = client.local_addr()?;
        let proxy_header = if xver == 1 {
            build_proxy_protocol_v1(peer, local)?
        } else {
            build_proxy_protocol_v2(peer, local)?
        };
        dest.write_all(&proxy_header).await?;
        info!(
            %dest_addr,
            proxy_header_len = proxy_header.len(),
            xver,
            "PROXY protocol header written"
        );
    }

    dest.write_all(initial_client_bytes).await?;
    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        "initial bytes forwarded"
    );

    let relay_result = copy_bidirectional(&mut client, &mut dest).await;
    let (client_to_dest, dest_to_client) = match relay_result {
        Ok(counts) => counts,
        Err(err)
            if !initial_client_bytes.is_empty() && is_benign_fallback_client_disconnect(&err) =>
        {
            info!(
                %dest_addr,
                xver,
                error = %err,
                "fallback client disconnected after initial bytes were forwarded"
            );
            (initial_client_bytes.len() as u64, 0)
        }
        Err(err) => return Err(err),
    };

    info!(
        %dest_addr,
        initial_bytes = initial_client_bytes.len(),
        xver,
        client_to_dest,
        dest_to_client,
        "fallback relay completed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{timeout, Duration};

    async fn read_until_initial(mut socket: TcpStream, initial: &[u8]) -> Vec<u8> {
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let read = timeout(Duration::from_secs(2), socket.read(&mut buf))
                .await
                .expect("read timeout")
                .expect("read fallback target");
            if read == 0 {
                break;
            }
            received.extend_from_slice(&buf[..read]);
            if received
                .windows(initial.len())
                .any(|window| window == initial)
            {
                break;
            }
        }
        received
    }

    async fn connected_inbound_stream() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind inbound listener");
        let inbound_addr = listener.local_addr().expect("inbound local addr");
        let client = TcpStream::connect(inbound_addr)
            .await
            .expect("connect inbound client");
        let (server, _) = listener.accept().await.expect("accept inbound");
        (client, server)
    }

    #[tokio::test]
    async fn relay_fallback_xver_1_writes_proxy_v1_before_initial_bytes() {
        let initial = b"CLIENT-INITIAL";
        let dest_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fallback target");
        let dest_addr = dest_listener
            .local_addr()
            .expect("fallback target addr")
            .to_string();
        let dest_task = tokio::spawn(async move {
            let (socket, _) = dest_listener.accept().await.expect("accept target");
            read_until_initial(socket, initial).await
        });

        let (client, server) = connected_inbound_stream().await;
        let relay_dest_addr = dest_addr.clone();
        let relay_task = tokio::spawn(async move {
            relay_fallback_with_xver(server, &relay_dest_addr, initial, 1).await
        });

        let received = dest_task.await.expect("target task");
        drop(client);
        let _ = relay_task.await.expect("relay task");

        let header_end = received
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("proxy v1 line terminator")
            + 2;
        assert!(received.starts_with(b"PROXY TCP4 "));
        assert_eq!(&received[header_end..header_end + initial.len()], initial);
    }

    #[tokio::test]
    async fn relay_fallback_xver_2_writes_proxy_v2_before_initial_bytes() {
        let initial = b"CLIENT-INITIAL";
        let dest_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fallback target");
        let dest_addr = dest_listener
            .local_addr()
            .expect("fallback target addr")
            .to_string();
        let dest_task = tokio::spawn(async move {
            let (socket, _) = dest_listener.accept().await.expect("accept target");
            read_until_initial(socket, initial).await
        });

        let (client, server) = connected_inbound_stream().await;
        let relay_dest_addr = dest_addr.clone();
        let relay_task = tokio::spawn(async move {
            relay_fallback_with_xver(server, &relay_dest_addr, initial, 2).await
        });

        let received = dest_task.await.expect("target task");
        drop(client);
        let _ = relay_task.await.expect("relay task");

        assert!(received.starts_with(&[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ]));
        let payload_offset = 28;
        assert_eq!(
            &received[payload_offset..payload_offset + initial.len()],
            initial
        );
    }
}
