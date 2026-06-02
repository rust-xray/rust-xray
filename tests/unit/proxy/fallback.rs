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
        relay_fallback_with_xver(server, &relay_dest_addr, initial, 1, None).await
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
        relay_fallback_with_xver(server, &relay_dest_addr, initial, 2, None).await
    });

    let received = dest_task.await.expect("target task");
    drop(client);
    let _ = relay_task.await.expect("relay task");

    assert_eq!(
        &received[..12],
        [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]
    );
    assert_eq!(received[12], 0x21);
    assert_eq!(received[13], 0x11);
    assert_eq!(&received[14..16], &[0x00, 0x0C]);
    let header_len = 16 + u16::from_be_bytes([received[14], received[15]]) as usize;
    assert_eq!(header_len, 28);
    assert_eq!(&received[header_len..header_len + initial.len()], initial);
}
