use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::debug;

use crate::reality::tls13::{
    handle_split_relay_reader_overflow, useless_record_overflow_limit, Tls13OverflowAlertWriter,
};
use crate::stats::StatsConnection;
use crate::vless::udp_framing::{
    encode_vless_udp_packet, VlessUdpPacketDecoder, VLESS_UDP_MAX_PACKET_LEN,
};
use crate::vless::udp_session::VlessUdpRelayOptions;

const UDP_RELAY_READ_BUF: usize = 16 * 1024;
const DOWNLINK_QUEUE_CAPACITY: usize = 64;

/// Bidirectional VLESS UDP relay over a single reader/writer pair.
pub async fn relay_vless_udp_split<R, W>(
    mut reader: R,
    mut writer: W,
    udp: Option<Arc<UdpSocket>>,
    target: Option<SocketAddr>,
    blackhole: bool,
    initial_payload: Vec<u8>,
    stats: Option<&StatsConnection>,
    options: VlessUdpRelayOptions,
) -> std::io::Result<(u64, u64)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    relay_vless_udp_split_inner(
        &mut reader,
        &mut writer,
        udp,
        target,
        blackhole,
        initial_payload,
        stats,
        options,
    )
    .await
}

/// REALITY split relay with useless-record overflow fatal alert emission on the same writer.
pub async fn relay_vless_udp_split_with_overflow_alert<R, W>(
    mut reader: R,
    mut writer: W,
    udp: Option<Arc<UdpSocket>>,
    target: Option<SocketAddr>,
    blackhole: bool,
    initial_payload: Vec<u8>,
    stats: Option<&StatsConnection>,
    options: VlessUdpRelayOptions,
) -> std::io::Result<(u64, u64)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Tls13OverflowAlertWriter,
{
    match relay_vless_udp_split_inner(
        &mut reader,
        &mut writer,
        udp,
        target,
        blackhole,
        initial_payload,
        stats,
        options,
    )
    .await
    {
        Err(err) if useless_record_overflow_limit(&err).is_some() => {
            handle_split_relay_reader_overflow(&mut writer, err).await
        }
        other => other,
    }
}

async fn relay_vless_udp_split_inner<R, W>(
    reader: &mut R,
    writer: &mut W,
    udp: Option<Arc<UdpSocket>>,
    target: Option<SocketAddr>,
    blackhole: bool,
    initial_payload: Vec<u8>,
    stats: Option<&StatsConnection>,
    options: VlessUdpRelayOptions,
) -> std::io::Result<(u64, u64)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let _stats = stats;
    let downlink_grace = options.downlink_grace_after_uplink_eof;
    let (downlink_tx, mut downlink_rx) = mpsc::channel(DOWNLINK_QUEUE_CAPACITY);
    let mut decoder = VlessUdpPacketDecoder::new();
    decoder.push(&initial_payload);

    let mut uplink_bytes = 0u64;
    let mut downlink_bytes = 0u64;
    let mut read_buf = vec![0u8; UDP_RELAY_READ_BUF];
    let mut uplink_open = true;
    let mut uplink_eof = false;
    let mut downlink_open = !blackhole && udp.is_some();

    let udp_for_recv = udp.clone();
    let recv_task = if downlink_open {
        Some(tokio::spawn(async move {
            let socket = udp_for_recv.expect("udp socket");
            let mut buf = vec![0u8; VLESS_UDP_MAX_PACKET_LEN];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, _peer)) => {
                        if len == 0 {
                            continue;
                        }
                        if downlink_tx
                            .send(Ok(Bytes::copy_from_slice(&buf[..len])))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = downlink_tx.send(Err(err)).await;
                        break;
                    }
                }
            }
        }))
    } else {
        None
    };

    let relay_result = async {
        loop {
            if !uplink_open && !downlink_open {
                break;
            }

            tokio::select! {
                read_result = async {
                    if !uplink_open {
                        std::future::pending::<std::io::Result<usize>>().await
                    } else {
                        reader.read(&mut read_buf).await
                    }
                }, if uplink_open => {
                    match read_result {
                        Ok(0) => {
                            uplink_open = false;
                            uplink_eof = true;
                            decoder.mark_eof();
                            while let Some(packet) = decoder.next_packet()? {
                                if !blackhole {
                                    if let (Some(socket), Some(addr)) = (udp.as_ref(), target) {
                                        socket.send_to(&packet, addr).await?;
                                        uplink_bytes += packet.len() as u64;
                                    }
                                } else {
                                    uplink_bytes += packet.len() as u64;
                                }
                            }
                        }
                        Ok(n) => {
                            decoder.push(&read_buf[..n]);
                            while let Some(packet) = decoder.next_packet()? {
                                if blackhole {
                                    uplink_bytes += packet.len() as u64;
                                    continue;
                                }
                                let (Some(socket), Some(addr)) = (udp.as_ref(), target) else {
                                    continue;
                                };
                                socket.send_to(&packet, addr).await?;
                                uplink_bytes += packet.len() as u64;
                            }
                        }
                        Err(err) => return Err(err),
                    }
                }
                packet = async {
                    if uplink_eof {
                        tokio::time::timeout(downlink_grace, downlink_rx.recv())
                            .await
                            .unwrap_or_default()
                    } else {
                        downlink_rx.recv().await
                    }
                }, if downlink_open => {
                    match packet {
                        Some(Ok(payload)) => {
                            let framed = encode_vless_udp_packet(&payload)?;
                            if framed.is_empty() {
                                continue;
                            }
                            writer.write_all(&framed).await?;
                            writer.flush().await?;
                            downlink_bytes += payload.len() as u64;
                        }
                        Some(Err(err)) => return Err(err),
                        None => {
                            downlink_open = false;
                        }
                    }
                }
            }
        }

        Ok((uplink_bytes, downlink_bytes))
    }
    .await;

    if let Some(task) = recv_task {
        task.abort();
        let _ = task.await;
    }

    relay_result.map(|(uplink, downlink)| {
        debug!(
            uplink_bytes = uplink,
            downlink_bytes = downlink,
            blackhole,
            "vless udp relay completed"
        );
        (uplink, downlink)
    })
}

pub async fn relay_vless_udp_bidirectional<S>(
    stream: S,
    udp: Option<Arc<UdpSocket>>,
    target: Option<SocketAddr>,
    blackhole: bool,
    initial_payload: Vec<u8>,
    stats: Option<&StatsConnection>,
    options: VlessUdpRelayOptions,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    relay_vless_udp_split(
        reader,
        writer,
        udp,
        target,
        blackhole,
        initial_payload,
        stats,
        options,
    )
    .await
}

#[cfg(test)]
#[path = "../../tests/unit/vless/udp_relay.rs"]
mod udp_relay_tests;

#[cfg(test)]
#[path = "../../tests/unit/vless/udp_reality_overflow.rs"]
mod udp_reality_overflow_tests;
