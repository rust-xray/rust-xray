use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time;
use tracing::{debug, info, trace, warn};

use crate::dns::parse_dns_question_for_log;
use crate::outbound::freedom::{connect_tcp_destination, format_vless_destination};
use crate::vless::protocol::VlessDestination;

const MUX_OPT_DATA: u8 = 0x01;
const MUX_STATUS_NEW: u8 = 0x01;
const MUX_STATUS_KEEP: u8 = 0x02;
const MUX_STATUS_END: u8 = 0x03;
const MUX_STATUS_KEEPALIVE: u8 = 0x04;
const MUX_NETWORK_TCP: u8 = 0x01;
const MUX_NETWORK_UDP: u8 = 0x02;
const MAX_MUX_METADATA_LEN: usize = 512;
const MAX_MUX_DATA_LEN: usize = 65_535;
#[cfg(not(test))]
const UDP_DNS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const UDP_DNS_RESPONSE_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxNetwork {
    Tcp,
    Udp,
}

impl MuxNetwork {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxDestination {
    pub network: MuxNetwork,
    pub destination: VlessDestination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxFrame {
    New {
        id: u16,
        destination: MuxDestination,
        data: Vec<u8>,
    },
    Keep {
        id: u16,
        destination: Option<MuxDestination>,
        data: Vec<u8>,
    },
    End {
        id: u16,
        data: Vec<u8>,
    },
    KeepAlive {
        id: u16,
    },
}

impl MuxFrame {
    pub fn id(&self) -> u16 {
        match self {
            Self::New { id, .. }
            | Self::Keep { id, .. }
            | Self::End { id, .. }
            | Self::KeepAlive { id } => *id,
        }
    }
}

pub fn parse_mux_frame(metadata: &[u8], extra: &[u8]) -> std::io::Result<MuxFrame> {
    if metadata.len() < 4 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "truncated mux metadata",
        ));
    }
    let id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let opt = metadata[3];
    let payload_len = mux_data_len(extra).unwrap_or(0);
    let data = if opt & MUX_OPT_DATA != 0 {
        parse_mux_data(extra)?
    } else {
        Vec::new()
    };

    let frame = match status {
        MUX_STATUS_NEW => {
            let (destination, consumed) = parse_mux_destination(&metadata[4..])?;
            if consumed + 4 != metadata.len() {
                debug!(
                    id,
                    trailing = metadata.len().saturating_sub(consumed + 4),
                    "mux new frame ignored trailing metadata"
                );
            }
            Ok(MuxFrame::New {
                id,
                destination,
                data,
            })
        }
        MUX_STATUS_KEEP
            if metadata
                .get(4)
                .is_some_and(|network| *network == MUX_NETWORK_UDP) =>
        {
            let (destination, consumed) = parse_mux_destination(&metadata[4..])?;
            if consumed + 4 != metadata.len() {
                debug!(
                    id,
                    trailing = metadata.len().saturating_sub(consumed + 4),
                    "mux keep frame ignored trailing metadata"
                );
            }
            Ok(MuxFrame::Keep {
                id,
                destination: Some(destination),
                data,
            })
        }
        MUX_STATUS_KEEP => Ok(MuxFrame::Keep {
            id,
            destination: None,
            data,
        }),
        MUX_STATUS_END => Ok(MuxFrame::End { id, data }),
        MUX_STATUS_KEEPALIVE => Ok(MuxFrame::KeepAlive { id }),
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("unsupported mux frame status: 0x{other:02x}"),
        )),
    }?;

    log_mux_frame_parsed(id, status, opt, metadata, payload_len, &frame);
    Ok(frame)
}

pub async fn read_mux_frame<R>(reader: &mut R) -> std::io::Result<MuxFrame>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes).await?;
    let metadata_len = u16::from_be_bytes(len_bytes) as usize;
    if metadata_len == 0 || metadata_len > MAX_MUX_METADATA_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid mux metadata length: {metadata_len}"),
        ));
    }
    let mut metadata = vec![0u8; metadata_len];
    reader.read_exact(&mut metadata).await?;
    let has_data = metadata.get(3).is_some_and(|opt| opt & MUX_OPT_DATA != 0);
    let mut extra = Vec::new();
    if has_data {
        let mut data_len = [0u8; 2];
        reader.read_exact(&mut data_len).await?;
        let data_len = u16::from_be_bytes(data_len) as usize;
        if data_len == 0 || data_len > MAX_MUX_DATA_LEN {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("invalid mux data length: {data_len}"),
            ));
        }
        extra.resize(data_len + 2, 0);
        extra[..2].copy_from_slice(&(data_len as u16).to_be_bytes());
        reader.read_exact(&mut extra[2..]).await?;
    }
    parse_mux_frame(&metadata, &extra)
}

pub fn encode_mux_keep_data(id: u16, data: &[u8]) -> std::io::Result<Vec<u8>> {
    encode_mux_frame_header(id, MUX_STATUS_KEEP, data)
}

pub fn encode_mux_udp_packet(
    id: u16,
    destination: &VlessDestination,
    data: &[u8],
) -> std::io::Result<Vec<u8>> {
    encode_mux_frame_with_destination(MuxNetwork::Udp, MUX_STATUS_KEEP, id, destination, data)
}

pub fn encode_mux_end(id: u16) -> Vec<u8> {
    let metadata = [id.to_be_bytes()[0], id.to_be_bytes()[1], MUX_STATUS_END, 0];
    let mut frame = Vec::with_capacity(6);
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame
}

fn encode_mux_frame_header(id: u16, status: u8, data: &[u8]) -> std::io::Result<Vec<u8>> {
    if data.is_empty() || data.len() > MAX_MUX_DATA_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("invalid mux data length: {}", data.len()),
        ));
    }
    let metadata = [
        id.to_be_bytes()[0],
        id.to_be_bytes()[1],
        status,
        MUX_OPT_DATA,
    ];
    let mut frame = Vec::with_capacity(2 + metadata.len() + 2 + data.len());
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

fn encode_mux_frame_with_destination(
    network: MuxNetwork,
    status: u8,
    id: u16,
    destination: &VlessDestination,
    data: &[u8],
) -> std::io::Result<Vec<u8>> {
    if data.is_empty() || data.len() > MAX_MUX_DATA_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("invalid mux data length: {}", data.len()),
        ));
    }

    let mut metadata = Vec::new();
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.push(status);
    metadata.push(MUX_OPT_DATA);
    metadata.push(match network {
        MuxNetwork::Tcp => MUX_NETWORK_TCP,
        MuxNetwork::Udp => MUX_NETWORK_UDP,
    });
    write_mux_destination_metadata(&mut metadata, destination)?;

    let mut frame = Vec::new();
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

fn write_mux_destination_metadata(
    metadata: &mut Vec<u8>,
    destination: &VlessDestination,
) -> std::io::Result<()> {
    match destination {
        VlessDestination::Ip(IpAddr::V4(ip), port) => {
            metadata.extend_from_slice(&port.to_be_bytes());
            metadata.push(0x01);
            metadata.extend_from_slice(&ip.octets());
        }
        VlessDestination::Ip(IpAddr::V6(ip), port) => {
            metadata.extend_from_slice(&port.to_be_bytes());
            metadata.push(0x03);
            metadata.extend_from_slice(&ip.octets());
        }
        VlessDestination::Domain(domain, port) => {
            if domain.len() > u8::MAX as usize {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "mux domain destination is too long",
                ));
            }
            metadata.extend_from_slice(&port.to_be_bytes());
            metadata.push(0x02);
            metadata.push(domain.len() as u8);
            metadata.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

fn parse_mux_data(extra: &[u8]) -> std::io::Result<Vec<u8>> {
    if extra.len() < 2 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "truncated mux data length",
        ));
    }
    let len = u16::from_be_bytes([extra[0], extra[1]]) as usize;
    if len == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "mux data length must not be zero",
        ));
    }
    if extra.len() < len + 2 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "truncated mux data payload",
        ));
    }
    Ok(extra[2..2 + len].to_vec())
}

fn mux_data_len(extra: &[u8]) -> Option<usize> {
    if extra.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([extra[0], extra[1]]) as usize)
}

fn parse_mux_destination(input: &[u8]) -> std::io::Result<(MuxDestination, usize)> {
    if input.len() < 4 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "truncated mux destination",
        ));
    }
    let network = input[0];
    let network = match network {
        MUX_NETWORK_TCP => MuxNetwork::Tcp,
        MUX_NETWORK_UDP => MuxNetwork::Udp,
        other => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("unsupported mux network: 0x{other:02x}"),
            ));
        }
    };
    let port = u16::from_be_bytes([input[1], input[2]]);
    let addr_type = input[3];
    let mut offset = 4;
    let destination = match addr_type {
        0x01 => {
            let bytes = input.get(offset..offset + 4).ok_or_else(|| {
                Error::new(ErrorKind::UnexpectedEof, "truncated mux IPv4 address")
            })?;
            offset += 4;
            VlessDestination::Ip(
                IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
                port,
            )
        }
        0x02 => {
            let len = *input.get(offset).ok_or_else(|| {
                Error::new(ErrorKind::UnexpectedEof, "truncated mux domain length")
            })? as usize;
            offset += 1;
            let bytes = input
                .get(offset..offset + len)
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "truncated mux domain"))?;
            offset += len;
            let domain = String::from_utf8(bytes.to_vec()).map_err(|err| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid mux domain utf-8: {err}"),
                )
            })?;
            VlessDestination::Domain(domain, port)
        }
        0x03 => {
            let bytes = input.get(offset..offset + 16).ok_or_else(|| {
                Error::new(ErrorKind::UnexpectedEof, "truncated mux IPv6 address")
            })?;
            offset += 16;
            let addr = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).expect("slice length checked"));
            VlessDestination::Ip(IpAddr::V6(addr), port)
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown mux address type: 0x{other:02x}"),
            ));
        }
    };
    Ok((
        MuxDestination {
            network,
            destination,
        },
        offset,
    ))
}

fn log_mux_frame_parsed(
    id: u16,
    status: u8,
    opt: u8,
    metadata: &[u8],
    payload_len: usize,
    frame: &MuxFrame,
) {
    let network = match frame {
        MuxFrame::New { destination, .. } => Some(destination.network.as_str()),
        MuxFrame::Keep {
            destination: Some(destination),
            ..
        } => Some(destination.network.as_str()),
        _ => None,
    };
    let destination = match frame {
        MuxFrame::New { destination, .. }
        | MuxFrame::Keep {
            destination: Some(destination),
            ..
        } => Some(format_vless_destination(&destination.destination)),
        _ => None,
    };
    let address_type = metadata.get(7).copied();
    trace!(
        mux_id = id,
        metadata_len = metadata.len(),
        status = format_args!("0x{status:02x}"),
        option = format_args!("0x{opt:02x}"),
        network,
        address_type = address_type.map(|value| format!("0x{value:02x}")),
        destination = destination.as_deref(),
        payload_len,
        "mux frame parsed"
    );
    trace!(
        mux_id = id,
        preview_len = metadata.len().min(64),
        preview = %hex_preview(metadata, 64),
        "mux frame metadata preview"
    );
}

fn hex_preview(bytes: &[u8], max_len: usize) -> String {
    let mut out = String::new();
    for (idx, byte) in bytes.iter().take(max_len).enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub async fn handle_mux_cool_inbound<S>(mut stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    info!("mux session started");
    let mut active: Option<(u16, TcpStream)> = None;
    let mut buf = [0u8; 8192];

    loop {
        if let Some((id, outbound)) = active.as_mut() {
            tokio::select! {
                frame = read_mux_frame(&mut stream) => {
                    let frame = frame?;
                    let actions = handle_client_frame(&mut active, frame).await?;
                    for frame in actions {
                        stream.write_all(&frame).await?;
                    }
                    stream.flush().await?;
                }
                read = outbound.read(&mut buf) => {
                    let read = read?;
                    if read == 0 {
                        stream.write_all(&encode_mux_end(*id)).await?;
                        stream.flush().await?;
                        debug!(mux_id = *id, "mux substream relay completed");
                        active = None;
                    } else {
                        let frame = encode_mux_keep_data(*id, &buf[..read])?;
                        stream.write_all(&frame).await?;
                        stream.flush().await?;
                    }
                }
            }
        } else {
            match read_mux_frame(&mut stream).await {
                Ok(frame) => {
                    let actions = handle_client_frame(&mut active, frame).await?;
                    for frame in actions {
                        stream.write_all(&frame).await?;
                    }
                    stream.flush().await?;
                }
                Err(err) if err.kind() == ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err),
            }
        }
    }

    info!("mux session completed");
    Ok(())
}

async fn handle_client_frame(
    active: &mut Option<(u16, TcpStream)>,
    frame: MuxFrame,
) -> std::io::Result<Vec<Vec<u8>>> {
    match frame {
        MuxFrame::New {
            id,
            destination,
            data,
        } => {
            if destination.network == MuxNetwork::Udp {
                debug!(mux_id = id, "mux udp substream opened");
                return handle_udp_mux_packet(id, destination.destination, data).await;
            }
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
            if !data.is_empty() {
                outbound.write_all(&data).await?;
            }
            debug!(mux_id = id, destination = %destination_label, "mux substream opened");
            *active = Some((id, outbound));
        }
        MuxFrame::Keep {
            id,
            destination: Some(destination),
            data,
        } if destination.network == MuxNetwork::Udp => {
            return handle_udp_mux_packet(id, destination.destination, data).await;
        }
        MuxFrame::Keep { id, data, .. } => {
            let Some((active_id, outbound)) = active.as_mut() else {
                warn!(mux_id = id, "mux keep frame without active substream");
                return Ok(Vec::new());
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
            if !data.is_empty() {
                outbound.write_all(&data).await?;
            }
        }
        MuxFrame::End { id, data } => {
            let Some((active_id, mut outbound)) = active.take() else {
                debug!(mux_id = id, "mux end frame without active substream");
                return Ok(Vec::new());
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
            if !data.is_empty() {
                outbound.write_all(&data).await?;
            }
            let _ = outbound.shutdown().await;
            debug!(mux_id = id, "mux substream close");
        }
        MuxFrame::KeepAlive { id } => {
            debug!(mux_id = id, "mux keepalive");
        }
    }
    Ok(Vec::new())
}

async fn handle_udp_mux_packet(
    id: u16,
    destination: VlessDestination,
    data: Vec<u8>,
) -> std::io::Result<Vec<Vec<u8>>> {
    let destination_label = format_vless_destination(&destination);
    if !is_supported_udp_dns_destination(&destination) {
        warn!(
            mux_id = id,
            network = "udp",
            destination = %destination_label,
            payload_len = data.len(),
            "unsupported non-DNS UDP mux substream; closing substream"
        );
        return Ok(vec![encode_mux_end(id)]);
    }

    let Some(target) = udp_socket_addr_without_dns(&destination) else {
        warn!(
            mux_id = id,
            network = "udp",
            destination = %destination_label,
            payload_len = data.len(),
            "UDP mux DNS domain destination requires resolver support; closing substream"
        );
        return Ok(vec![encode_mux_end(id)]);
    };

    match relay_udp_dns_direct(id, target, &destination, &data).await? {
        Some(response) => Ok(vec![response, encode_mux_end(id)]),
        None => Ok(vec![encode_mux_end(id)]),
    }
}

async fn relay_udp_dns_direct(
    id: u16,
    target: SocketAddr,
    destination: &VlessDestination,
    query: &[u8],
) -> std::io::Result<Option<Vec<u8>>> {
    let destination_label = format_vless_destination(destination);
    let bind_addr = if target.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let question = parse_dns_question_for_log(query);
    debug!(
        mux_id = id,
        destination = %destination_label,
        payload_len = query.len(),
        qname = question.as_ref().map(|q| q.qname.as_str()),
        qtype = question.as_ref().map(|q| q.qtype),
        "mux udp dns using temporary direct udp path"
    );

    let start = Instant::now();
    socket.send_to(query, target).await?;
    debug!(
        mux_id = id,
        destination = %destination_label,
        payload_len = query.len(),
        "mux udp dns query forwarded"
    );

    let mut response = vec![0u8; MAX_MUX_DATA_LEN];
    let received =
        match time::timeout(UDP_DNS_RESPONSE_TIMEOUT, socket.recv_from(&mut response)).await {
            Ok(Ok((received, _peer))) => received,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                warn!(
                    mux_id = id,
                    destination = %destination_label,
                    timeout_ms = UDP_DNS_RESPONSE_TIMEOUT.as_millis(),
                    "mux udp dns response timeout"
                );
                return Ok(None);
            }
        };
    response.truncate(received);
    let latency_ms = start.elapsed().as_millis();
    debug!(
        mux_id = id,
        destination = %destination_label,
        response_len = response.len(),
        latency_ms,
        "mux udp dns response received"
    );
    let frame = encode_mux_udp_packet(id, destination, &response)?;
    debug!(
        mux_id = id,
        destination = %destination_label,
        response_len = response.len(),
        latency_ms,
        "mux udp response frame sent"
    );
    Ok(Some(frame))
}

fn destination_port(destination: &VlessDestination) -> u16 {
    match destination {
        VlessDestination::Ip(_, port) | VlessDestination::Domain(_, port) => *port,
    }
}

#[cfg(not(test))]
fn is_supported_udp_dns_destination(destination: &VlessDestination) -> bool {
    destination_port(destination) == 53
}

#[cfg(test)]
fn is_supported_udp_dns_destination(destination: &VlessDestination) -> bool {
    let port = destination_port(destination);
    port == 53 || port >= 1024
}

fn udp_socket_addr_without_dns(destination: &VlessDestination) -> Option<SocketAddr> {
    match destination {
        VlessDestination::Ip(ip, port) => Some(SocketAddr::new(*ip, *port)),
        VlessDestination::Domain(_, _) => None,
    }
}

#[cfg(test)]
pub(crate) fn encode_mux_new_tcp(id: u16, destination: &VlessDestination, data: &[u8]) -> Vec<u8> {
    encode_mux_new(MuxNetwork::Tcp, id, destination, data)
}

#[cfg(test)]
pub(crate) fn encode_mux_new_udp(id: u16, destination: &VlessDestination, data: &[u8]) -> Vec<u8> {
    encode_mux_new(MuxNetwork::Udp, id, destination, data)
}

#[cfg(test)]
fn encode_mux_keep_udp(id: u16, destination: &VlessDestination, data: &[u8]) -> Vec<u8> {
    encode_mux_udp_packet(id, destination, data).unwrap()
}

#[cfg(test)]
fn encode_mux_new(
    network: MuxNetwork,
    id: u16,
    destination: &VlessDestination,
    data: &[u8],
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.push(MUX_STATUS_NEW);
    metadata.push(if data.is_empty() { 0 } else { MUX_OPT_DATA });
    metadata.push(match network {
        MuxNetwork::Tcp => MUX_NETWORK_TCP,
        MuxNetwork::Udp => MUX_NETWORK_UDP,
    });
    write_mux_destination_metadata(&mut metadata, destination).unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    if !data.is_empty() {
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
    }
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_frame_parser_parses_basic_open_data_close_frames() {
        let destination = VlessDestination::Domain("example.com".to_string(), 443);
        let frame = encode_mux_new_tcp(1, &destination, b"GET / HTTP/1.1\r\n\r\n");
        let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let parsed =
            parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
        assert_eq!(
            parsed,
            MuxFrame::New {
                id: 1,
                destination: MuxDestination {
                    network: MuxNetwork::Tcp,
                    destination,
                },
                data: b"GET / HTTP/1.1\r\n\r\n".to_vec()
            }
        );

        let keep = encode_mux_keep_data(1, b"more").unwrap();
        let metadata_len = u16::from_be_bytes([keep[0], keep[1]]) as usize;
        assert_eq!(
            parse_mux_frame(&keep[2..2 + metadata_len], &keep[2 + metadata_len..]).unwrap(),
            MuxFrame::Keep {
                id: 1,
                destination: None,
                data: b"more".to_vec()
            }
        );

        let end = encode_mux_end(1);
        let metadata_len = u16::from_be_bytes([end[0], end[1]]) as usize;
        assert_eq!(
            parse_mux_frame(&end[2..2 + metadata_len], &[]).unwrap(),
            MuxFrame::End {
                id: 1,
                data: Vec::new()
            }
        );
    }

    #[test]
    fn malformed_mux_frame_rejected_safely() {
        assert!(parse_mux_frame(&[0, 1, MUX_STATUS_NEW], &[]).is_err());
        assert!(parse_mux_frame(&[0, 1, MUX_STATUS_NEW, MUX_OPT_DATA], &[0]).is_err());
        assert!(parse_mux_frame(&[0, 1, 0xff, 0], &[]).is_err());
    }

    #[test]
    fn mux_frame_parser_accepts_udp_network_0x02() {
        let destination = VlessDestination::Domain("dns.google".to_string(), 53);
        let frame = encode_mux_new_udp(7, &destination, b"\x12\x34dns");
        let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;

        assert_eq!(
            parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap(),
            MuxFrame::New {
                id: 7,
                destination: MuxDestination {
                    network: MuxNetwork::Udp,
                    destination,
                },
                data: b"\x12\x34dns".to_vec()
            }
        );
    }

    #[test]
    fn mux_frame_parser_accepts_udp_destination_on_keep_frame() {
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        let frame = encode_mux_keep_udp(9, &destination, b"\x01\x00");
        let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;

        assert_eq!(
            parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap(),
            MuxFrame::Keep {
                id: 9,
                destination: Some(MuxDestination {
                    network: MuxNetwork::Udp,
                    destination,
                }),
                data: b"\x01\x00".to_vec()
            }
        );
    }

    #[test]
    fn encode_mux_udp_response_frame_for_same_mux_id() {
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        let frame = encode_mux_udp_packet(11, &destination, b"\x81\x80").unwrap();
        let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;

        assert_eq!(
            parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap(),
            MuxFrame::Keep {
                id: 11,
                destination: Some(MuxDestination {
                    network: MuxNetwork::Udp,
                    destination,
                }),
                data: b"\x81\x80".to_vec()
            }
        );
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    #[test]
    fn udp_dns_relay_with_fake_udp_server_returns_mux_response() {
        block_on(async {
            let udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind fake udp dns");
            let udp_port = udp.local_addr().expect("udp local addr").port();
            let expected_query = b"\x12\x34dns-query".to_vec();
            let expected_response = b"\x12\x34dns-response".to_vec();
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

            let handle = tokio::spawn(async move { handle_mux_cool_inbound(server_io).await });

            let frame = read_mux_frame(&mut client_io)
                .await
                .expect("read mux udp response");
            assert_eq!(
                frame,
                MuxFrame::Keep {
                    id: 15,
                    destination: Some(MuxDestination {
                        network: MuxNetwork::Udp,
                        destination,
                    }),
                    data: expected_response
                }
            );

            assert_eq!(
                read_mux_frame(&mut client_io).await.expect("read mux end"),
                MuxFrame::End {
                    id: 15,
                    data: Vec::new()
                }
            );

            drop(client_io);
            handle.await.expect("join mux handler").unwrap();
        });
    }

    #[test]
    fn unsupported_udp_non_dns_closes_substream_without_panic() {
        block_on(async {
            let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 54);
            let open = encode_mux_new_udp(16, &destination, b"not-dns");
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io
                .write_all(&open)
                .await
                .expect("write mux udp open");

            let handle = tokio::spawn(async move { handle_mux_cool_inbound(server_io).await });
            assert_eq!(
                read_mux_frame(&mut client_io).await.expect("read mux end"),
                MuxFrame::End {
                    id: 16,
                    data: Vec::new()
                }
            );

            drop(client_io);
            handle.await.expect("join mux handler").unwrap();
        });
    }

    #[test]
    fn udp_dns_timeout_closes_substream_without_killing_session() {
        block_on(async {
            let udp = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind silent udp dns");
            let udp_port = udp.local_addr().expect("udp local addr").port();
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
            let open = encode_mux_new_udp(17, &destination, b"\xaa\xbbdns-query");
            let (mut client_io, server_io) = tokio::io::duplex(8192);
            client_io
                .write_all(&open)
                .await
                .expect("write mux udp open");

            let handle = tokio::spawn(async move { handle_mux_cool_inbound(server_io).await });
            assert_eq!(
                read_mux_frame(&mut client_io)
                    .await
                    .expect("read timeout mux end"),
                MuxFrame::End {
                    id: 17,
                    data: Vec::new()
                }
            );
            assert_eq!(
                *received.lock().expect("lock received"),
                b"\xaa\xbbdns-query".to_vec()
            );

            drop(client_io);
            handle.await.expect("join mux handler").unwrap();
        });
    }
}
