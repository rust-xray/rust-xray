use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use crate::dns::packet::dns_query_id;
use crate::dns::{DnsEngine, DnsEngineOptions, DnsError, DnsQueryResponse, DnsQueryTrace};
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
const ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE: &str = "RUST_XRAY_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE";

type MuxOutTx = mpsc::UnboundedSender<MuxFrameActions>;

/// Outbound mux frames plus optional first-DNS latency trace for DEBUG diagnostics.
pub(crate) struct MuxFrameActions {
    pub frames: Vec<Vec<u8>>,
    pub dns_latency_trace: Option<MuxUdpDnsLatencyTrace>,
}

#[derive(Clone, Copy)]
pub struct MuxSessionTrace {
    pub conn_id: u64,
    pub conn_started: Instant,
}

#[derive(Clone, Copy)]
pub(crate) struct MuxUdpDnsLatencyTrace {
    pub conn_id: Option<u64>,
    pub conn_started: Option<Instant>,
    pub mux_id: u16,
    pub received_at: Instant,
}

fn mux_actions(frames: Vec<Vec<u8>>) -> MuxFrameActions {
    MuxFrameActions {
        frames,
        dns_latency_trace: None,
    }
}

fn mux_dns_actions(
    response: Vec<u8>,
    end: Option<Vec<u8>>,
    trace: MuxUdpDnsLatencyTrace,
) -> MuxFrameActions {
    let mut frames = vec![response];
    if let Some(end) = end {
        frames.push(end);
    }
    MuxFrameActions {
        frames,
        dns_latency_trace: Some(trace),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxStatus {
    New,
    Keep,
    End,
    KeepAlive,
}

impl MuxStatus {
    fn from_wire(value: u8) -> std::io::Result<Self> {
        match value {
            MUX_STATUS_NEW => Ok(Self::New),
            MUX_STATUS_KEEP => Ok(Self::Keep),
            MUX_STATUS_END => Ok(Self::End),
            MUX_STATUS_KEEPALIVE => Ok(Self::KeepAlive),
            other => Err(Error::new(
                ErrorKind::Unsupported,
                format!("unsupported mux frame status: 0x{other:02x}"),
            )),
        }
    }

    fn as_wire(self) -> u8 {
        match self {
            Self::New => MUX_STATUS_NEW,
            Self::Keep => MUX_STATUS_KEEP,
            Self::End => MUX_STATUS_END,
            Self::KeepAlive => MUX_STATUS_KEEPALIVE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxOption {
    pub has_data: bool,
}

impl MuxOption {
    fn from_wire(value: u8) -> Self {
        Self {
            has_data: value & MUX_OPT_DATA != 0,
        }
    }

    fn as_wire(self) -> u8 {
        if self.has_data {
            MUX_OPT_DATA
        } else {
            0
        }
    }
}

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
pub struct MuxFrame {
    pub mux_id: u16,
    pub status: MuxStatus,
    pub option: MuxOption,
    pub command: MuxCommand,
}

impl MuxFrame {
    pub fn id(&self) -> u16 {
        self.mux_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxCommand {
    Tcp {
        destination: MuxDestination,
        initial_payload: Vec<u8>,
    },
    Udp {
        destination: MuxDestination,
        packet: Vec<u8>,
    },
    Data {
        payload: Vec<u8>,
    },
    Close {
        payload: Vec<u8>,
    },
    KeepAlive,
}

pub fn parse_mux_frame(metadata: &[u8], extra: &[u8]) -> std::io::Result<MuxFrame> {
    if metadata.len() < 4 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "truncated mux metadata",
        ));
    }
    let id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = MuxStatus::from_wire(metadata[2])?;
    let option = MuxOption::from_wire(metadata[3]);
    let payload_len = mux_data_len(extra).unwrap_or(0);
    let data = if option.has_data {
        parse_mux_data(extra)?
    } else {
        Vec::new()
    };

    let command = match status {
        MuxStatus::New => {
            let (destination, consumed) = parse_mux_destination(&metadata[4..])?;
            if consumed + 4 != metadata.len() {
                debug!(
                    id,
                    trailing = metadata.len().saturating_sub(consumed + 4),
                    "mux new frame ignored trailing metadata"
                );
            }
            match destination.network {
                MuxNetwork::Tcp => MuxCommand::Tcp {
                    destination,
                    initial_payload: data,
                },
                MuxNetwork::Udp => MuxCommand::Udp {
                    destination,
                    packet: data,
                },
            }
        }
        MuxStatus::Keep
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
            MuxCommand::Udp {
                destination,
                packet: data,
            }
        }
        MuxStatus::Keep => MuxCommand::Data { payload: data },
        MuxStatus::End => MuxCommand::Close { payload: data },
        MuxStatus::KeepAlive => MuxCommand::KeepAlive,
    };

    let frame = MuxFrame {
        mux_id: id,
        status,
        option,
        command,
    };
    log_mux_frame_parsed(id, status, option, metadata, payload_len, &frame);
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
    let metadata = [
        id.to_be_bytes()[0],
        id.to_be_bytes()[1],
        MuxStatus::End.as_wire(),
        MuxOption { has_data: false }.as_wire(),
    ];
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

    let mut metadata = Vec::with_capacity(20);
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.push(status);
    metadata.push(MUX_OPT_DATA);
    metadata.push(match network {
        MuxNetwork::Tcp => MUX_NETWORK_TCP,
        MuxNetwork::Udp => MUX_NETWORK_UDP,
    });
    write_mux_destination_metadata(&mut metadata, destination)?;

    let mut frame = Vec::with_capacity(2 + metadata.len() + 2 + data.len());
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

fn append_mux_udp_dns_close(id: u16, response: Option<Vec<u8>>) -> Vec<u8> {
    let end = encode_mux_end(id);
    match response {
        Some(response) => {
            let mut out = Vec::with_capacity(response.len() + end.len());
            out.extend_from_slice(&response);
            out.extend_from_slice(&end);
            out
        }
        None => end,
    }
}

async fn write_mux_out_frames<S>(stream: &mut S, actions: &MuxFrameActions) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frames = &actions.frames;
    if frames.is_empty() {
        return Ok(());
    }
    if let Some(trace) = actions.dns_latency_trace {
        let response_started = Instant::now();
        debug!(
            conn_id = trace.conn_id,
            mux_id = trace.mux_id,
            frame_bytes = frames[0].len(),
            elapsed_ms_since_conn_start = trace
                .conn_started
                .map(|started| started.elapsed().as_millis()),
            total_latency_ms = trace.received_at.elapsed().as_millis(),
            "mux udp dns response frame write started"
        );
        stream.write_all(&frames[0]).await?;
        stream.flush().await?;
        debug!(
            conn_id = trace.conn_id,
            mux_id = trace.mux_id,
            frame_bytes = frames[0].len(),
            write_ms = response_started.elapsed().as_millis(),
            total_latency_ms = trace.received_at.elapsed().as_millis(),
            elapsed_ms_since_conn_start = trace
                .conn_started
                .map(|started| started.elapsed().as_millis()),
            "mux udp dns response frame write done"
        );
        debug!(
            conn_id = trace.conn_id,
            mux_id = trace.mux_id,
            frame_bytes = frames[0].len(),
            write_ms = response_started.elapsed().as_millis(),
            total_latency_ms = trace.received_at.elapsed().as_millis(),
            elapsed_ms_since_conn_start = trace
                .conn_started
                .map(|started| started.elapsed().as_millis()),
            "mux udp dns response frame written"
        );
        if frames.len() > 1 {
            for close_frame in &frames[1..] {
                let close_started = Instant::now();
                stream.write_all(close_frame).await?;
                stream.flush().await?;
                debug!(
                    conn_id = trace.conn_id,
                    mux_id = trace.mux_id,
                    frame_bytes = close_frame.len(),
                    write_ms = close_started.elapsed().as_millis(),
                    elapsed_ms_since_conn_start = trace
                        .conn_started
                        .map(|started| started.elapsed().as_millis()),
                    "mux udp dns close frame sent"
                );
            }
        } else {
            debug!(
                conn_id = trace.conn_id,
                mux_id = trace.mux_id,
                reason = "success_response_default",
                "mux udp dns close frame skipped"
            );
        }
        debug!(
            conn_id = trace.conn_id,
            mux_id = trace.mux_id,
            elapsed_ms_since_conn_start = trace
                .conn_started
                .map(|started| started.elapsed().as_millis()),
            "mux session remains open after udp dns response"
        );
        return Ok(());
    }
    if frames.len() == 1 {
        stream.write_all(&frames[0]).await?;
    } else {
        let total: usize = frames.iter().map(Vec::len).sum();
        let mut buf = Vec::with_capacity(total);
        for frame in frames {
            buf.extend_from_slice(frame);
        }
        stream.write_all(&buf).await?;
    }
    stream.flush().await?;
    Ok(())
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
    status: MuxStatus,
    option: MuxOption,
    metadata: &[u8],
    payload_len: usize,
    frame: &MuxFrame,
) {
    let network = match &frame.command {
        MuxCommand::Tcp { destination, .. } | MuxCommand::Udp { destination, .. } => {
            Some(destination.network.as_str())
        }
        _ => None,
    };
    let destination = match &frame.command {
        MuxCommand::Tcp { destination, .. } | MuxCommand::Udp { destination, .. } => {
            Some(format_vless_destination(&destination.destination))
        }
        _ => None,
    };
    let address_type = metadata.get(7).copied();
    trace!(
        mux_id = id,
        metadata_len = metadata.len(),
        status = format_args!("0x{:02x}", status.as_wire()),
        option = format_args!("0x{:02x}", option.as_wire()),
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

pub async fn handle_mux_cool_inbound<S>(stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns(stream, DnsEngine::shared()).await
}

pub async fn handle_mux_cool_inbound_traced<S>(
    stream: S,
    trace: MuxSessionTrace,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns_and_trace(stream, DnsEngine::shared(), Some(trace)).await
}

pub async fn handle_mux_cool_inbound_with_dns<S>(
    stream: S,
    dns: Arc<DnsEngine>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_mux_cool_inbound_with_dns_and_trace(stream, dns, None).await
}

pub async fn handle_mux_cool_inbound_with_dns_and_trace<S>(
    mut stream: S,
    dns: Arc<DnsEngine>,
    trace: Option<MuxSessionTrace>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session_started = Instant::now();
    info!(
        conn_id = trace.map(|trace| trace.conn_id),
        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
        "mux session started"
    );
    let mut active: Option<(u16, TcpStream)> = None;
    let mut buf = [0u8; 8192];
    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<MuxFrameActions>();

    loop {
        if let Some((id, outbound)) = active.as_mut() {
            tokio::select! {
                frame = read_mux_frame(&mut stream) => {
                    let frame = frame?;
                    debug!(
                        conn_id = trace.map(|trace| trace.conn_id),
                        mux_id = frame.id(),
                        elapsed_ms_since_conn_start = trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                        "first/next mux frame received"
                    );
                    let actions = handle_client_frame(&mut active, &dns, frame, trace, udp_tx.clone()).await?;
                    write_mux_out_frames(&mut stream, &actions).await?;
                }
                Some(actions) = udp_rx.recv() => {
                    write_mux_out_frames(&mut stream, &actions).await?;
                }
                read = outbound.read(&mut buf) => {
                    let read = read?;
                    if read == 0 {
                        write_mux_out_frames(
                            &mut stream,
                            &mux_actions(vec![encode_mux_end(*id)]),
                        )
                        .await?;
                        debug!(mux_id = *id, "mux substream relay completed");
                        active = None;
                    } else {
                        let frame = encode_mux_keep_data(*id, &buf[..read])?;
                        write_mux_out_frames(&mut stream, &mux_actions(vec![frame])).await?;
                    }
                }
            }
        } else {
            debug!(
                conn_id = trace.map(|trace| trace.conn_id),
                elapsed_ms_since_conn_start =
                    trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                "waiting next mux frame"
            );
            tokio::select! {
                frame = read_mux_frame(&mut stream) => {
                    match frame {
                        Ok(frame) => {
                            debug!(
                                conn_id = trace.map(|trace| trace.conn_id),
                                mux_id = frame.id(),
                                elapsed_ms_since_conn_start =
                                    trace.map(|trace| trace.conn_started.elapsed().as_millis()),
                                "first/next mux frame received"
                            );
                            let actions = handle_client_frame(&mut active, &dns, frame, trace, udp_tx.clone()).await?;
                            write_mux_out_frames(&mut stream, &actions).await?;
                        }
                        Err(err) if err.kind() == ErrorKind::UnexpectedEof => break,
                        Err(err) => return Err(err),
                    }
                }
                Some(actions) = udp_rx.recv() => {
                    write_mux_out_frames(&mut stream, &actions).await?;
                }
            }
        }
    }

    debug!(
        duration_ms = session_started.elapsed().as_millis(),
        conn_id = trace.map(|trace| trace.conn_id),
        "mux session completed"
    );
    info!("mux session completed");
    Ok(())
}

async fn handle_client_frame(
    active: &mut Option<(u16, TcpStream)>,
    dns: &Arc<DnsEngine>,
    frame: MuxFrame,
    trace: Option<MuxSessionTrace>,
    udp_tx: MuxOutTx,
) -> std::io::Result<MuxFrameActions> {
    let id = frame.mux_id;
    match frame.command {
        MuxCommand::Udp {
            destination,
            packet,
        } => {
            debug!(mux_id = id, "mux udp substream opened");
            return handle_udp_mux_packet(id, destination.destination, packet, dns, trace, udp_tx)
                .await;
        }
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
    }
    Ok(mux_actions(Vec::new()))
}

pub(crate) fn mux_dns_legacy_direct_enabled() -> bool {
    crate::dns::options::mux_dns_legacy_direct_enabled()
}

pub(crate) fn mux_udp_send_close_after_response_enabled() -> bool {
    std::env::var(ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE)
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
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

async fn handle_udp_mux_packet(
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
        spawn_generic_udp_relay(id, destination, data, trace, received_at, udp_tx);
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

fn spawn_generic_udp_relay(
    id: u16,
    destination: VlessDestination,
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
    destination: &VlessDestination,
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
    metadata.push(MuxStatus::New.as_wire());
    metadata.push(
        MuxOption {
            has_data: !data.is_empty(),
        }
        .as_wire(),
    );
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
    use std::sync::{Mutex, OnceLock};
    use tokio::net::UdpSocket;

    #[test]
    fn mux_frame_parser_parses_basic_open_data_close_frames() {
        let destination = VlessDestination::Domain("example.com".to_string(), 443);
        let frame = encode_mux_new_tcp(1, &destination, b"GET / HTTP/1.1\r\n\r\n");
        let metadata_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let parsed =
            parse_mux_frame(&frame[2..2 + metadata_len], &frame[2 + metadata_len..]).unwrap();
        assert_eq!(
            parsed,
            MuxFrame {
                mux_id: 1,
                status: MuxStatus::New,
                option: MuxOption { has_data: true },
                command: MuxCommand::Tcp {
                    destination: MuxDestination {
                        network: MuxNetwork::Tcp,
                        destination,
                    },
                    initial_payload: b"GET / HTTP/1.1\r\n\r\n".to_vec()
                }
            }
        );

        let keep = encode_mux_keep_data(1, b"more").unwrap();
        let metadata_len = u16::from_be_bytes([keep[0], keep[1]]) as usize;
        assert_eq!(
            parse_mux_frame(&keep[2..2 + metadata_len], &keep[2 + metadata_len..]).unwrap(),
            MuxFrame {
                mux_id: 1,
                status: MuxStatus::Keep,
                option: MuxOption { has_data: true },
                command: MuxCommand::Data {
                    payload: b"more".to_vec()
                }
            }
        );

        let end = encode_mux_end(1);
        let metadata_len = u16::from_be_bytes([end[0], end[1]]) as usize;
        assert_eq!(
            parse_mux_frame(&end[2..2 + metadata_len], &[]).unwrap(),
            MuxFrame {
                mux_id: 1,
                status: MuxStatus::End,
                option: MuxOption { has_data: false },
                command: MuxCommand::Close {
                    payload: Vec::new()
                }
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
            MuxFrame {
                mux_id: 7,
                status: MuxStatus::New,
                option: MuxOption { has_data: true },
                command: MuxCommand::Udp {
                    destination: MuxDestination {
                        network: MuxNetwork::Udp,
                        destination,
                    },
                    packet: b"\x12\x34dns".to_vec()
                }
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
            MuxFrame {
                mux_id: 9,
                status: MuxStatus::Keep,
                option: MuxOption { has_data: true },
                command: MuxCommand::Udp {
                    destination: MuxDestination {
                        network: MuxNetwork::Udp,
                        destination,
                    },
                    packet: b"\x01\x00".to_vec()
                }
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
            MuxFrame {
                mux_id: 11,
                status: MuxStatus::Keep,
                option: MuxOption { has_data: true },
                command: MuxCommand::Udp {
                    destination: MuxDestination {
                        network: MuxNetwork::Udp,
                        destination,
                    },
                    packet: b"\x81\x80".to_vec()
                }
            }
        );
    }
    #[test]
    fn encode_mux_udp_response_frame_matches_xray_cool_golden_bytes() {
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        let frame = encode_mux_udp_packet(0x1234, &destination, b"\x81\x80").unwrap();

        assert_eq!(
            frame,
            vec![
                0x00, 0x0c, // metadata length
                0x12, 0x34, // mux id
                0x02, // status keep
                0x01, // option data
                0x02, // network udp
                0x00, 0x35, // port 53
                0x01, // ipv4 address
                0x01, 0x01, 0x01, 0x01, // 1.1.1.1
                0x00, 0x02, // data length
                0x81, 0x80, // DNS response payload
            ]
        );
    }

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
            use crate::dns::{DnsEngineOptions, MuxDnsUpstreamMode};

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
            let second = encode_mux_keep_udp(0, &destination, &expected_query);
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

    #[test]
    fn udp_dns_timeout_closes_substream_without_killing_session() {
        block_on(async {
            use crate::dns::config::{DnsConfig, QueryStrategy};
            use crate::dns::{DnsEngineOptions, MuxDnsUpstreamMode};
            use std::time::Duration;

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
    fn mux_dns_legacy_direct_disabled_by_default() {
        assert!(!mux_dns_legacy_direct_enabled());
    }

    #[test]
    fn mux_udp_dns_repeat_query_hits_engine_cache() {
        block_on(async {
            use crate::dns::config::{DnsConfig, QueryStrategy};
            use crate::dns::DnsEngineOptions;
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::time::Duration;

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
