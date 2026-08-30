use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, trace};

use crate::mux::frame::{
    is_xudp_global_id, MuxCommand, MuxDestination, MuxFrame, MuxGlobalId, MuxNetwork, MuxOption,
    MuxStatus, MAX_MUX_DATA_LEN, MAX_MUX_METADATA_LEN, MUX_NETWORK_TCP, MUX_NETWORK_UDP,
    MUX_OPT_DATA, XUDP_GLOBAL_ID_LEN,
};
use crate::outbound::freedom::format_vless_destination;
use crate::vless::protocol::VlessDestination;

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
            let trailing = &metadata[4 + consumed..];
            let global_id = parse_xudp_global_id(trailing, option.has_data, destination.network);
            if !trailing.is_empty() && global_id.is_none() {
                debug!(
                    id,
                    trailing = trailing.len(),
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
                    global_id,
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
                global_id: None,
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

fn parse_xudp_global_id(
    trailing: &[u8],
    has_data: bool,
    network: MuxNetwork,
) -> Option<MuxGlobalId> {
    if network != MuxNetwork::Udp || !has_data || trailing.len() < XUDP_GLOBAL_ID_LEN {
        return None;
    }
    let mut global_id = MuxGlobalId::default();
    global_id.copy_from_slice(&trailing[..XUDP_GLOBAL_ID_LEN]);
    is_xudp_global_id(&global_id).then_some(global_id)
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

#[cfg(test)]
#[path = "../../tests/unit/mux/parser.rs"]
mod tests;
