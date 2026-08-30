use std::io::{Error, ErrorKind};
use std::net::IpAddr;

use crate::mux::frame::{
    MuxNetwork, MuxOption, MuxStatus, ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE, MAX_MUX_DATA_LEN,
    MUX_NETWORK_TCP, MUX_NETWORK_UDP, MUX_OPT_DATA, MUX_STATUS_KEEP,
};
use crate::vless::protocol::VlessDestination;

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

pub(crate) fn mux_udp_send_close_after_response_enabled() -> bool {
    std::env::var(ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE)
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

pub(crate) fn append_mux_udp_dns_close(id: u16, response: Option<Vec<u8>>) -> Vec<u8> {
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

pub(crate) fn write_mux_destination_metadata(
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

pub fn encode_mux_new_tcp(id: u16, destination: &VlessDestination, data: &[u8]) -> Vec<u8> {
    encode_mux_new(MuxNetwork::Tcp, id, destination, data)
}

#[cfg(test)]
pub(crate) fn encode_mux_new_udp_xudp(
    id: u16,
    destination: &VlessDestination,
    global_id: &[u8; 8],
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
    metadata.push(MUX_NETWORK_UDP);
    write_mux_destination_metadata(&mut metadata, destination).unwrap();
    metadata.extend_from_slice(global_id);
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
pub(crate) fn encode_mux_new_udp_xudp_with_trailing(
    id: u16,
    destination: &VlessDestination,
    global_id: &[u8; 8],
    extra_trailing: &[u8],
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
    metadata.push(MUX_NETWORK_UDP);
    write_mux_destination_metadata(&mut metadata, destination).unwrap();
    metadata.extend_from_slice(global_id);
    metadata.extend_from_slice(extra_trailing);
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
pub(crate) fn encode_mux_new_udp(id: u16, destination: &VlessDestination, data: &[u8]) -> Vec<u8> {
    encode_mux_new(MuxNetwork::Udp, id, destination, data)
}

#[cfg(test)]
pub(crate) fn encode_mux_keep_udp(id: u16, destination: &VlessDestination, data: &[u8]) -> Vec<u8> {
    encode_mux_udp_packet(id, destination, data).unwrap()
}

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
#[path = "../../tests/unit/mux/encoder.rs"]
mod tests;
