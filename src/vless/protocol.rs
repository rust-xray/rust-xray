use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub version: u8,
    pub user_id: uuid::Uuid,
    pub command: VlessCommand,
    pub destination: VlessDestination,
    pub additional_info: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp,
    Udp,
    Mux,
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessDestination {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

fn unexpected_eof() -> Error {
    Error::new(ErrorKind::UnexpectedEof, "unexpected end of vless request")
}

pub fn parse_vless_request(input: &[u8]) -> std::io::Result<(VlessRequest, usize)> {
    let mut offset = 0;

    let version = *input.get(offset).ok_or_else(unexpected_eof)?;
    if version != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("unsupported vless request version: {version}"),
        ));
    }
    offset += 1;

    let uuid_bytes: [u8; 16] = input
        .get(offset..offset + 16)
        .ok_or_else(unexpected_eof)?
        .try_into()
        .expect("slice length checked");
    offset += 16;
    let user_id = uuid::Uuid::from_bytes(uuid_bytes);

    let add_info_len = *input.get(offset).ok_or_else(unexpected_eof)? as usize;
    offset += 1;

    let additional_info = input
        .get(offset..offset + add_info_len)
        .ok_or_else(unexpected_eof)?
        .to_vec();
    offset += add_info_len;

    let command_byte = *input.get(offset).ok_or_else(unexpected_eof)?;
    offset += 1;
    let command = match command_byte {
        0x01 => VlessCommand::Tcp,
        0x02 => VlessCommand::Udp,
        0x03 => VlessCommand::Mux,
        b => VlessCommand::Unknown(b),
    };

    // Xray omits address/port on the wire for Mux (and Rvs) commands.
    if command == VlessCommand::Mux {
        return Ok((
            VlessRequest {
                version,
                user_id,
                command,
                destination: VlessDestination::Domain("v1.mux.cool".to_string(), 0),
                additional_info,
            },
            offset,
        ));
    }

    let port_bytes = input.get(offset..offset + 2).ok_or_else(unexpected_eof)?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    offset += 2;

    let addr_type = *input.get(offset).ok_or_else(unexpected_eof)?;
    offset += 1;

    let destination = match addr_type {
        0x01 => {
            let ip_bytes = input.get(offset..offset + 4).ok_or_else(unexpected_eof)?;
            offset += 4;
            let ip = IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(ip_bytes).expect("slice length checked"),
            ));
            VlessDestination::Ip(ip, port)
        }
        0x02 => {
            let domain_len = *input.get(offset).ok_or_else(unexpected_eof)? as usize;
            offset += 1;
            let domain_bytes = input
                .get(offset..offset + domain_len)
                .ok_or_else(unexpected_eof)?;
            offset += domain_len;
            let domain = String::from_utf8(domain_bytes.to_vec()).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid vless domain utf-8: {e}"),
                )
            })?;
            VlessDestination::Domain(domain, port)
        }
        0x03 => {
            let ip_bytes = input.get(offset..offset + 16).ok_or_else(unexpected_eof)?;
            offset += 16;
            let ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(ip_bytes).expect("slice length checked"),
            ));
            VlessDestination::Ip(ip, port)
        }
        b => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown vless address type: 0x{b:02x}"),
            ));
        }
    };

    Ok((
        VlessRequest {
            version,
            user_id,
            command,
            destination,
            additional_info,
        },
        offset,
    ))
}

#[cfg(test)]
pub(crate) fn build_vless_request_wire(
    version: u8,
    user_id: &[u8; 16],
    additional_info: &[u8],
    command: u8,
    port: u16,
    address: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(version);
    buf.extend_from_slice(user_id);
    buf.push(additional_info.len() as u8);
    buf.extend_from_slice(additional_info);
    buf.push(command);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(address);
    buf
}

#[cfg(test)]
pub(crate) fn build_vless_domain_address(domain: &str) -> Vec<u8> {
    let domain_bytes = domain.as_bytes();
    let mut address = Vec::with_capacity(2 + domain_bytes.len());
    address.push(0x02);
    address.push(domain_bytes.len() as u8);
    address.extend_from_slice(domain_bytes);
    address
}

/// Encodes a VLESS inbound response header.
///
/// Xray/VLESS clients expect this header on the TLS application stream **before**
/// any proxied target response bytes. Without it, clients such as Xray may interpret
/// the first target bytes (for example a TLS ServerHello `0x16`) as a malformed
/// response header and close the connection.
///
/// Layout: `[version, addons_len, addons...]`. For the current MVP inbound path
/// `addons` is `None`, which encodes as `[version, 0]`.
pub fn encode_vless_response_header(version: u8, addons: Option<&[u8]>) -> Vec<u8> {
    let addons = addons.unwrap_or(&[]);
    if addons.is_empty() {
        return vec![version, 0];
    }

    assert!(
        addons.len() <= u8::MAX as usize,
        "VLESS response addons length exceeds 255 bytes"
    );

    let mut header = Vec::with_capacity(2 + addons.len());
    header.push(version);
    header.push(addons.len() as u8);
    header.extend_from_slice(addons);
    header
}

#[cfg(test)]
pub(crate) fn decode_vless_response_header(input: &[u8]) -> std::io::Result<(u8, Vec<u8>)> {
    if input.len() < 2 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "vless response header too short",
        ));
    }

    let version = input[0];
    let addons_len = input[1] as usize;
    if input.len() < 2 + addons_len {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "vless response addons truncated",
        ));
    }

    Ok((version, input[2..2 + addons_len].to_vec()))
}

#[cfg(test)]
#[path = "../../tests/unit/vless/protocol.rs"]
mod tests;
