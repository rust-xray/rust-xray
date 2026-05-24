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
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const USER_ID: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];

    fn build_request(
        version: u8,
        additional_info: &[u8],
        command: u8,
        port: u16,
        address: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(version);
        buf.extend_from_slice(&USER_ID);
        buf.push(additional_info.len() as u8);
        buf.extend_from_slice(additional_info);
        buf.push(command);
        buf.extend_from_slice(&port.to_be_bytes());
        buf.extend_from_slice(address);
        buf
    }

    #[test]
    fn vless_command_debug_includes_variant_name() {
        assert!(format!("{:?}", VlessCommand::Tcp).contains("Tcp"));
        assert!(format!("{:?}", VlessCommand::Unknown(99)).contains("Unknown"));
    }

    #[test]
    fn vless_destination_debug_formats_ip_and_domain() {
        let ip = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let domain = VlessDestination::Domain("example.com".to_string(), 443);

        assert!(format!("{ip:?}").contains("127.0.0.1"));
        assert!(format!("{domain:?}").contains("example.com"));
    }

    #[test]
    fn parse_vless_request_tcp_ipv4() {
        let input = build_request(0, &[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
        let (request, consumed) = parse_vless_request(&input).unwrap();

        assert_eq!(consumed, input.len());
        assert_eq!(request.version, 0);
        assert_eq!(request.user_id, uuid::Uuid::from_bytes(USER_ID));
        assert_eq!(request.command, VlessCommand::Tcp);
        assert_eq!(
            request.destination,
            VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)
        );
        assert!(request.additional_info.is_empty());
    }

    #[test]
    fn parse_vless_request_tcp_ipv6() {
        let ipv6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let mut address = vec![0x03];
        address.extend_from_slice(&ipv6);

        let input = build_request(0, &[], 0x01, 8443, &address);
        let (request, consumed) = parse_vless_request(&input).unwrap();

        assert_eq!(consumed, input.len());
        assert_eq!(request.command, VlessCommand::Tcp);
        assert_eq!(
            request.destination,
            VlessDestination::Ip(IpAddr::V6(Ipv6Addr::from(ipv6)), 8443)
        );
    }

    #[test]
    fn parse_vless_request_tcp_domain() {
        let domain = b"example.com";
        let mut address = vec![0x02, domain.len() as u8];
        address.extend_from_slice(domain);

        let input = build_request(0, &[], 0x01, 443, &address);
        let (request, consumed) = parse_vless_request(&input).unwrap();

        assert_eq!(consumed, input.len());
        assert_eq!(request.command, VlessCommand::Tcp);
        assert_eq!(
            request.destination,
            VlessDestination::Domain("example.com".to_string(), 443)
        );
    }

    #[test]
    fn parse_vless_request_preserves_additional_info() {
        let additional_info = b"xtls-rprx-vision";
        let input = build_request(0, additional_info, 0x01, 443, &[0x01, 10, 0, 0, 1]);
        let (request, _) = parse_vless_request(&input).unwrap();

        assert_eq!(request.additional_info, additional_info);
    }

    #[test]
    fn parse_vless_request_unknown_command() {
        let input = build_request(0, &[], 0x99, 443, &[0x01, 10, 0, 0, 1]);
        let (request, _) = parse_vless_request(&input).unwrap();

        assert_eq!(request.command, VlessCommand::Unknown(0x99));
    }

    #[test]
    fn parse_vless_request_unknown_address_type_is_invalid_data() {
        let input = build_request(0, &[], 0x01, 443, &[0x04, 0, 0, 0, 0]);
        let err = parse_vless_request(&input).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn parse_vless_request_truncated_uuid_is_unexpected_eof() {
        let mut input = build_request(0, &[], 0x01, 443, &[0x01, 10, 0, 0, 1]);
        input.truncate(10);

        let err = parse_vless_request(&input).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn parse_vless_request_truncated_domain_is_unexpected_eof() {
        let input = build_request(0, &[], 0x01, 443, &[0x02, 11, b'e', b'x']);
        let err = parse_vless_request(&input).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn parse_vless_request_invalid_utf8_domain_is_invalid_data() {
        let input = build_request(0, &[], 0x01, 443, &[0x02, 1, 0xff]);
        let err = parse_vless_request(&input).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }
}
