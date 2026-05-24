use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequest {
    pub version: u8,
    pub user_id: [u8; 16],
    pub flow: Option<String>,
    pub command: VlessCommand,
    pub destination: VlessDestination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp,
    Udp,
    Mux,
    Unknown(u8),
}

#[derive(Clone, PartialEq, Eq)]
pub enum VlessDestination {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl fmt::Debug for VlessDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr, port) => f.debug_tuple("Ip").field(addr).field(port).finish(),
            Self::Domain(domain, port) => {
                f.debug_tuple("Domain").field(domain).field(port).finish()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
}
