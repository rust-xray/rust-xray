use std::net::IpAddr;
use std::sync::Arc;

use tokio::net::TcpStream;

use crate::outbound::freedom::connect_tcp_destination_with_runtime;
use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::context::{NetworkKind, RouteContext};
use crate::routing::sniff::sniff_protocol_from_payload;
use crate::runtime::{OutboundProtocol, RuntimeOutboundManager};
use crate::vless::protocol::VlessDestination;
use crate::vless::user_manager::VlessAuthenticatedClient;

pub enum RoutedOutbound {
    Tcp(TcpStream),
    Blackhole,
}

/// Socket metadata available on accepted TCP connections.
#[derive(Debug, Clone, Default)]
pub struct RouteSocketMeta {
    pub source_ip: Option<IpAddr>,
    pub source_port: u16,
    pub local_ips: Vec<IpAddr>,
    pub local_port: u16,
}

impl RouteSocketMeta {
    pub fn from_tcp_stream(stream: &TcpStream) -> Self {
        let source_ip = stream.peer_addr().ok().map(|addr| addr.ip());
        let source_port = stream.peer_addr().ok().map(|addr| addr.port()).unwrap_or(0);
        let local_ips = stream
            .local_addr()
            .ok()
            .map(|addr| vec![addr.ip()])
            .unwrap_or_default();
        let local_port = stream
            .local_addr()
            .ok()
            .map(|addr| addr.port())
            .unwrap_or(0);
        Self {
            source_ip,
            source_port,
            local_ips,
            local_port,
        }
    }
}

/// Upstream: VLESS UUID bytes[6]<<8 | bytes[7].
pub fn vless_route_from_uuid(id: &uuid::Uuid) -> u16 {
    let bytes = id.as_bytes();
    u16::from_be_bytes([bytes[6], bytes[7]])
}

pub async fn connect_routed_outbound(
    outbound_tag: &str,
    destination: &VlessDestination,
    outbound_manager: &RuntimeOutboundManager,
    connect_runtime: Arc<OutboundConnectRuntime>,
) -> std::io::Result<RoutedOutbound> {
    let protocol = outbound_manager.get_protocol(outbound_tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("outbound tag not found: {outbound_tag}"),
        )
    })?;

    match protocol {
        OutboundProtocol::Blackhole => Ok(RoutedOutbound::Blackhole),
        OutboundProtocol::Freedom => {
            let stream = connect_tcp_destination_with_runtime(destination, connect_runtime).await?;
            Ok(RoutedOutbound::Tcp(stream))
        }
    }
}

pub fn route_context_from_vless(
    inbound_tag: &str,
    auth: &VlessAuthenticatedClient,
    destination: &VlessDestination,
    initial_payload: &[u8],
    socket: &RouteSocketMeta,
    sniffing_enabled: bool,
) -> RouteContext {
    let (target_domain, target_ips, target_port) = match destination {
        VlessDestination::Ip(addr, port) => (String::new(), vec![*addr], *port),
        VlessDestination::Domain(domain, port) => (domain.clone(), Vec::new(), *port),
    };
    RouteContext {
        inbound_tag: inbound_tag.to_string(),
        network: NetworkKind::Tcp,
        source_ips: socket.source_ip.into_iter().collect(),
        target_ips,
        source_port: socket.source_port,
        target_port,
        target_domain,
        protocol: if sniffing_enabled {
            sniff_protocol_from_payload(initial_payload)
        } else {
            String::new()
        },
        user: auth.email.clone().unwrap_or_default(),
        attributes: Default::default(),
        local_ips: socket.local_ips.clone(),
        local_port: socket.local_port,
        vless_route: vless_route_from_uuid(&auth.id),
        skip_dns_resolve: false,
        process_name: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn vless_route_uses_uuid_bytes_six_and_seven() {
        let id = Uuid::parse_str("00000000-0000-1234-0000-000000000001").expect("uuid");
        assert_eq!(vless_route_from_uuid(&id), 0x1234);
    }
}
