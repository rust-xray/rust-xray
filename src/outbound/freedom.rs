use crate::vless::protocol::VlessDestination;
use std::net::IpAddr;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub fn format_vless_destination(destination: &VlessDestination) -> String {
    match destination {
        VlessDestination::Ip(addr, port) => match addr {
            IpAddr::V4(v4) => format!("{v4}:{port}"),
            IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        },
        VlessDestination::Domain(domain, port) => format!("{domain}:{port}"),
    }
}

pub async fn connect_tcp_destination(destination: &VlessDestination) -> std::io::Result<TcpStream> {
    let dest = format_vless_destination(destination);
    info!(%dest, "freedom outbound connect started");

    let stream = match destination {
        VlessDestination::Ip(addr, port) => TcpStream::connect((*addr, *port)).await?,
        VlessDestination::Domain(domain, port) => {
            TcpStream::connect((domain.as_str(), *port)).await?
        }
    };

    info!(%dest, "freedom outbound connected");
    Ok(stream)
}

pub async fn forward_tcp_initial_payload(
    outbound: &mut TcpStream,
    initial_payload: &[u8],
) -> std::io::Result<()> {
    if initial_payload.is_empty() {
        return Ok(());
    }

    outbound.write_all(initial_payload).await
}

pub async fn relay_tcp_bidirectional<S>(
    mut inbound: S,
    outbound: &mut TcpStream,
) -> std::io::Result<(u64, u64)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (inbound_to_outbound, outbound_to_inbound) =
        copy_bidirectional(&mut inbound, outbound).await?;

    info!(
        inbound_to_outbound,
        outbound_to_inbound, "freedom relay ended"
    );

    Ok((inbound_to_outbound, outbound_to_inbound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn format_vless_destination_ipv4() {
        let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert_eq!(format_vless_destination(&destination), "192.168.1.1:8080");
    }

    #[test]
    fn format_vless_destination_ipv6() {
        let destination = VlessDestination::Ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        assert_eq!(format_vless_destination(&destination), "[2001:db8::1]:443");
    }

    #[test]
    fn format_vless_destination_domain() {
        let destination = VlessDestination::Domain("example.com".to_string(), 443);
        assert_eq!(format_vless_destination(&destination), "example.com:443");
    }
}
