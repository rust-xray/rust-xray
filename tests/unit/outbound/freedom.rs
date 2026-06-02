use super::*;
use crate::dns::DnsError;
use crate::dns::QueryStrategy;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

struct MockResolver {
    v4: Vec<IpAddr>,
    v6: Vec<IpAddr>,
    lookups: AtomicUsize,
}

#[async_trait::async_trait]
impl OutboundDnsResolver for MockResolver {
    async fn lookup_ip(
        &self,
        _domain: &str,
        strategy: QueryStrategy,
    ) -> Result<Vec<IpAddr>, DnsError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        match strategy {
            QueryStrategy::UseIPv6 => Ok(self.v6.clone()),
            QueryStrategy::UseIPv4 | QueryStrategy::UseIP | QueryStrategy::UseSystem => {
                Ok(self.v4.clone())
            }
        }
    }
}

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

#[test]
fn freedom_source_does_not_use_system_dns_helpers() {
    let src = include_str!("freedom.rs");
    let code = src.split("#[cfg(test)]").next().unwrap_or(src);
    assert!(
        !code.contains("lookup_host("),
        "freedom outbound must not call tokio::net::lookup_host"
    );
    assert!(
        !code.contains("ToSocketAddrs"),
        "freedom outbound must not use ToSocketAddrs"
    );
}

#[tokio::test]
async fn ip_destination_bypasses_dns_engine() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let resolver = MockResolver {
        v4: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        v6: Vec::new(),
        lookups: AtomicUsize::new(0),
    };
    let destination = VlessDestination::Ip(addr.ip(), addr.port());
    tokio::spawn(async move {
        let _ = listener.accept().await.unwrap();
    });
    connect_tcp_destination_with_resolver(
        &destination,
        OutboundDomainStrategy::UseIp,
        Some(&resolver),
    )
    .await
    .unwrap();
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn use_ipv4_resolves_via_dns_engine_mock() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let resolver = MockResolver {
        v4: vec![addr.ip()],
        v6: Vec::new(),
        lookups: AtomicUsize::new(0),
    };
    let destination = VlessDestination::Domain("example.com".to_string(), addr.port());
    tokio::spawn(async move {
        let _ = listener.accept().await.unwrap();
    });
    connect_tcp_destination_with_resolver(
        &destination,
        OutboundDomainStrategy::UseIpv4,
        Some(&resolver),
    )
    .await
    .unwrap();
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn use_ipv6_chooses_aaaa_from_mock() {
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let resolver = MockResolver {
        v4: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        v6: vec![addr.ip()],
        lookups: AtomicUsize::new(0),
    };
    let destination = VlessDestination::Domain("example.com".to_string(), addr.port());
    tokio::spawn(async move {
        let _ = listener.accept().await.unwrap();
    });
    connect_tcp_destination_with_resolver(
        &destination,
        OutboundDomainStrategy::UseIpv6,
        Some(&resolver),
    )
    .await
    .unwrap();
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_dns_records_returns_error() {
    let resolver = MockResolver {
        v4: Vec::new(),
        v6: Vec::new(),
        lookups: AtomicUsize::new(0),
    };
    let destination = VlessDestination::Domain("missing.example".to_string(), 443);
    let err = connect_tcp_destination_with_resolver(
        &destination,
        OutboundDomainStrategy::UseIp,
        Some(&resolver),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
