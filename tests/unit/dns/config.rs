use super::*;

#[test]
fn parse_dns_tcp_with_port() {
    let server = parse_dns_server("tcp://1.1.1.1:5353").unwrap();
    assert_eq!(server.transport, DnsServerTransport::Tcp);
    assert_eq!(server.host, "1.1.1.1");
    assert_eq!(server.port, 5353);
}

#[test]
fn parse_dns_tcp_default_port() {
    let server = parse_dns_server("tcp://dns.example.com").unwrap();
    assert_eq!(server.transport, DnsServerTransport::Tcp);
    assert_eq!(server.host, "dns.example.com");
    assert_eq!(server.port, 53);
}

#[test]
fn parse_dns_udp_ip_default_port() {
    let server = parse_dns_server("1.1.1.1").unwrap();
    assert_eq!(server.transport, DnsServerTransport::Udp);
    assert_eq!(server.host, "1.1.1.1");
    assert_eq!(server.port, 53);
}

#[test]
fn parse_dns_doh_unsupported_but_parsed() {
    let server = parse_dns_server("https://dns.google/dns-query").unwrap();
    assert_eq!(server.transport, DnsServerTransport::Doh);
    assert_eq!(server.host, "dns.google");
    assert_eq!(server.port, 443);
    assert_eq!(server.path.as_deref(), Some("/dns-query"));
}

#[test]
fn parse_query_strategy_use_ipv4() {
    let config: DnsConfig =
        serde_json::from_str(r#"{"servers":["tcp://1.1.1.1:53"],"queryStrategy":"UseIPv4"}"#)
            .unwrap();
    assert_eq!(config.query_strategy, QueryStrategy::UseIPv4);
}

#[test]
fn invalid_query_strategy_rejected() {
    let err = serde_json::from_str::<DnsConfig>(
        r#"{"servers":["tcp://1.1.1.1:53"],"queryStrategy":"PreferIPv4"}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unsupported dns.queryStrategy"));
}
