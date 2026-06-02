use super::*;

#[test]
fn parse_routing_domain_strategy() {
    assert_eq!(
        OutboundDomainStrategy::parse("UseIP"),
        Some(OutboundDomainStrategy::UseIp)
    );
    assert_eq!(
        OutboundDomainStrategy::parse("AsIs"),
        Some(OutboundDomainStrategy::AsIs)
    );
}

#[test]
fn routing_overrides_dns_query_strategy() {
    assert_eq!(
        OutboundDomainStrategy::from_config(Some("UseIPv4"), Some(QueryStrategy::UseIPv6)),
        OutboundDomainStrategy::UseIpv4
    );
}
