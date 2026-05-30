use crate::dns::QueryStrategy;

/// Outbound domain resolution policy (Xray `routing.domainStrategy` / DNS `queryStrategy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutboundDomainStrategy {
    /// Pass domain to connect; may use OS resolver (explicit system path).
    #[default]
    AsIs,
    UseIp,
    UseIpv4,
    UseIpv6,
    /// Explicitly use OS resolver (same connect path as AsIs, logged as system).
    UseSystem,
}

impl OutboundDomainStrategy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "asis" | "as-is" => Some(Self::AsIs),
            "useip" | "use_ip" => Some(Self::UseIp),
            "useipv4" | "use_ipv4" => Some(Self::UseIpv4),
            "useipv6" | "use_ipv6" => Some(Self::UseIpv6),
            "usesystem" | "use_system" => Some(Self::UseSystem),
            _ => None,
        }
    }

    pub fn from_config(
        routing_domain_strategy: Option<&str>,
        dns_query_strategy: Option<QueryStrategy>,
    ) -> Self {
        if let Some(raw) = routing_domain_strategy {
            if let Some(parsed) = Self::parse(raw) {
                return parsed;
            }
        }
        if let Some(strategy) = dns_query_strategy {
            return Self::from_query_strategy(strategy);
        }
        Self::AsIs
    }

    pub fn from_query_strategy(strategy: QueryStrategy) -> Self {
        match strategy {
            QueryStrategy::UseIP => Self::UseIp,
            QueryStrategy::UseIPv4 => Self::UseIpv4,
            QueryStrategy::UseIPv6 => Self::UseIpv6,
            QueryStrategy::UseSystem => Self::UseSystem,
        }
    }

    pub fn uses_dns_engine(self) -> bool {
        matches!(self, Self::UseIp | Self::UseIpv4 | Self::UseIpv6)
    }

    pub fn uses_system_resolver(self) -> bool {
        matches!(self, Self::AsIs | Self::UseSystem)
    }

    pub fn to_query_strategy(self) -> QueryStrategy {
        match self {
            Self::UseIp => QueryStrategy::UseIP,
            Self::UseIpv4 => QueryStrategy::UseIPv4,
            Self::UseIpv6 => QueryStrategy::UseIPv6,
            Self::UseSystem | Self::AsIs => QueryStrategy::UseSystem,
        }
    }
}

#[cfg(test)]
mod tests {
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
}
