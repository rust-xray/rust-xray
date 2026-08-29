use std::collections::HashMap;
use std::net::IpAddr;

/// ATTRIBUTE_RUNTIME_SOURCE: unavailable — no production path populates sniffed routing attributes.
pub const ATTRIBUTE_RUNTIME_SOURCE: &str = "unavailable";

/// PROCESS_RUNTIME_SOURCE: unavailable for remote VLESS — process metadata is not collected on inbound relay paths.
pub const PROCESS_RUNTIME_SOURCE: &str = "unavailable for remote VLESS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkKind {
    #[default]
    Unknown,
    Tcp,
    Udp,
    Unix,
}

impl NetworkKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Unix => "unix",
        }
    }
}

/// Routing evaluation input shared by data-plane dispatch and RoutingService TestRoute.
#[derive(Debug, Clone, Default)]
pub struct RouteContext {
    pub inbound_tag: String,
    pub network: NetworkKind,
    pub source_ips: Vec<IpAddr>,
    pub target_ips: Vec<IpAddr>,
    pub source_port: u16,
    pub target_port: u16,
    pub target_domain: String,
    pub protocol: String,
    pub user: String,
    pub attributes: HashMap<String, String>,
    pub local_ips: Vec<IpAddr>,
    pub local_port: u16,
    pub vless_route: u16,
    /// When set, DomainStrategy must not resolve the target domain (DNS loop guard).
    pub skip_dns_resolve: bool,
    /// Optional local process name when available (local/system traffic).
    pub process_name: String,
}

/// Result of a routing decision (implements routing.Route semantics).
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub context: RouteContext,
    pub outbound_tag: String,
    pub outbound_group_tags: Vec<String>,
    pub rule_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    NoClue,
    InvalidArgument(String),
    DuplicateRuleTag(String),
    DuplicateBalancerTag(String),
    BalancerNotFound(String),
    UnsupportedRule(String),
    Balancer(String),
    /// Required feature dependency (for example Observatory) is not configured.
    UnresolvedDependencies(String),
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoClue => f.write_str("no clue"),
            Self::InvalidArgument(message) | Self::UnsupportedRule(message) => f.write_str(message),
            Self::UnresolvedDependencies(message) => f.write_str(message),
            Self::DuplicateRuleTag(tag) => write!(f, "duplicate ruleTag {tag}"),
            Self::DuplicateBalancerTag(_tag) => write!(f, "duplicate balancer tag"),
            Self::BalancerNotFound(tag) => write!(f, "balancer {tag} not found"),
            Self::Balancer(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RouteError {}

#[cfg(test)]
#[path = "../../tests/unit/routing/context_parity.rs"]
mod context_parity_tests;
