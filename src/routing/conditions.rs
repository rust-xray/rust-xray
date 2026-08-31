use std::net::IpAddr;

use crate::routing::context::{NetworkKind, RouteContext};

/// Mutable routing evaluation state shared during a single pick_route pass.
pub struct RouteMatchState<'a> {
    pub ctx: &'a mut RouteContext,
    resolve_on_demand: bool,
    /// Lowercase target domain computed once per route decision for rule matching.
    normalized_domain: Option<String>,
}

impl<'a> RouteMatchState<'a> {
    pub fn new(ctx: &'a mut RouteContext, resolve_on_demand: bool) -> Self {
        Self {
            ctx,
            resolve_on_demand,
            normalized_domain: None,
        }
    }

    /// Returns the lowercase target domain, computing and caching it on first use.
    /// Original `ctx.target_domain` is preserved for outbound/SNI semantics.
    pub fn normalized_target_domain(&mut self) -> &str {
        if self.normalized_domain.is_none() && !self.ctx.target_domain.is_empty() {
            self.normalized_domain = Some(self.ctx.target_domain.to_ascii_lowercase());
        }
        self.normalized_domain.as_deref().unwrap_or("")
    }

    pub fn target_ips(&self) -> &[IpAddr] {
        &self.ctx.target_ips
    }

    fn should_resolve_target_ips(&self) -> bool {
        self.resolve_on_demand
            && self.ctx.target_ips.is_empty()
            && !self.ctx.target_domain.is_empty()
            && !self.ctx.skip_dns_resolve
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionResult {
    Match,
    NoMatch,
    ResolveTargetIps,
}

pub trait Condition: Send + Sync {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool;
    fn needs_target_ip_resolution(&self) -> bool {
        false
    }
}

pub struct InboundTagMatcher {
    tags: Vec<String>,
}

impl InboundTagMatcher {
    pub fn new(tags: Vec<String>) -> Self {
        Self {
            tags: tags.into_iter().filter(|tag| !tag.is_empty()).collect(),
        }
    }
}

impl Condition for InboundTagMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        !self.tags.is_empty() && self.tags.iter().any(|tag| tag == &state.ctx.inbound_tag)
    }
}

pub struct NetworkMatcher {
    networks: Vec<NetworkKind>,
}

impl NetworkMatcher {
    pub fn new(networks: Vec<NetworkKind>) -> Self {
        Self { networks }
    }
}

impl Condition for NetworkMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        !self.networks.is_empty() && self.networks.contains(&state.ctx.network)
    }
}

pub struct PortMatcher {
    ports: PortRanges,
    source: bool,
    target: bool,
    local: bool,
    vless_route: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PortRanges {
    ranges: Vec<(u16, u16)>,
}

impl PortRanges {
    pub fn push_range(&mut self, from: u16, to: u16) {
        self.ranges.push((from, to));
    }

    pub fn contains(&self, port: u16) -> bool {
        self.ranges
            .iter()
            .any(|(from, to)| *from <= port && port <= *to)
    }
}

impl PortMatcher {
    pub fn source(ports: PortRanges) -> Self {
        Self {
            ports,
            source: true,
            target: false,
            local: false,
            vless_route: false,
        }
    }

    pub fn local(ports: PortRanges) -> Self {
        Self {
            ports,
            source: false,
            target: false,
            local: true,
            vless_route: false,
        }
    }

    pub fn vless_route(ports: PortRanges) -> Self {
        Self {
            ports,
            source: false,
            target: false,
            local: false,
            vless_route: true,
        }
    }

    pub fn target_only(ports: PortRanges) -> Self {
        Self {
            ports,
            source: false,
            target: true,
            local: false,
            vless_route: false,
        }
    }
}

impl Condition for PortMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        if self.target && !self.source {
            return self.ports.contains(state.ctx.target_port);
        }
        if self.source && !self.target {
            return self.ports.contains(state.ctx.source_port);
        }
        if self.local {
            return self.ports.contains(state.ctx.local_port);
        }
        if self.vless_route {
            return self.ports.contains(state.ctx.vless_route);
        }
        false
    }
}

pub struct DomainMatcher {
    full: Vec<String>,
    domain: Vec<String>,
    substr: Vec<String>,
    regex: Vec<regex::Regex>,
}

fn normalize_domain_pattern(value: String) -> String {
    value.to_ascii_lowercase()
}

fn domain_suffix_match(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || domain.ends_with(suffix)
            && domain
                .as_bytes()
                .get(domain.len().wrapping_sub(suffix.len()).wrapping_sub(1))
                .is_some_and(|byte| *byte == b'.')
}

impl DomainMatcher {
    pub fn new(
        full: Vec<String>,
        domain: Vec<String>,
        substr: Vec<String>,
        regex: Vec<regex::Regex>,
    ) -> Self {
        Self {
            full: full.into_iter().map(normalize_domain_pattern).collect(),
            domain: domain.into_iter().map(normalize_domain_pattern).collect(),
            substr: substr.into_iter().map(normalize_domain_pattern).collect(),
            regex,
        }
    }
}

impl Condition for DomainMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        let domain = state.normalized_target_domain();
        if domain.is_empty() {
            return false;
        }
        if self.full.iter().any(|value| domain == value) {
            return true;
        }
        if self
            .domain
            .iter()
            .any(|value| domain_suffix_match(domain, value))
        {
            return true;
        }
        if self.substr.iter().any(|value| domain.contains(value)) {
            return true;
        }
        self.regex.iter().any(|re| re.is_match(domain))
    }
}

pub struct IpMatcher {
    networks: Vec<(IpNetwork, bool)>,
    source: bool,
    target: bool,
    local: bool,
}

#[derive(Debug, Clone)]
pub struct IpNetwork {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpNetwork {
    pub fn parse(input: &str) -> Option<Self> {
        let (addr_part, prefix_part) = input.split_once('/')?;
        let addr: IpAddr = addr_part.parse().ok()?;
        let prefix_len: u8 = prefix_part.parse().ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return None;
        }
        Some(Self { addr, prefix_len })
    }

    pub fn from_bytes(ip: &[u8], prefix: u32) -> Option<Self> {
        let addr = match ip.len() {
            4 => IpAddr::from([ip[0], ip[1], ip[2], ip[3]]),
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(ip);
                IpAddr::from(octets)
            }
            _ => return None,
        };
        let prefix_len = u8::try_from(prefix).ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return None;
        }
        Some(Self { addr, prefix_len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let net_bits = u32::from_be_bytes(net.octets());
                let cand_bits = u32::from_be_bytes(candidate.octets());
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (net_bits & mask) == (cand_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let net_bits = u128::from_be_bytes(net.octets());
                let cand_bits = u128::from_be_bytes(candidate.octets());
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (net_bits & mask) == (cand_bits & mask)
            }
            _ => false,
        }
    }

    fn same_family(&self, ip: IpAddr) -> bool {
        matches!(
            (self.addr, ip),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
    }
}

impl IpMatcher {
    pub fn target(networks: Vec<(IpNetwork, bool)>) -> Self {
        Self {
            networks,
            source: false,
            target: true,
            local: false,
        }
    }

    pub fn source(networks: Vec<(IpNetwork, bool)>) -> Self {
        Self {
            networks,
            source: true,
            target: false,
            local: false,
        }
    }

    pub fn local(networks: Vec<(IpNetwork, bool)>) -> Self {
        Self {
            networks,
            source: false,
            target: false,
            local: true,
        }
    }

    fn ips<'b>(&self, state: &'b mut RouteMatchState<'_>) -> &'b [IpAddr] {
        if self.target {
            state.target_ips()
        } else if self.source {
            &state.ctx.source_ips
        } else if self.local {
            &state.ctx.local_ips
        } else {
            &[]
        }
    }
}

impl Condition for IpMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        let ips = self.ips(state);
        if ips.is_empty() {
            return false;
        }
        ips.iter().any(|ip| {
            self.networks.iter().any(|(net, reverse)| {
                if !net.same_family(*ip) {
                    return false;
                }
                let matched = net.contains(*ip);
                matched != *reverse
            })
        })
    }

    fn needs_target_ip_resolution(&self) -> bool {
        self.target
    }
}

pub struct UserMatcher {
    exact: Vec<String>,
    regex: Vec<regex::Regex>,
}

impl UserMatcher {
    pub fn new(users: Vec<String>) -> Self {
        let mut exact = Vec::new();
        let mut regex = Vec::new();
        for user in users {
            if user.len() > 7 && user.starts_with("regexp:") {
                if let Ok(re) = regex::Regex::new(&user[7..]) {
                    regex.push(re);
                }
                continue;
            }
            if !user.is_empty() {
                exact.push(user);
            }
        }
        Self { exact, regex }
    }
}

impl Condition for UserMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        if state.ctx.user.is_empty() {
            return false;
        }
        if self.exact.iter().any(|user| user == &state.ctx.user) {
            return true;
        }
        self.regex.iter().any(|re| re.is_match(&state.ctx.user))
    }
}

pub struct ProtocolMatcher {
    protocols: Vec<String>,
}

impl ProtocolMatcher {
    pub fn new(protocols: Vec<String>) -> Self {
        Self {
            protocols: protocols.into_iter().filter(|p| !p.is_empty()).collect(),
        }
    }
}

impl Condition for ProtocolMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        if state.ctx.protocol.is_empty() {
            return false;
        }
        self.protocols
            .iter()
            .any(|protocol| state.ctx.protocol.starts_with(protocol))
    }
}

pub struct AttributeMatcher {
    required: Vec<(String, regex::Regex)>,
}

impl AttributeMatcher {
    pub fn new(required: Vec<(String, String)>) -> Result<Self, regex::Error> {
        let mut patterns = Vec::new();
        for (key, value) in required {
            patterns.push((key.to_ascii_lowercase(), regex::Regex::new(&value)?));
        }
        Ok(Self { required: patterns })
    }
}

impl Condition for AttributeMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        if state.ctx.attributes.is_empty() {
            return false;
        }
        let lowered: std::collections::HashMap<String, String> = state
            .ctx
            .attributes
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect();
        self.required.iter().all(|(key, regex)| {
            lowered
                .get(key)
                .is_some_and(|actual| regex.is_match(actual))
        })
    }
}

pub struct ProcessMatcher {
    names: Vec<String>,
}

impl ProcessMatcher {
    pub fn new(names: Vec<String>) -> Self {
        Self {
            names: names.into_iter().filter(|name| !name.is_empty()).collect(),
        }
    }
}

impl Condition for ProcessMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        if self.names.is_empty() || state.ctx.process_name.is_empty() {
            return false;
        }
        self.names
            .iter()
            .any(|name| name == &state.ctx.process_name)
    }
}

pub struct LocalOsMatcher {
    systems: Vec<String>,
}

impl LocalOsMatcher {
    pub fn new(systems: Vec<String>) -> Self {
        Self {
            systems: systems
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
        }
    }
}

impl Condition for LocalOsMatcher {
    fn matches(&self, state: &mut RouteMatchState<'_>) -> bool {
        let _ = state;
        if self.systems.is_empty() {
            return false;
        }
        let current = std::env::consts::OS.to_ascii_lowercase();
        self.systems.iter().any(|os| os == &current)
    }
}

pub struct ConditionChain {
    conditions: Vec<Box<dyn Condition>>,
}

impl ConditionChain {
    pub fn new(conditions: Vec<Box<dyn Condition>>) -> Self {
        Self { conditions }
    }

    pub fn evaluate(&self, state: &mut RouteMatchState<'_>) -> ConditionResult {
        for condition in &self.conditions {
            if condition.needs_target_ip_resolution() && state.should_resolve_target_ips() {
                return ConditionResult::ResolveTargetIps;
            }
            if !condition.matches(state) {
                return ConditionResult::NoMatch;
            }
        }
        ConditionResult::Match
    }
}
