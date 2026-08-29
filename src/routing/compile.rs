use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use prost::Message;
use regex::Regex;
use serde_json::Value;

use crate::api::proto::app::router::{
    BalancingRule as ProtoBalancingRule, Config as RouterConfig, RoutingRule as ProtoRoutingRule,
};
use crate::api::proto::common::geodata::domain::Type as DomainType;
use crate::api::proto::common::geodata::{
    domain_rule, ip_rule, Domain, DomainRule, GeoIpRule, GeoSiteRule, IpRule,
};
use crate::api::proto::common::net::Network;
use crate::api::proto::common::serial::TypedMessage;
use crate::config::xray::raw::{RoutingConfig, RoutingRuleObject};
use crate::routing::balancer::{
    parse_strategy, Balancer, BalancerConfig, BalancerStrategy, LeastLoadConfig, StrategyWeight,
};
use crate::routing::conditions::{
    AttributeMatcher, Condition, ConditionChain, DomainMatcher, InboundTagMatcher, IpMatcher,
    IpNetwork, LocalOsMatcher, NetworkMatcher, PortMatcher, PortRanges, ProcessMatcher,
    ProtocolMatcher, UserMatcher,
};
use crate::routing::context::{NetworkKind, RouteError};
use crate::routing::geodata::{domain_to_matcher_parts, GeodataCache, GeodataError};
use crate::routing::webhook::{compile_webhook, WebhookNotifier};
use crate::runtime::RuntimeOutboundManager;

pub const ROUTER_CONFIG_TYPE: &str = "xray.app.router.Config";

#[derive(Clone)]
pub struct CompiledRule {
    pub rule_tag: String,
    pub outbound_tag: Option<String>,
    pub balancer_tag: Option<String>,
    pub conditions: Arc<ConditionChain>,
    pub webhook: Option<Arc<dyn WebhookNotifier>>,
}

#[derive(Clone)]
pub struct RouteTable {
    pub rules: Vec<CompiledRule>,
    pub balancers: HashMap<String, Arc<Balancer>>,
}

pub struct RuleCompiler {
    geodata: GeodataCache,
    outbound: Arc<RuntimeOutboundManager>,
    health: crate::routing::health::SharedHealthProvider,
}

impl RuleCompiler {
    pub fn with_health(
        outbound: Arc<RuntimeOutboundManager>,
        geodata: GeodataCache,
        health: crate::routing::health::SharedHealthProvider,
    ) -> Self {
        Self {
            geodata,
            outbound,
            health,
        }
    }

    pub fn compile_startup_table(
        &self,
        routing: Option<&RoutingConfig>,
    ) -> Result<RouteTable, RouteError> {
        let mut rules = Vec::new();
        let mut balancers = HashMap::new();

        if let Some(routing) = routing {
            for raw in &routing.balancers {
                let balancer = compile_balancer_json(raw)?;
                if balancers.contains_key(&balancer.tag) {
                    return Err(RouteError::DuplicateBalancerTag(balancer.tag.clone()));
                }
                balancers.insert(
                    balancer.tag.clone(),
                    Arc::new(Balancer::new(
                        balancer,
                        Arc::clone(&self.outbound),
                        Some(Arc::clone(&self.health)),
                    )),
                );
            }

            for rule in &routing.rules {
                rules.push(self.compile_json_rule(rule, &balancers)?);
            }
        }

        Ok(RouteTable { rules, balancers })
    }

    pub fn reload_table(
        &self,
        current: &RouteTable,
        config: &RouterConfig,
        should_append: bool,
    ) -> Result<RouteTable, RouteError> {
        let mut rules = Vec::new();
        let mut balancers = HashMap::new();
        let mut exist_rule_tags = HashSet::new();

        if should_append {
            for rule in &current.rules {
                if !rule.rule_tag.is_empty() {
                    if exist_rule_tags.contains(&rule.rule_tag) {
                        return Err(RouteError::DuplicateRuleTag(rule.rule_tag.clone()));
                    }
                    exist_rule_tags.insert(rule.rule_tag.clone());
                }
                rules.push(rule.clone());
            }
            balancers = current
                .balancers
                .iter()
                .map(|(tag, balancer)| (tag.clone(), Arc::clone(balancer)))
                .collect();
        }

        for proto in &config.balancing_rule {
            let compiled = compile_balancer_proto(proto)?;
            if balancers.contains_key(&compiled.tag) {
                return Err(RouteError::DuplicateBalancerTag(compiled.tag.clone()));
            }
            balancers.insert(
                compiled.tag.clone(),
                Arc::new(Balancer::new(
                    compiled,
                    Arc::clone(&self.outbound),
                    Some(Arc::clone(&self.health)),
                )),
            );
        }

        for proto in &config.rule {
            let compiled = self.compile_proto_rule(proto, &balancers)?;
            if !compiled.rule_tag.is_empty() {
                if exist_rule_tags.contains(&compiled.rule_tag) {
                    return Err(RouteError::DuplicateRuleTag(compiled.rule_tag.clone()));
                }
                exist_rule_tags.insert(compiled.rule_tag.clone());
            }
            rules.push(compiled);
        }

        Ok(RouteTable { rules, balancers })
    }

    fn compile_json_rule(
        &self,
        rule: &RoutingRuleObject,
        balancers: &HashMap<String, Arc<Balancer>>,
    ) -> Result<CompiledRule, RouteError> {
        if rule
            .rule_type
            .as_deref()
            .is_some_and(|value| !value.eq_ignore_ascii_case("field"))
        {
            return Err(RouteError::UnsupportedRule(format!(
                "unsupported routing rule type: {}",
                rule.rule_type.as_deref().unwrap_or("")
            )));
        }

        let mut conditions: Vec<Box<dyn Condition>> = Vec::new();

        if let Some(value) = &rule.inbound_tag {
            conditions.push(Box::new(InboundTagMatcher::new(parse_string_list(value))));
        }

        if let Some(value) = rule.extra.get("network") {
            conditions.push(Box::new(NetworkMatcher::new(parse_network_list(value))));
        }

        if let Some(value) = rule
            .extra
            .get("domain")
            .or_else(|| rule.extra.get("domains"))
        {
            conditions.push(Box::new(
                self.compile_domain_json_list(parse_string_list(value))?,
            ));
        }

        if let Some(value) = rule.extra.get("ip") {
            conditions.push(Box::new(
                self.compile_ip_json_list(parse_string_list(value), false)?,
            ));
        }

        if let Some(value) = rule
            .extra
            .get("sourceIP")
            .or_else(|| rule.extra.get("source"))
        {
            conditions.push(Box::new(
                self.compile_ip_json_list(parse_string_list(value), true)?,
            ));
        }

        if let Some(value) = rule.extra.get("port") {
            conditions.push(Box::new(PortMatcher::target_only(parse_port_list(value))));
        }

        if let Some(value) = rule.extra.get("sourcePort") {
            conditions.push(Box::new(PortMatcher::source(parse_port_list(value))));
        }

        if let Some(value) = rule.extra.get("localIP") {
            let networks = self.compile_ip_json_networks(parse_string_list(value))?;
            conditions.push(Box::new(IpMatcher::local(networks)));
        }

        if let Some(value) = rule.extra.get("localPort") {
            conditions.push(Box::new(PortMatcher::local(parse_port_list(value))));
        }

        if let Some(value) = rule.extra.get("vlessRoute") {
            conditions.push(Box::new(PortMatcher::vless_route(parse_port_list(value))));
        }

        if let Some(value) = rule.extra.get("user") {
            conditions.push(Box::new(UserMatcher::new(parse_string_list(value))));
        }

        if let Some(value) = rule.extra.get("protocol") {
            conditions.push(Box::new(ProtocolMatcher::new(parse_string_list(value))));
        }

        if let Some(value) = rule.extra.get("attrs") {
            conditions.push(Box::new(
                AttributeMatcher::new(parse_attrs(value)).map_err(|err| {
                    RouteError::InvalidArgument(format!("invalid attribute regexp: {err}"))
                })?,
            ));
        }

        if let Some(value) = rule.extra.get("process") {
            conditions.push(Box::new(ProcessMatcher::new(parse_string_list(value))));
        }

        if let Some(value) = rule.extra.get("localOS") {
            conditions.push(Box::new(LocalOsMatcher::new(parse_string_list(value))));
        }

        if conditions.is_empty() {
            return Err(RouteError::InvalidArgument(
                "this rule has no effective fields".to_string(),
            ));
        }

        let balancer_tag = rule.balancer_tag.clone();
        if let Some(tag) = balancer_tag.as_deref() {
            if !balancers.contains_key(tag) {
                return Err(RouteError::BalancerNotFound(tag.to_string()));
            }
        }

        Ok(CompiledRule {
            rule_tag: rule
                .extra
                .get("ruleTag")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            outbound_tag: rule.outbound_tag.clone(),
            balancer_tag,
            conditions: Arc::new(ConditionChain::new(conditions)),
            webhook: compile_webhook_json(rule.extra.get("webhook"))?,
        })
    }

    fn compile_proto_rule(
        &self,
        rule: &ProtoRoutingRule,
        balancers: &HashMap<String, Arc<Balancer>>,
    ) -> Result<CompiledRule, RouteError> {
        let mut conditions: Vec<Box<dyn Condition>> = Vec::new();

        if !rule.inbound_tag.is_empty() {
            conditions.push(Box::new(InboundTagMatcher::new(rule.inbound_tag.clone())));
        }

        if !rule.networks.is_empty() {
            conditions.push(Box::new(NetworkMatcher::new(
                rule.networks
                    .iter()
                    .filter_map(|network| Network::try_from(*network).ok().and_then(proto_network))
                    .collect(),
            )));
        }

        if !rule.protocol.is_empty() {
            conditions.push(Box::new(ProtocolMatcher::new(rule.protocol.clone())));
        }

        if let Some(list) = rule.port_list.as_ref() {
            conditions.push(Box::new(PortMatcher::target_only(proto_port_list(list))));
        }

        if let Some(list) = rule.source_port_list.as_ref() {
            conditions.push(Box::new(PortMatcher::source(proto_port_list(list))));
        }

        if let Some(list) = rule.local_port_list.as_ref() {
            conditions.push(Box::new(PortMatcher::local(proto_port_list(list))));
        }

        if let Some(list) = rule.vless_route_list.as_ref() {
            conditions.push(Box::new(PortMatcher::vless_route(proto_port_list(list))));
        }

        if !rule.user_email.is_empty() {
            conditions.push(Box::new(UserMatcher::new(rule.user_email.clone())));
        }

        if !rule.attributes.is_empty() {
            conditions.push(Box::new(
                AttributeMatcher::new(
                    rule.attributes
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
                .map_err(|err| {
                    RouteError::InvalidArgument(format!("invalid attribute regexp: {err}"))
                })?,
            ));
        }

        if !rule.ip.is_empty() {
            conditions.push(Box::new(self.compile_ip_proto_list(&rule.ip, false)?));
        }

        if !rule.source_ip.is_empty() {
            conditions.push(Box::new(self.compile_ip_proto_list(&rule.source_ip, true)?));
        }

        if !rule.local_ip.is_empty() {
            conditions.push(Box::new(IpMatcher::local(
                self.compile_ip_networks(&rule.local_ip)?,
            )));
        }

        if !rule.domain.is_empty() {
            conditions.push(Box::new(self.compile_domain_proto_list(&rule.domain)?));
        }

        if !rule.process.is_empty() {
            conditions.push(Box::new(ProcessMatcher::new(rule.process.clone())));
        }

        if !rule.local_os.is_empty() {
            conditions.push(Box::new(LocalOsMatcher::new(rule.local_os.clone())));
        }

        if conditions.is_empty() {
            return Err(RouteError::InvalidArgument(
                "this rule has no effective fields".to_string(),
            ));
        }

        let outbound_tag = match &rule.target_tag {
            Some(crate::api::proto::app::router::routing_rule::TargetTag::Tag(tag)) => {
                Some(tag.clone())
            }
            _ => None,
        };
        let balancer_tag = match &rule.target_tag {
            Some(crate::api::proto::app::router::routing_rule::TargetTag::BalancingTag(tag)) => {
                if !balancers.contains_key(tag) {
                    return Err(RouteError::BalancerNotFound(tag.clone()));
                }
                Some(tag.clone())
            }
            _ => None,
        };

        Ok(CompiledRule {
            rule_tag: rule.rule_tag.clone(),
            outbound_tag,
            balancer_tag,
            conditions: Arc::new(ConditionChain::new(conditions)),
            webhook: compile_webhook(rule.webhook.as_ref()).map_err(|err| {
                RouteError::InvalidArgument(format!("invalid webhook config: {err}"))
            })?,
        })
    }

    fn compile_domain_json_list(&self, values: Vec<String>) -> Result<DomainMatcher, RouteError> {
        let mut full = Vec::new();
        let mut domain = Vec::new();
        let mut substr = Vec::new();
        let mut regex = Vec::new();

        for value in values {
            let (mut raw, _) = cut_reverse_prefix(&value);
            if raw.starts_with("geosite:") {
                raw = format!("ext:geosite.dat:{}", &raw["geosite:".len()..]);
            }
            if let Some(rest) = raw.strip_prefix("ext:") {
                self.push_geosite_json(rest, &mut full, &mut domain, &mut substr, &mut regex)?;
                continue;
            }
            if let Some(rest) = raw.strip_prefix("full:") {
                full.push(rest.to_string());
                continue;
            }
            if let Some(rest) = raw.strip_prefix("domain:") {
                domain.push(rest.to_string());
                continue;
            }
            if let Some(rest) = raw.strip_prefix("regexp:") {
                regex.push(Regex::new(rest).map_err(|err| {
                    RouteError::InvalidArgument(format!("invalid domain regexp: {err}"))
                })?);
                continue;
            }
            if let Some(rest) = raw.strip_prefix("keyword:") {
                substr.push(rest.to_string());
            } else {
                substr.push(raw);
            }
        }

        Ok(DomainMatcher::new(full, domain, substr, regex))
    }

    fn push_geosite_json(
        &self,
        rule: &str,
        full: &mut Vec<String>,
        domain: &mut Vec<String>,
        substr: &mut Vec<String>,
        regex: &mut Vec<Regex>,
    ) -> Result<(), RouteError> {
        let (file, code, attrs) = parse_ext_rule(rule)?;
        let geosite = GeoSiteRule {
            file,
            code: code.to_ascii_uppercase(),
            attrs,
        };
        self.push_geosite_domains(&geosite, full, domain, substr, regex)
    }

    fn compile_domain_proto_list(&self, rules: &[DomainRule]) -> Result<DomainMatcher, RouteError> {
        let mut full = Vec::new();
        let mut domain = Vec::new();
        let mut substr = Vec::new();
        let mut regex = Vec::new();

        for rule in rules {
            match &rule.value {
                Some(domain_rule::Value::Geosite(geosite)) => {
                    self.push_geosite_domains(
                        geosite,
                        &mut full,
                        &mut domain,
                        &mut substr,
                        &mut regex,
                    )?;
                }
                Some(domain_rule::Value::Custom(custom)) => {
                    push_domain(custom, &mut full, &mut domain, &mut substr, &mut regex)?;
                }
                None => {}
            }
        }

        Ok(DomainMatcher::new(full, domain, substr, regex))
    }

    fn push_geosite_domains(
        &self,
        geosite: &GeoSiteRule,
        full: &mut Vec<String>,
        domain: &mut Vec<String>,
        substr: &mut Vec<String>,
        regex: &mut Vec<Regex>,
    ) -> Result<(), RouteError> {
        let domains = self
            .geodata
            .load_geosite(&geosite.file, &geosite.code, &geosite.attrs)
            .map_err(map_geodata_error)?;
        for entry in domains.iter() {
            let parts = domain_to_matcher_parts(entry).map_err(map_geodata_error)?;
            match parts.kind {
                DomainType::Full => full.push(parts.value),
                DomainType::Domain => domain.push(parts.value),
                DomainType::Substr => substr.push(parts.value),
                DomainType::Regex => regex.push(Regex::new(&parts.value).map_err(|err| {
                    RouteError::InvalidArgument(format!("invalid domain regexp: {err}"))
                })?),
            }
        }
        Ok(())
    }

    fn compile_ip_json_list(
        &self,
        values: Vec<String>,
        source: bool,
    ) -> Result<IpMatcher, RouteError> {
        let networks = self.compile_ip_json_networks(values)?;
        Ok(if source {
            IpMatcher::source(networks)
        } else {
            IpMatcher::target(networks)
        })
    }

    fn compile_ip_json_networks(
        &self,
        values: Vec<String>,
    ) -> Result<Vec<(IpNetwork, bool)>, RouteError> {
        let mut networks = Vec::new();
        for value in values {
            let (raw, reverse) = cut_reverse_prefix(&value);
            let mut raw = raw;
            if raw.starts_with("geoip:") {
                raw = format!("ext:geoip.dat:{}", &raw["geoip:".len()..]);
            }
            if let Some(rest) = raw.strip_prefix("ext:") {
                networks.extend(self.compile_geoip_json(rest, reverse)?);
                continue;
            }
            let network = IpNetwork::parse(&raw).ok_or_else(|| {
                RouteError::InvalidArgument(format!("invalid CIDR in routing rule: {raw}"))
            })?;
            networks.push((network, reverse));
        }
        Ok(networks)
    }

    fn compile_geoip_json(
        &self,
        rule: &str,
        reverse: bool,
    ) -> Result<Vec<(IpNetwork, bool)>, RouteError> {
        let (file, code, _) = parse_ext_rule(rule)?;
        let geoip = GeoIpRule {
            file,
            code: code.to_ascii_uppercase(),
            reverse_match: reverse,
        };
        self.geodata
            .load_geoip(&geoip.file, &geoip.code, geoip.reverse_match)
            .map(|networks| networks.iter().cloned().collect())
            .map_err(map_geodata_error)
    }

    fn compile_ip_proto_list(
        &self,
        rules: &[IpRule],
        source: bool,
    ) -> Result<IpMatcher, RouteError> {
        Ok(if source {
            IpMatcher::source(self.compile_ip_networks(rules)?)
        } else {
            IpMatcher::target(self.compile_ip_networks(rules)?)
        })
    }

    fn compile_ip_networks(&self, rules: &[IpRule]) -> Result<Vec<(IpNetwork, bool)>, RouteError> {
        let mut networks = Vec::new();
        for rule in rules {
            match &rule.value {
                Some(ip_rule::Value::Geoip(geoip)) => {
                    networks.extend(
                        self.geodata
                            .load_geoip(&geoip.file, &geoip.code, geoip.reverse_match)
                            .map(|loaded| loaded.iter().cloned().collect::<Vec<_>>())
                            .map_err(map_geodata_error)?,
                    );
                }
                Some(ip_rule::Value::Custom(custom)) => {
                    let Some(cidr) = custom.cidr.as_ref() else {
                        continue;
                    };
                    let network =
                        IpNetwork::from_bytes(&cidr.ip, cidr.prefix).ok_or_else(|| {
                            RouteError::InvalidArgument("invalid CIDR in routing rule".to_string())
                        })?;
                    networks.push((network, custom.reverse_match));
                }
                None => {}
            }
        }
        Ok(networks)
    }
}

pub fn decode_router_config(message: &TypedMessage) -> Result<RouterConfig, RouteError> {
    if message.r#type != ROUTER_CONFIG_TYPE {
        return Err(RouteError::InvalidArgument(
            "AddRule: config type error".to_string(),
        ));
    }
    RouterConfig::decode(message.value.as_slice()).map_err(|err| {
        RouteError::InvalidArgument(format!("failed to decode router config: {err}"))
    })
}

fn compile_balancer_json(raw: &Value) -> Result<BalancerConfig, RouteError> {
    let tag = raw
        .get("tag")
        .and_then(Value::as_str)
        .ok_or_else(|| RouteError::InvalidArgument("empty balancer tag".to_string()))?
        .to_string();
    let selectors = raw
        .get("selector")
        .map(parse_string_list)
        .unwrap_or_default();
    if selectors.is_empty() {
        return Err(RouteError::InvalidArgument(
            "empty selector list".to_string(),
        ));
    }
    let strategy = raw
        .get("strategy")
        .and_then(|value| value.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let strategy = parse_strategy(strategy).map_err(RouteError::InvalidArgument)?;
    let fallback_tag = raw
        .get("fallbackTag")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(BalancerConfig {
        tag,
        selectors,
        strategy,
        fallback_tag,
        least_load: if strategy == BalancerStrategy::LeastLoad {
            Some(parse_least_load_json(
                raw.get("strategy").and_then(|value| value.get("settings")),
            )?)
        } else {
            None
        },
    })
}

fn compile_balancer_proto(rule: &ProtoBalancingRule) -> Result<BalancerConfig, RouteError> {
    if rule.tag.is_empty() {
        return Err(RouteError::InvalidArgument(
            "empty balancer tag".to_string(),
        ));
    }
    if rule.outbound_selector.is_empty() {
        return Err(RouteError::InvalidArgument(
            "empty selector list".to_string(),
        ));
    }
    let strategy = parse_strategy(&rule.strategy).map_err(RouteError::InvalidArgument)?;
    Ok(BalancerConfig {
        tag: rule.tag.clone(),
        selectors: rule.outbound_selector.clone(),
        strategy,
        fallback_tag: rule.fallback_tag.clone(),
        least_load: if strategy == BalancerStrategy::LeastLoad {
            Some(parse_least_load_proto(rule.strategy_settings.as_ref())?)
        } else {
            None
        },
    })
}

fn parse_least_load_proto(settings: Option<&TypedMessage>) -> Result<LeastLoadConfig, RouteError> {
    const TYPE: &str = "xray.app.router.StrategyLeastLoadConfig";
    let settings = settings.ok_or_else(|| {
        RouteError::InvalidArgument("leastLoad strategy settings are required".to_string())
    })?;
    if settings.r#type != TYPE {
        return Err(RouteError::InvalidArgument(format!(
            "expected typed message {TYPE}, got {}",
            settings.r#type
        )));
    }
    let decoded =
        crate::api::proto::app::router::StrategyLeastLoadConfig::decode(settings.value.as_slice())
            .map_err(|err| {
                RouteError::InvalidArgument(format!("failed to decode {TYPE}: {err}"))
            })?;
    let costs = decoded
        .costs
        .into_iter()
        .map(|weight| compile_strategy_weight(weight.regexp, weight.r#match, weight.value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LeastLoadConfig {
        costs,
        baselines: decoded.baselines,
        expected: decoded.expected,
        max_rtt: decoded.max_rtt,
        tolerance: decoded.tolerance,
    })
}

fn parse_least_load_json(settings: Option<&Value>) -> Result<LeastLoadConfig, RouteError> {
    let settings = settings.cloned().unwrap_or_else(|| serde_json::json!({}));
    let costs = settings
        .get("costs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|weight| {
            compile_strategy_weight(
                weight
                    .get("regexp")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                weight
                    .get("match")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                weight
                    .get("value")
                    .and_then(Value::as_f64)
                    .unwrap_or_default() as f32,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LeastLoadConfig {
        costs,
        baselines: settings
            .get("baselines")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_i64)
            .collect(),
        expected: settings
            .get("expected")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or_default(),
        max_rtt: settings
            .get("maxRTT")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        tolerance: settings
            .get("tolerance")
            .and_then(Value::as_f64)
            .unwrap_or_default() as f32,
    })
}

fn compile_strategy_weight(
    regexp: bool,
    matcher: String,
    value: f32,
) -> Result<StrategyWeight, RouteError> {
    let compiled = regexp
        .then(|| Regex::new(&matcher))
        .transpose()
        .map_err(|err| {
            RouteError::InvalidArgument(format!("invalid leastLoad cost regexp: {err}"))
        })?;
    Ok(StrategyWeight {
        matcher,
        value,
        compiled,
    })
}

fn compile_webhook_json(
    value: Option<&Value>,
) -> Result<Option<Arc<dyn WebhookNotifier>>, RouteError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let config = crate::api::proto::app::router::WebhookConfig {
        url: value
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        deduplication: value
            .get("deduplication")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or_default(),
        headers: value
            .get("headers")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|headers| headers.iter())
            .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
            .collect(),
    };
    compile_webhook(Some(&config))
        .map_err(|err| RouteError::InvalidArgument(format!("invalid webhook config: {err}")))
}

fn push_domain(
    custom: &Domain,
    full: &mut Vec<String>,
    domain: &mut Vec<String>,
    substr: &mut Vec<String>,
    regex: &mut Vec<Regex>,
) -> Result<(), RouteError> {
    let value = custom.value.clone();
    match DomainType::try_from(custom.r#type).unwrap_or(DomainType::Substr) {
        DomainType::Full => full.push(value),
        DomainType::Domain => domain.push(value),
        DomainType::Substr => substr.push(value),
        DomainType::Regex => {
            regex.push(Regex::new(&value).map_err(|err| {
                RouteError::InvalidArgument(format!("invalid domain regexp: {err}"))
            })?);
        }
    }
    Ok(())
}

fn cut_reverse_prefix(value: &str) -> (String, bool) {
    let mut reverse = false;
    let mut raw = value.to_string();
    while raw.starts_with('!') {
        raw = raw[1..].to_string();
        reverse = !reverse;
    }
    (raw, reverse)
}

fn parse_ext_rule(rule: &str) -> Result<(String, String, String), RouteError> {
    let (file, rest) = rule
        .split_once(':')
        .ok_or_else(|| RouteError::InvalidArgument("illegal geodata rule syntax".to_string()))?;
    if file.is_empty() {
        return Err(RouteError::InvalidArgument(
            "empty geodata file".to_string(),
        ));
    }
    let (code, attrs) = match rest.split_once('@') {
        Some((code, attrs)) => (code.to_string(), attrs.to_string()),
        None => (rest.to_string(), String::new()),
    };
    let (code, code_reverse) = cut_reverse_prefix(&code);
    let _ = code_reverse;
    if code.is_empty() {
        return Err(RouteError::InvalidArgument(
            "empty geodata code".to_string(),
        ));
    }
    Ok((file.to_string(), code, attrs))
}

fn map_geodata_error(err: GeodataError) -> RouteError {
    RouteError::InvalidArgument(err.to_string())
}

fn parse_string_list(value: &Value) -> Vec<String> {
    match value {
        Value::String(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect(),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_network_list(value: &Value) -> Vec<NetworkKind> {
    parse_string_list(value)
        .into_iter()
        .filter_map(|network| match network.to_ascii_lowercase().as_str() {
            "tcp" => Some(NetworkKind::Tcp),
            "udp" => Some(NetworkKind::Udp),
            "unix" => Some(NetworkKind::Unix),
            _ => None,
        })
        .collect()
}

fn parse_port_list(value: &Value) -> PortRanges {
    let mut ranges = PortRanges::default();
    if let Some(port) = value.as_u64().and_then(|port| u16::try_from(port).ok()) {
        ranges.push_range(port, port);
        return ranges;
    }
    for part in parse_string_list(value) {
        if let Some((from, to)) = part.split_once('-') {
            if let (Ok(from), Ok(to)) = (from.trim().parse(), to.trim().parse()) {
                ranges.push_range(from, to);
            }
            continue;
        }
        if let Ok(port) = part.parse::<u16>() {
            ranges.push_range(port, port);
        }
    }
    ranges
}

fn parse_attrs(value: &Value) -> Vec<(String, String)> {
    match value {
        Value::Object(map) => map
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|v| (key.clone(), v.to_string())))
            .collect(),
        _ => Vec::new(),
    }
}

fn proto_port_list(list: &crate::api::proto::common::net::PortList) -> PortRanges {
    let mut ranges = PortRanges::default();
    for range in &list.range {
        let from = u16::try_from(range.from).unwrap_or(0);
        let to = u16::try_from(range.to).unwrap_or(from);
        ranges.push_range(from, to);
    }
    ranges
}

fn proto_network(network: Network) -> Option<NetworkKind> {
    match network {
        Network::Tcp => Some(NetworkKind::Tcp),
        Network::Udp => Some(NetworkKind::Udp),
        Network::Unix => Some(NetworkKind::Unix),
        Network::Unknown => Some(NetworkKind::Unknown),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/routing/domain_geodata.rs"]
mod domain_geodata_tests;

#[cfg(test)]
#[path = "../../tests/unit/routing/compile.rs"]
mod compile_tests;
