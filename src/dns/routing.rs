use crate::config::{OutboundObject, RoutingConfig, RoutingRuleObject};
use serde_json::Value;

use super::client::Network;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRoutingContext {
    pub network: Network,
    pub destination_host: String,
    pub destination_port: u16,
    pub inbound_tag: Option<String>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsRouter {
    routing: Option<RoutingConfig>,
    outbounds: Vec<OutboundObject>,
}

impl DnsRouter {
    pub fn new(routing: Option<RoutingConfig>, outbounds: Vec<OutboundObject>) -> Self {
        Self { routing, outbounds }
    }

    pub fn select_outbound_tag(&self, ctx: &DnsRoutingContext) -> Option<String> {
        if let Some(routing) = &self.routing {
            for rule in &routing.rules {
                if rule_matches(rule, ctx) {
                    if let Some(tag) = &rule.outbound_tag {
                        return Some(tag.clone());
                    }
                }
            }
        }
        self.outbounds
            .first()
            .and_then(|outbound| outbound.tag.clone())
            .or_else(|| self.outbounds.first().map(default_outbound_tag))
    }
}

fn default_outbound_tag(outbound: &OutboundObject) -> String {
    outbound
        .protocol
        .clone()
        .unwrap_or_else(|| "default".to_string())
}

fn rule_matches(rule: &RoutingRuleObject, ctx: &DnsRoutingContext) -> bool {
    if let Some(rule_type) = rule.rule_type.as_deref() {
        if !rule_type.eq_ignore_ascii_case("field") {
            return false;
        }
    }
    inbound_matches(rule, ctx) && network_matches(rule, ctx) && port_matches(rule, ctx)
}

fn inbound_matches(rule: &RoutingRuleObject, ctx: &DnsRoutingContext) -> bool {
    let Some(value) = &rule.inbound_tag else {
        return true;
    };
    let Some(inbound_tag) = ctx.inbound_tag.as_deref() else {
        return false;
    };
    match value {
        Value::String(tag) => tag == inbound_tag,
        Value::Array(tags) => tags
            .iter()
            .filter_map(Value::as_str)
            .any(|tag| tag == inbound_tag),
        _ => false,
    }
}

fn network_matches(rule: &RoutingRuleObject, ctx: &DnsRoutingContext) -> bool {
    let Some(value) = rule.extra.get("network") else {
        return true;
    };
    let expected = ctx.network.as_str();
    match value {
        Value::String(networks) => networks
            .split(',')
            .map(str::trim)
            .any(|network| network.eq_ignore_ascii_case(expected)),
        Value::Array(networks) => networks
            .iter()
            .filter_map(Value::as_str)
            .any(|network| network.eq_ignore_ascii_case(expected)),
        _ => false,
    }
}

fn port_matches(rule: &RoutingRuleObject, ctx: &DnsRoutingContext) -> bool {
    let Some(value) = rule.extra.get("port") else {
        return true;
    };
    match value {
        Value::Number(port) => port.as_u64() == Some(ctx.destination_port as u64),
        Value::String(expr) => port_expr_matches(expr, ctx.destination_port),
        Value::Array(values) => values.iter().any(|value| match value {
            Value::Number(port) => port.as_u64() == Some(ctx.destination_port as u64),
            Value::String(expr) => port_expr_matches(expr, ctx.destination_port),
            _ => false,
        }),
        _ => false,
    }
}

fn port_expr_matches(expr: &str, port: u16) -> bool {
    expr.split(',').map(str::trim).any(|part| {
        if let Some((start, end)) = part.split_once('-') {
            let Ok(start) = start.trim().parse::<u16>() else {
                return false;
            };
            let Ok(end) = end.trim().parse::<u16>() else {
                return false;
            };
            return start <= port && port <= end;
        }
        part.parse::<u16>().is_ok_and(|expected| expected == port)
    })
}

#[cfg(test)]
#[path = "../../tests/unit/dns/routing.rs"]
mod tests;
