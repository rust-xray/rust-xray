use std::net::IpAddr;

use crate::api::proto::app::router::command::RoutingContext;
use crate::api::proto::common::net::Network;
use crate::routing::context::{NetworkKind, RouteContext, RouteDecision};

pub fn route_context_from_proto(message: &RoutingContext) -> RouteContext {
    RouteContext {
        inbound_tag: message.inbound_tag.clone(),
        network: proto_network(message.network()),
        source_ips: decode_ips(&message.source_i_ps),
        target_ips: decode_ips(&message.target_i_ps),
        source_port: u16::try_from(message.source_port).unwrap_or(0),
        target_port: u16::try_from(message.target_port).unwrap_or(0),
        target_domain: message.target_domain.clone(),
        protocol: message.protocol.clone(),
        user: message.user.clone(),
        attributes: message.attributes.clone(),
        local_ips: decode_ips(&message.local_i_ps),
        local_port: u16::try_from(message.local_port).unwrap_or(0),
        vless_route: u16::try_from(message.vless_route).unwrap_or(0),
        skip_dns_resolve: false,
        process_name: String::new(),
    }
}

pub fn route_decision_to_proto(decision: &RouteDecision) -> RoutingContext {
    let ctx = &decision.context;
    RoutingContext {
        inbound_tag: ctx.inbound_tag.clone(),
        network: network_to_proto(ctx.network) as i32,
        source_i_ps: encode_ips(&ctx.source_ips),
        target_i_ps: encode_ips(&ctx.target_ips),
        source_port: ctx.source_port as u32,
        target_port: ctx.target_port as u32,
        target_domain: ctx.target_domain.clone(),
        protocol: ctx.protocol.clone(),
        user: ctx.user.clone(),
        attributes: ctx.attributes.clone(),
        outbound_group_tags: decision.outbound_group_tags.clone(),
        outbound_tag: decision.outbound_tag.clone(),
        local_i_ps: encode_ips(&ctx.local_ips),
        local_port: ctx.local_port as u32,
        vless_route: ctx.vless_route as u32,
    }
}

pub fn apply_field_selectors(decision: &RouteDecision, selectors: &[String]) -> RoutingContext {
    if selectors.is_empty() {
        return route_decision_to_proto(decision);
    }

    let mut message = RoutingContext::default();
    for (field, apply) in FIELD_APPLIERS {
        if selectors
            .iter()
            .any(|selector| field.starts_with(selector.as_str()))
        {
            apply(&mut message, decision);
        }
    }
    message
}

type FieldApplier = fn(&mut RoutingContext, &RouteDecision);

const FIELD_APPLIERS: &[(&str, FieldApplier)] = &[
    ("inbound", |message, decision| {
        message.inbound_tag = decision.context.inbound_tag.clone();
    }),
    ("network", |message, decision| {
        message.network = network_to_proto(decision.context.network) as i32;
    }),
    ("ip_source", |message, decision| {
        message.source_i_ps = encode_ips(&decision.context.source_ips);
    }),
    ("ip_target", |message, decision| {
        message.target_i_ps = encode_ips(&decision.context.target_ips);
    }),
    ("ip_local", |message, decision| {
        message.local_i_ps = encode_ips(&decision.context.local_ips);
    }),
    ("port_source", |message, decision| {
        message.source_port = decision.context.source_port as u32;
    }),
    ("port_target", |message, decision| {
        message.target_port = decision.context.target_port as u32;
    }),
    ("port_local", |message, decision| {
        message.local_port = decision.context.local_port as u32;
    }),
    ("domain", |message, decision| {
        message.target_domain = decision.context.target_domain.clone();
    }),
    ("protocol", |message, decision| {
        message.protocol = decision.context.protocol.clone();
    }),
    ("user", |message, decision| {
        message.user = decision.context.user.clone();
    }),
    ("attributes", |message, decision| {
        message.attributes = decision.context.attributes.clone();
    }),
    ("outbound_group", |message, decision| {
        message.outbound_group_tags = decision.outbound_group_tags.clone();
    }),
    ("outbound", |message, decision| {
        message.outbound_tag = decision.outbound_tag.clone();
        message.outbound_group_tags = decision.outbound_group_tags.clone();
    }),
];

fn decode_ips(raw: &[Vec<u8>]) -> Vec<IpAddr> {
    raw.iter()
        .filter_map(|bytes| match bytes.len() {
            4 => Some(IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]])),
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                Some(IpAddr::from(octets))
            }
            _ => None,
        })
        .collect()
}

fn encode_ips(ips: &[IpAddr]) -> Vec<Vec<u8>> {
    ips.iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        })
        .collect()
}

fn proto_network(network: Network) -> NetworkKind {
    match network {
        Network::Tcp => NetworkKind::Tcp,
        Network::Udp => NetworkKind::Udp,
        Network::Unix => NetworkKind::Unix,
        Network::Unknown => NetworkKind::Unknown,
    }
}

fn network_to_proto(network: NetworkKind) -> Network {
    match network {
        NetworkKind::Tcp => Network::Tcp,
        NetworkKind::Udp => Network::Udp,
        NetworkKind::Unix => Network::Unix,
        NetworkKind::Unknown => Network::Unknown,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/routing/proto_convert.rs"]
mod proto_convert_tests;
