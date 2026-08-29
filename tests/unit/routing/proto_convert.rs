use std::net::Ipv4Addr;

use crate::routing::{
    route_context_from_proto, route_decision_to_proto, RouteContext, RouteDecision,
};

#[test]
fn ipv4_round_trip_in_routing_context() {
    let ctx = RouteContext {
        target_ips: vec![Ipv4Addr::new(1, 2, 3, 4).into()],
        ..Default::default()
    };
    let decision = RouteDecision {
        context: ctx,
        outbound_tag: "direct".to_string(),
        outbound_group_tags: vec![],
        rule_tag: String::new(),
    };
    let proto = route_decision_to_proto(&decision);
    let back = route_context_from_proto(&proto);
    assert_eq!(back.target_ips, decision.context.target_ips);
}
