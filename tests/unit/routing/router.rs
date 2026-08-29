use std::sync::Arc;

use crate::config::xray::raw::OutboundObject;
use crate::dns::engine::DnsEngine;
use crate::routing::{RouteContext, RuntimeRouter};
use crate::runtime::RuntimeOutboundManager;

fn test_router(tags: &[&str]) -> Arc<RuntimeRouter> {
    let outbound = RuntimeOutboundManager::new();
    for tag in tags {
        outbound
            .register_startup_outbound(&OutboundObject {
                tag: Some(tag.to_string()),
                protocol: Some("freedom".to_string()),
                extra: Default::default(),
            })
            .expect("outbound");
    }
    RuntimeRouter::new(
        None,
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router")
}

#[tokio::test]
async fn default_outbound_used_when_no_rule_matches() {
    let router = test_router(&["direct-a", "direct-b"]);
    let decision = router
        .pick_route_with_default(RouteContext {
            target_domain: "nomatch.example".to_string(),
            ..Default::default()
        })
        .await
        .expect("decision");
    assert_eq!(decision.outbound_tag, "direct-a");
}
