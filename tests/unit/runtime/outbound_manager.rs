use std::sync::Arc;

use crate::runtime::{encode_blackhole_outbound, encode_freedom_outbound, RuntimeOutboundManager};

fn add_freedom(manager: &Arc<RuntimeOutboundManager>, tag: &str) {
    manager
        .add_outbound(encode_freedom_outbound(tag))
        .expect("add freedom outbound");
}

#[test]
fn first_inserted_becomes_default() {
    let manager = RuntimeOutboundManager::new();
    add_freedom(&manager, "A");
    add_freedom(&manager, "B");
    add_freedom(&manager, "C");
    assert_eq!(manager.default_tag().as_deref(), Some("A"));
}

#[test]
fn remove_non_default_leaves_default_unchanged() {
    let manager = RuntimeOutboundManager::new();
    add_freedom(&manager, "A");
    add_freedom(&manager, "B");
    manager.remove_outbound("B").expect("remove B");
    assert_eq!(manager.default_tag().as_deref(), Some("A"));
    assert_eq!(manager.registration_order(), vec!["A"]);
}

#[test]
fn remove_default_selects_next_registered() {
    let manager = RuntimeOutboundManager::new();
    add_freedom(&manager, "A");
    add_freedom(&manager, "B");
    add_freedom(&manager, "C");
    manager.remove_outbound("A").expect("remove A");
    assert_eq!(manager.default_tag().as_deref(), Some("B"));
}

#[test]
fn repeated_removals_preserve_registration_order() {
    let manager = RuntimeOutboundManager::new();
    add_freedom(&manager, "A");
    add_freedom(&manager, "B");
    add_freedom(&manager, "C");
    manager.remove_outbound("A").expect("remove A");
    assert_eq!(manager.registration_order(), vec!["B", "C"]);
    manager.remove_outbound("B").expect("remove B");
    assert_eq!(manager.default_tag().as_deref(), Some("C"));
    assert_eq!(manager.registration_order(), vec!["C"]);
}

#[test]
fn add_after_removals_keeps_current_default() {
    let manager = RuntimeOutboundManager::new();
    add_freedom(&manager, "A");
    add_freedom(&manager, "B");
    add_freedom(&manager, "C");
    manager.remove_outbound("A").expect("remove A");
    manager.remove_outbound("B").expect("remove B");
    add_freedom(&manager, "D");
    assert_eq!(manager.default_tag().as_deref(), Some("C"));
    assert_eq!(manager.registration_order(), vec!["C", "D"]);
}

#[test]
fn remove_all_clears_default() {
    let manager = RuntimeOutboundManager::new();
    add_freedom(&manager, "A");
    add_freedom(&manager, "B");
    manager.remove_outbound("A").expect("remove A");
    manager.remove_outbound("B").expect("remove B");
    assert_eq!(manager.default_tag(), None);
    assert!(manager.registration_order().is_empty());
}

#[test]
fn readd_same_tag_gets_new_registration_position() {
    let manager = RuntimeOutboundManager::new();
    add_freedom(&manager, "A");
    add_freedom(&manager, "B");
    manager.remove_outbound("A").expect("remove A");
    add_freedom(&manager, "A");
    assert_eq!(manager.registration_order(), vec!["B", "A"]);
    manager.remove_outbound("B").expect("remove B");
    assert_eq!(manager.default_tag().as_deref(), Some("A"));
}

#[test]
fn default_selection_is_independent_of_hashmap_iteration() {
    for _ in 0..32 {
        let manager = RuntimeOutboundManager::new();
        for tag in ["A", "B", "C", "D", "E"] {
            add_freedom(&manager, tag);
        }
        manager.remove_outbound("A").expect("remove A");
        assert_eq!(manager.default_tag().as_deref(), Some("B"));
        manager.remove_outbound("B").expect("remove B");
        assert_eq!(manager.default_tag().as_deref(), Some("C"));
    }
}

#[test]
fn dynamic_handler_lifecycle_matches_registration_order() {
    let manager = RuntimeOutboundManager::new();
    add_freedom(&manager, "A");
    add_freedom(&manager, "B");
    assert_eq!(manager.default_tag().as_deref(), Some("A"));

    manager.remove_outbound("A").expect("remove A");
    assert_eq!(manager.default_tag().as_deref(), Some("B"));

    add_freedom(&manager, "C");
    assert_eq!(manager.default_tag().as_deref(), Some("B"));

    manager.remove_outbound("B").expect("remove B");
    assert_eq!(manager.default_tag().as_deref(), Some("C"));
}

#[test]
fn startup_register_skips_duplicate_without_reordering() {
    let manager = RuntimeOutboundManager::new();
    let outbound = crate::config::xray::raw::OutboundObject {
        tag: Some("direct".to_string()),
        protocol: Some("freedom".to_string()),
        extra: Default::default(),
    };
    manager
        .register_startup_outbound(&outbound)
        .expect("first register");
    manager
        .register_startup_outbound(&outbound)
        .expect("duplicate register");
    assert_eq!(manager.registration_order(), vec!["direct"]);
    assert_eq!(manager.default_tag().as_deref(), Some("direct"));
}

#[test]
fn blackhole_outbound_participates_in_default_chain() {
    let manager = RuntimeOutboundManager::new();
    manager
        .add_outbound(encode_blackhole_outbound("block"))
        .expect("block");
    add_freedom(&manager, "direct");
    manager.remove_outbound("block").expect("remove block");
    assert_eq!(manager.default_tag().as_deref(), Some("direct"));
}
