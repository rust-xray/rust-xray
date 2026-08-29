use crate::api::proto::app::router::{Config as RouterConfig, RoutingRule};
use crate::api::proto::common::geodata::{domain, domain_rule, Domain, DomainRule};
use crate::api::proto::common::serial::TypedMessage;
use crate::routing::compile::decode_router_config;
use crate::routing::ROUTER_CONFIG_TYPE;
use prost::Message;

#[test]
fn rejects_wrong_typed_message_type() {
    let err = decode_router_config(&TypedMessage {
        r#type: "wrong.type".to_string(),
        value: vec![],
    })
    .expect_err("type error");
    assert!(err.to_string().contains("config type error"));
}

#[test]
fn decodes_domain_rule_config() {
    let config = RouterConfig {
        rule: vec![RoutingRule {
            target_tag: Some(
                crate::api::proto::app::router::routing_rule::TargetTag::Tag("direct".to_string()),
            ),
            rule_tag: "r1".to_string(),
            domain: vec![DomainRule {
                value: Some(domain_rule::Value::Custom(Domain {
                    r#type: domain::Type::Full as i32,
                    value: "example.com".to_string(),
                    attribute: vec![],
                })),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let decoded = decode_router_config(&TypedMessage {
        r#type: ROUTER_CONFIG_TYPE.to_string(),
        value: config.encode_to_vec(),
    })
    .expect("decode");
    assert_eq!(decoded.rule.len(), 1);
}
