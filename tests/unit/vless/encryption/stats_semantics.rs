//! Stats count logical application payload, not encryption transport overhead.

use std::net::IpAddr;
use std::sync::Arc;

use crate::config::PolicyConfig;
use crate::stats::{StatsConnection, StatsRegistry, StatsSession};

#[test]
fn stats_record_logical_uplink_and_downlink_payload_only() {
    let registry = Arc::new(StatsRegistry::new());
    let session = StatsSession::new(
        Arc::clone(&registry),
        crate::stats::StatsPolicy {
            inbound_uplink: true,
            inbound_downlink: true,
            outbound_uplink: true,
            outbound_downlink: true,
            user_uplink: true,
            user_downlink: true,
            user_online: false,
        },
        None::<&PolicyConfig>,
        "enc-in".to_string(),
        "direct".to_string(),
        Some("stats@test".to_string()),
        None,
        Some("127.0.0.1".parse::<IpAddr>().expect("ip")),
    );
    session.ensure_registered();
    let conn = StatsConnection::open(session);

    conn.record_uplink(1000);
    conn.record_downlink(2000);

    assert_eq!(
        registry
            .get(&format!("inbound>>>enc-in>>>traffic>>>uplink"), false)
            .expect("uplink"),
        1000
    );
    assert_eq!(
        registry
            .get(&format!("inbound>>>enc-in>>>traffic>>>downlink"), false)
            .expect("downlink"),
        2000
    );
    assert_eq!(
        registry
            .get(&format!("outbound>>>direct>>>traffic>>>uplink"), false)
            .expect("out uplink"),
        1000
    );
    assert_eq!(
        registry
            .get(&format!("outbound>>>direct>>>traffic>>>downlink"), false)
            .expect("out downlink"),
        2000
    );
    assert_eq!(
        registry
            .get(&format!("user>>>stats@test>>>traffic>>>uplink"), false)
            .expect("user uplink"),
        1000
    );
    assert_eq!(
        registry
            .get(&format!("user>>>stats@test>>>traffic>>>downlink"), false)
            .expect("user downlink"),
        2000
    );
}

#[test]
fn encrypted_record_overhead_exceeds_plaintext_length() {
    use super::stream_common::build_client_frames;
    let plain = vec![0xABu8; 1000];
    let wire = build_client_frames(&[plain.as_slice()]);
    assert!(
        wire.len() >= plain.len() + 5 + 16,
        "AEAD record must add header+tag beyond application payload"
    );
    assert!(wire.len() > plain.len());
}
