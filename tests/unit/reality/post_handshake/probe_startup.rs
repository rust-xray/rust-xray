use crate::config::{
    InboundTransportConfig, LimitFallback, RealityServerConfig, VlessRealityInbound, VlessUser,
};
use crate::reality::{
    post_handshake_probe_cache, PostHandshakeProbeCache, PostHandshakeProbeKey,
    PostHandshakeProbeState, RealityAlpnProfile, RealityDestTransport,
};

fn probe_inbound(dest: &str, server_names: &[&str]) -> VlessRealityInbound {
    VlessRealityInbound {
        tag: Some("probe-test".to_string()),
        listen_addr: "127.0.0.1:443".to_string(),
        users: Vec::<VlessUser>::new(),
        transport: InboundTransportConfig::RawTcp,
        fallbacks: Vec::new(),
        sniffing_enabled: false,
        reality: RealityServerConfig {
            dest_addr: dest.to_string(),
            private_key: "test".to_string(),
            server_names: server_names
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            short_ids: vec![Vec::new()],
            max_time_diff: 0,
            min_client_ver: None,
            max_client_ver: None,
            show: false,
            mldsa65_seed: None,
            decryption: "none".to_string(),
            dest_xver: 0,
            dest_transport: RealityDestTransport::Tcp,
            limit_fallback_upload: LimitFallback::default(),
            limit_fallback_download: LimitFallback::default(),
        },
    }
}

#[test]
fn schedules_server_name_times_three_alpn_profiles() {
    let cache = PostHandshakeProbeCache::new();
    let inbounds = vec![probe_inbound("127.0.0.1:9", &["a.example", "b.example"])];

    let mut scheduled = 0usize;
    for inbound in &inbounds {
        for server_name in &inbound.reality.server_names {
            for alpn_profile in RealityAlpnProfile::PROBE_PROFILES {
                let key = PostHandshakeProbeKey {
                    dest_addr: inbound.reality.dest_addr.clone(),
                    server_name: server_name.clone(),
                    alpn_profile,
                };
                if cache.try_begin_detection(key) {
                    scheduled += 1;
                }
            }
        }
    }

    assert_eq!(scheduled, 6);
}

#[test]
fn alpn_profile_classification_matches_upstream_grouping() {
    assert_eq!(
        RealityAlpnProfile::classify_alpn_offers(&[]),
        RealityAlpnProfile::None
    );
    assert_eq!(
        RealityAlpnProfile::classify_alpn_offers(&["h2".to_string()]),
        RealityAlpnProfile::H2
    );
    assert_eq!(
        RealityAlpnProfile::classify_alpn_offers(&["http/1.1".to_string()]),
        RealityAlpnProfile::Http11
    );
    assert_eq!(
        RealityAlpnProfile::classify_alpn_offers(&["h2".to_string(), "http/1.1".to_string()]),
        RealityAlpnProfile::H2
    );
}

#[tokio::test]
async fn global_cache_is_accessible() {
    let _ = post_handshake_probe_cache();
}

#[test]
fn ready_empty_is_distinguishable_from_not_started() {
    let cache = PostHandshakeProbeCache::new();
    let key = PostHandshakeProbeKey {
        dest_addr: "example.com:443".to_string(),
        server_name: "example.com".to_string(),
        alpn_profile: RealityAlpnProfile::None,
    };

    assert!(cache.get(&key).is_none());
    cache.complete_detection(&key, Vec::new());
    assert_eq!(
        cache.get(&key),
        Some(PostHandshakeProbeState::Ready(Vec::new()))
    );
}
