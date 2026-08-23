//! Proactive REALITY post-handshake record-length probe startup.

use std::sync::OnceLock;

use tracing::debug;

use crate::config::VlessRealityInbound;

use super::dest_dial::RealityDestDialConfig;
use super::post_handshake::cache::{PostHandshakeProbeCache, PostHandshakeProbeKey};
use super::post_handshake::probe::execute_post_handshake_probe;

static GLOBAL_POST_HANDSHAKE_PROBE_CACHE: OnceLock<PostHandshakeProbeCache> = OnceLock::new();

/// Process-wide post-handshake probe cache (lazy-initialized).
pub fn post_handshake_probe_cache() -> &'static PostHandshakeProbeCache {
    GLOBAL_POST_HANDSHAKE_PROBE_CACHE.get_or_init(PostHandshakeProbeCache::new)
}

/// Starts background post-handshake probes for every configured `serverName × 3` ALPN profile.
///
/// Does not block listener startup. Multiple inbounds sharing the same `(dest, SNI, ALPN)` key
/// share one probe via [`PostHandshakeProbeCache::try_begin_detection`].
pub fn start_reality_post_handshake_probes(inbounds: &[VlessRealityInbound]) {
    let cache = post_handshake_probe_cache();
    let mut scheduled = 0usize;

    for inbound in inbounds {
        let dial_config = RealityDestDialConfig {
            dest_addr: inbound.reality.dest_addr.clone(),
            transport: inbound.reality.dest_transport,
            xver: inbound.reality.dest_xver,
        };

        for server_name in &inbound.reality.server_names {
            for alpn_profile in super::post_handshake::RealityAlpnProfile::PROBE_PROFILES {
                let key = PostHandshakeProbeKey {
                    dest_addr: dial_config.dest_addr.clone(),
                    server_name: server_name.clone(),
                    alpn_profile,
                };

                if !cache.try_begin_detection(key.clone()) {
                    continue;
                }

                scheduled += 1;
                let cache = cache.clone();
                let dial_config = dial_config.clone();
                tokio::spawn(async move {
                    run_post_handshake_probe(cache, key, dial_config).await;
                });
            }
        }
    }

    if scheduled > 0 {
        debug!(
            scheduled_probe_count = scheduled,
            "REALITY post-handshake record-length probes scheduled"
        );
    }
}

async fn run_post_handshake_probe(
    cache: PostHandshakeProbeCache,
    key: PostHandshakeProbeKey,
    dial_config: RealityDestDialConfig,
) {
    let mut guard = ProbeCompletionGuard::new(cache, key);
    let result = execute_post_handshake_probe(&dial_config, &guard.key).await;
    match result {
        Ok(lengths) => guard.complete_with(lengths),
        Err(err) => {
            debug!(
                dest = %guard.key.dest_addr,
                server_name = %guard.key.server_name,
                alpn_profile = ?guard.key.alpn_profile,
                error = %err,
                "REALITY post-handshake probe failed"
            );
            guard.complete_empty();
        }
    }
}

struct ProbeCompletionGuard {
    cache: PostHandshakeProbeCache,
    key: PostHandshakeProbeKey,
    completed: bool,
}

impl ProbeCompletionGuard {
    fn new(cache: PostHandshakeProbeCache, key: PostHandshakeProbeKey) -> Self {
        Self {
            cache,
            key,
            completed: false,
        }
    }

    fn complete_with(&mut self, lengths: Vec<usize>) {
        self.cache.complete_detection(&self.key, lengths);
        self.completed = true;
    }

    fn complete_empty(&mut self) {
        self.cache.complete_detection_empty(&self.key);
        self.completed = true;
    }
}

impl Drop for ProbeCompletionGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.cache.complete_detection_empty(&self.key);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/reality/post_handshake/probe_startup.rs"]
mod tests;
