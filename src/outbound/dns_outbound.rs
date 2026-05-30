use tracing::warn;

use crate::config::OutboundObject;

/// DNS outbound (`protocol: "dns"`) placeholder for future Xray-compatible DNS egress.
pub struct DnsOutboundPlaceholder {
    pub tag: Option<String>,
}

impl DnsOutboundPlaceholder {
    pub fn from_config(outbound: &OutboundObject) -> Self {
        Self {
            tag: outbound.tag.clone(),
        }
    }

    pub fn dial_unsupported(&self) -> std::io::Error {
        warn!(
            outbound_tag = self.tag.as_deref(),
            "dns outbound is parsed but not implemented yet"
        );
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "dns outbound{} is not implemented yet",
                self.tag
                    .as_deref()
                    .map(|tag| format!(" tag={tag}"))
                    .unwrap_or_default()
            ),
        )
    }
}

pub fn log_dns_outbounds(outbounds: &[OutboundObject]) {
    for outbound in outbounds {
        if outbound
            .protocol
            .as_deref()
            .is_some_and(|protocol| protocol.eq_ignore_ascii_case("dns"))
        {
            let _placeholder = DnsOutboundPlaceholder::from_config(outbound);
            warn!(
                outbound_tag = outbound.tag.as_deref(),
                "dns outbound present in config; egress path not implemented (placeholder only)"
            );
        }
    }
}
