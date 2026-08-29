use tracing::warn;

use super::raw::XrayConfig;

pub(crate) fn validate_routing_config(config: &XrayConfig) -> std::io::Result<()> {
    let Some(routing) = config.routing.as_ref() else {
        return Ok(());
    };
    if !routing.rules.is_empty() {
        tracing::debug!(
            rule_count = routing.rules.len(),
            "routing.rules loaded into RuntimeRouter"
        );
    }
    if !routing.balancers.is_empty() {
        warn!(
            balancer_count = routing.balancers.len(),
            "routing.balancers parsed; unsupported strategies fail at compile time"
        );
    }
    Ok(())
}
