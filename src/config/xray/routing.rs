use tracing::warn;

use super::raw::XrayConfig;

pub(crate) fn validate_routing_config(config: &XrayConfig) -> std::io::Result<()> {
    let Some(routing) = config.routing.as_ref() else {
        return Ok(());
    };
    if !routing.rules.is_empty() {
        warn!(
            rule_count = routing.rules.len(),
            "routing.rules are parsed for API listen compatibility but are not enforced for proxy traffic"
        );
    }
    if !routing.balancers.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "routing.balancers are not supported at runtime",
        ));
    }
    Ok(())
}
