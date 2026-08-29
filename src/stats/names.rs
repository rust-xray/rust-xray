//! Xray-compatible counter names (`>>>` separated).

pub fn user_traffic_uplink(email: &str) -> String {
    format!("user>>>{email}>>>traffic>>>uplink")
}

pub fn user_traffic_downlink(email: &str) -> String {
    format!("user>>>{email}>>>traffic>>>downlink")
}

pub fn user_online(email: &str) -> String {
    format!("user>>>{email}>>>online")
}

const USER_ONLINE_PREFIX: &str = "user>>>";
const USER_ONLINE_SUFFIX: &str = ">>>online";

/// Parse `user>>>EMAIL>>>online` into the email segment.
pub fn parse_user_online_email(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(USER_ONLINE_PREFIX)?;
    rest.strip_suffix(USER_ONLINE_SUFFIX)
        .filter(|email| !email.is_empty())
}

pub fn inbound_traffic_uplink(tag: &str) -> String {
    format!("inbound>>>{tag}>>>traffic>>>uplink")
}

pub fn inbound_traffic_downlink(tag: &str) -> String {
    format!("inbound>>>{tag}>>>traffic>>>downlink")
}

pub fn outbound_traffic_uplink(tag: &str) -> String {
    format!("outbound>>>{tag}>>>traffic>>>uplink")
}

pub fn outbound_traffic_downlink(tag: &str) -> String {
    format!("outbound>>>{tag}>>>traffic>>>downlink")
}
