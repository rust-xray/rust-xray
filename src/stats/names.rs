//! Xray-compatible counter names (`>>>` separated).

pub fn user_traffic_uplink(email: &str) -> String {
    format!("user>>>{email}>>>traffic>>>uplink")
}

pub fn user_traffic_downlink(email: &str) -> String {
    format!("user>>>{email}>>>traffic>>>downlink")
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
