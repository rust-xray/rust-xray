use crate::protocol::structs::{ClientHelloPayload, ServerNamePayload};

/// Returns the first DNS hostname from the ClientHello SNI extension, lowercased.
pub fn extract_sni_hostname(hello: &ClientHelloPayload) -> Option<String> {
    let names = hello.sni_extension()?;
    for name in names {
        if let ServerNamePayload::HostName(dns) = &name.payload {
            return Some(dns.as_ref().to_ascii_lowercase());
        }
    }
    None
}

pub fn server_name_allowed(sni: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return false;
    }

    let sni_lower = sni.to_ascii_lowercase();
    allowed
        .iter()
        .any(|name| name.to_ascii_lowercase() == sni_lower)
}

#[cfg(test)]
#[path = "../../tests/unit/reality/sni.rs"]
mod tests;
