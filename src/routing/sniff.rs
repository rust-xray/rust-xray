/// Sniff application protocol from the first payload bytes (Xray-compatible subset).
pub fn sniff_protocol_from_payload(payload: &[u8]) -> String {
    if payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03 {
        return "tls".to_string();
    }
    if looks_like_http(payload) {
        return "http".to_string();
    }
    String::new()
}

fn looks_like_http(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 5] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE "];
    METHODS.iter().any(|method| payload.starts_with(method))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_client_hello_sniffs_as_tls() {
        assert_eq!(sniff_protocol_from_payload(&[0x16, 0x03, 0x01]), "tls");
    }
}
