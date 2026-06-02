use super::*;

#[test]
fn classify_tls_client_hello() {
    let hint = classify_initial_bytes(&[0x16, 0x03, 0x01, 0x00, 0x05]);
    assert_eq!(hint, ApiWireHint::TlsClientHello);
}

#[test]
fn classify_http2_prior_knowledge() {
    let hint = classify_initial_bytes(HTTP2_PREFACE);
    assert_eq!(hint, ApiWireHint::Http2PriorKnowledge);
}
