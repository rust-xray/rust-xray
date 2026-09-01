use crate::vless::handle_reality_vless_tcp_inbound_traced;

#[test]
fn raw_transport_uses_reality_vless_handler_symbol() {
    let _handler = handle_reality_vless_tcp_inbound_traced::<tokio::io::DuplexStream>;
}
