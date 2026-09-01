use crate::vless::encryption::parse_inbound_decryption;

#[test]
fn parser_does_not_panic_on_garbage() {
    for input in [
        "",
        "a",
        "mlkem768x25519plus",
        "mlkem768x25519plus.",
        "mlkem768x25519plus.native",
        "mlkem768x25519plus.native.",
        "mlkem768x25519plus.native.600s",
        "mlkem768x25519plus.native.not-a-number.s",
        "mlkem768x25519plus.native.999999999999999999999s.key",
        "mlkem768x25519plus.native.600s.!!!",
    ] {
        let _ = parse_inbound_decryption(input);
    }
}
