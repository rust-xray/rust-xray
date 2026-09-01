//! Captured / upstream-derived first traffic record regression.

use crate::vless::encryption::aead::TrafficAeadKind;
use crate::vless::encryption::EncryptedReader;

const GO_AES_HEADER: [u8; 5] = [0x17, 0x03, 0x03, 0x00, 0x27];
const GO_AES_CIPHERTEXT: [u8; 39] = [
    0x40, 0x75, 0x1f, 0x2b, 0x0d, 0x05, 0x2a, 0x50, 0x50, 0xb8, 0x09, 0xe6, 0x07, 0xa5, 0xf0, 0x5a,
    0x55, 0xbd, 0xa0, 0xc1, 0x72, 0xd9, 0x0c, 0xb4, 0x63, 0xec, 0x3d, 0x55, 0xc6, 0x03, 0x31, 0x3a,
    0xce, 0x0f, 0x3e, 0x5d, 0x9b, 0x27, 0x94,
];
const GOLDEN_CONTEXT: &[u8] = b"golden-traffic-context-1234567890";
const GOLDEN_PLAINTEXT: &[u8] = b"vless-traffic-plaintext";

#[test]
fn upstream_derived_first_traffic_record_opens_with_handshake_state() {
    let united = {
        let mut arr = [0u8; 96];
        arr[0] = 0x01;
        arr[32] = 0x02;
        arr[64] = 0x03;
        arr
    };
    let download = crate::vless::encryption::handshake::TrafficDirectionKeys {
        aead: crate::vless::encryption::aead::TrafficAead::new(GOLDEN_CONTEXT, &united, true),
        context_label: GOLDEN_CONTEXT.to_vec(),
    };
    let mut reader = EncryptedReader::new(download, united, true);
    let opened = reader
        .decrypt_record(&GO_AES_HEADER, &GO_AES_CIPHERTEXT)
        .expect("open captured upstream frame");
    assert_eq!(opened.as_ref(), GOLDEN_PLAINTEXT);
    assert_eq!(reader.aead_kind(), TrafficAeadKind::Aes256Gcm);
}
