use crate::vless::encryption::aead::{TrafficAead, TrafficAeadKind};
use crate::vless::encryption::header::encode_traffic_header;

/// Go-derived traffic golden from Xray-core @ 5e245b082e6be8c8899c34410f488e8ab001aaba
/// Generator: proxy/vless/encryption/common.go NewAEAD + CommonConn.Write
/// Inputs: united[0]=0x01, united[32]=0x02, united[64]=0x03,
///         context=`golden-traffic-context-1234567890`,
///         plaintext=`vless-traffic-plaintext`, prefer AES, initial nonce 00..00
const GO_AES_HEADER: &str = "1703030027";
const GO_AES_CIPHERTEXT: &str =
    "40751f2b0d052a5050b809e607a5f05a55bda0c172d90cb463ec3d55c603313ace0f3e5d9b2794";
const GO_CHACHA_CIPHERTEXT: &str =
    "ec82862fcbdb1f8560bcf8d51f2acb4ff7f62e4e5ba19840b216b763cdc97be083f67d9c6c0b76";

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn golden_united() -> [u8; 96] {
    let mut arr = [0u8; 96];
    arr[0] = 0x01;
    arr[32] = 0x02;
    arr[64] = 0x03;
    arr
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn rust_encrypt_matches_go_aes_traffic_frame() {
    let united = golden_united();
    let ctx = b"golden-traffic-context-1234567890";
    let plaintext = b"vless-traffic-plaintext";
    let mut aead = TrafficAead::new(ctx, &united, true);
    assert_eq!(aead.kind(), TrafficAeadKind::Aes256Gcm);

    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (plaintext.len() + 16) as u16);
    assert_eq!(hex_encode(&header), GO_AES_HEADER);

    let mut buffer = plaintext.to_vec();
    let sealed = aead.seal_in_place(&mut buffer, &header).expect("seal");
    assert_eq!(hex_encode(&buffer[..sealed]), GO_AES_CIPHERTEXT);
}

#[test]
fn rust_decrypt_go_aes_frame_yields_plaintext() {
    let united = golden_united();
    let ctx = b"golden-traffic-context-1234567890";
    let plaintext = b"vless-traffic-plaintext";
    let header = hex_decode(GO_AES_HEADER);
    let mut arr = [0u8; 5];
    arr.copy_from_slice(&header);
    let body = hex_decode(GO_AES_CIPHERTEXT);

    let mut reader = TrafficAead::new(ctx, &united, true);
    reader.set_kind(TrafficAeadKind::Aes256Gcm);
    let mut open_buf = body.clone();
    let opened = reader
        .open_in_place(&mut open_buf, plaintext.len(), &arr)
        .expect("open go frame");
    assert_eq!(&open_buf[..opened], plaintext);
}

#[test]
fn rust_encrypt_matches_go_chacha_traffic_ciphertext() {
    let united = golden_united();
    let ctx = b"golden-traffic-context-1234567890";
    let plaintext = b"vless-traffic-plaintext";
    let mut aead = TrafficAead::new(ctx, &united, false);
    assert_eq!(aead.kind(), TrafficAeadKind::ChaCha20Poly1305);

    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (plaintext.len() + 16) as u16);
    let mut buffer = plaintext.to_vec();
    let sealed = aead.seal_in_place(&mut buffer, &header).expect("seal");
    assert_eq!(hex_encode(&buffer[..sealed]), GO_CHACHA_CIPHERTEXT);
}

#[test]
fn rust_decrypt_go_chacha_frame_yields_plaintext() {
    let united = golden_united();
    let ctx = b"golden-traffic-context-1234567890";
    let plaintext = b"vless-traffic-plaintext";
    let header = hex_decode(GO_AES_HEADER);
    let mut arr = [0u8; 5];
    arr.copy_from_slice(&header);
    let body = hex_decode(GO_CHACHA_CIPHERTEXT);

    let mut reader = TrafficAead::new(ctx, &united, false);
    reader.set_kind(TrafficAeadKind::ChaCha20Poly1305);
    let mut open_buf = body;
    let opened = reader
        .open_in_place(&mut open_buf, plaintext.len(), &arr)
        .expect("open go chacha frame");
    assert_eq!(&open_buf[..opened], plaintext);
}

#[test]
fn go_frame_concat_roundtrip() {
    let frame = hex_decode(&format!("{GO_AES_HEADER}{GO_AES_CIPHERTEXT}"));
    let united = golden_united();
    let ctx = b"golden-traffic-context-1234567890";
    let mut reader = TrafficAead::new(ctx, &united, true);
    reader.set_kind(TrafficAeadKind::Aes256Gcm);
    let mut header = [0u8; 5];
    header.copy_from_slice(&frame[..5]);
    let plain_len = b"vless-traffic-plaintext".len();
    let mut body = frame[5..].to_vec();
    let opened = reader
        .open_in_place(&mut body, plain_len, &header)
        .expect("open full frame");
    assert_eq!(&body[..opened], b"vless-traffic-plaintext");
}
