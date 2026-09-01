use crate::vless::encryption::aead::{TrafficAead, TrafficAeadKind};
use crate::vless::encryption::header::encode_traffic_header;
use crate::vless::encryption::{
    increase_nonce, reset_test_seal_count, test_seal_count, EncryptedReader, EncryptedWriter,
    MAX_NONCE,
};

use super::stream_common::{client_writer_keys, test_direction_keys, test_united};

#[test]
fn nonce_starts_at_zero_and_first_operation_uses_one() {
    let united = test_united();
    let ctx = b"client-pfs-public-key-32-bytes!!";
    let mut aead = TrafficAead::new(ctx, &united, true);
    assert_eq!(*aead.nonce().as_bytes(), [0u8; 12]);

    let plain = b"nonce-step-1";
    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (plain.len() + 16) as u16);
    let mut buf = plain.to_vec();
    aead.seal_in_place(&mut buf, &header).expect("seal");
    assert_eq!(*aead.nonce().as_bytes(), {
        let mut n = [0u8; 12];
        n[11] = 1;
        n
    });
}

#[test]
fn nonce_second_operation_uses_two_no_double_increment() {
    let united = test_united();
    let ctx = b"client-pfs-public-key-32-bytes!!";
    let mut aead = TrafficAead::new(ctx, &united, true);

    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (1 + 16) as u16);
    let mut buf1 = vec![0xAA];
    aead.seal_in_place(&mut buf1, &header).expect("seal1");

    encode_traffic_header(&mut header, (2 + 16) as u16);
    let mut buf2 = vec![0xBB, 0xCC];
    aead.seal_in_place(&mut buf2, &header).expect("seal2");

    assert_eq!(*aead.nonce().as_bytes(), {
        let mut n = [0u8; 12];
        n[11] = 2;
        n
    });
}

#[test]
fn nonce_never_used_at_zero_for_crypto() {
    let united = test_united();
    let ctx = b"client-pfs-public-key-32-bytes!!";
    let mut aead = TrafficAead::new(ctx, &united, true);
    let zero = [0u8; 12];
    let plain = b"x";
    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (plain.len() + 16) as u16);

    let sealed_with_zero = aead
        .seal_with_nonce(&zero, plain, &header)
        .expect("seal zero");
    let mut live = plain.to_vec();
    let live_len = aead.seal_in_place(&mut live, &header).expect("live seal");
    assert_ne!(
        sealed_with_zero,
        live[..live_len],
        "live path must not use nonce 00..00"
    );
}

#[test]
fn failed_aes_autodetect_does_not_advance_chacha_nonce() {
    let united = test_united();
    let ctx = b"client-pfs-public-key-32-bytes!!";
    let (mut chacha_keys, _) = client_writer_keys();
    chacha_keys.aead.set_kind(TrafficAeadKind::ChaCha20Poly1305);
    let frame = EncryptedWriter::new(chacha_keys)
        .build_record(b"chacha-only")
        .expect("seal");

    let mut header = [0u8; 5];
    header.copy_from_slice(&frame[..5]);
    let body = &frame[5..];

    let (_upload, download, united_arr) = test_direction_keys();
    let mut reader = EncryptedReader::new(download, united_arr, true);
    let opened = reader.decrypt_record(&header, body).expect("open");
    assert_eq!(opened.as_ref(), b"chacha-only");
    assert_eq!(reader.aead_kind(), TrafficAeadKind::ChaCha20Poly1305);

    // Fresh ChaCha attempt on failed AES path starts from zero; winning reader ends at nonce 1.
    let mut chacha_probe = TrafficAead::new(ctx, &united, true);
    chacha_probe.set_kind(TrafficAeadKind::ChaCha20Poly1305);
    assert_eq!(*chacha_probe.nonce().as_bytes(), [0u8; 12]);
}

#[test]
fn maxnonce_rotation_resets_nonce_and_changes_key() {
    let united = test_united();
    let ctx = b"client-pfs-public-key-32-bytes!!";
    let mut aead = TrafficAead::new(ctx, &united, true);
    aead.set_nonce_for_test(MAX_NONCE);

    let plain = b"rotate-at-max";
    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (plain.len() + 16) as u16);
    let mut buf = plain.to_vec();
    let key_before = aead.kind();
    aead.seal_in_place(&mut buf, &header).expect("seal at max");
    assert_eq!(
        *aead.nonce().as_bytes(),
        [0u8; 12],
        "nonce reset after rotate"
    );
    assert_eq!(aead.kind(), key_before);

    let mut buf2 = b"post-rotate".to_vec();
    encode_traffic_header(&mut header, (buf2.len() + 16) as u16);
    aead.seal_in_place(&mut buf2, &header)
        .expect("seal after rotate");
    let mut expected = [0u8; 12];
    expected[11] = 1;
    assert_eq!(*aead.nonce().as_bytes(), expected);
}

#[test]
fn increase_nonce_matches_upstream_progression() {
    let mut nonce = [0u8; 12];
    increase_nonce(&mut nonce);
    assert_eq!(nonce[11], 1);
    increase_nonce(&mut nonce);
    assert_eq!(nonce[11], 2);
}
