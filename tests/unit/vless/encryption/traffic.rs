use crate::vless::encryption::aead::{TrafficAead, TrafficAeadKind};
use crate::vless::encryption::handshake::TrafficDirectionKeys;
use crate::vless::encryption::header::encode_traffic_header;
use crate::vless::encryption::{EncryptedReader, EncryptedWriter};

fn test_keys() -> (TrafficDirectionKeys, TrafficDirectionKeys, [u8; 96]) {
    let united = [0x5au8; 96];
    // Server upload = client download (server PFS public context).
    let server_pfs_public = b"server-pfs-public-key-32-bytes!!";
    // Server download = client upload (client PFS public context).
    let client_pfs_public = b"client-pfs-public-key-32-bytes!!";
    let upload = TrafficDirectionKeys {
        aead: TrafficAead::new(server_pfs_public, &united, true),
        context_label: server_pfs_public.to_vec(),
    };
    let download = TrafficDirectionKeys {
        aead: TrafficAead::new(client_pfs_public, &united, true),
        context_label: client_pfs_public.to_vec(),
    };
    (upload, download, united)
}

fn build_frame(writer: &mut EncryptedWriter, plaintext: &[u8]) -> Vec<u8> {
    writer.build_record(plaintext).expect("seal").to_vec()
}

#[test]
fn traffic_roundtrip_single_record() {
    let (_upload, download, united) = test_keys();
    let plaintext = b"hello-encrypted-vless-traffic";
    // Client upload uses client PFS public context; server reads with download_keys.
    let mut writer = EncryptedWriter::new(TrafficDirectionKeys {
        aead: TrafficAead::new(b"client-pfs-public-key-32-bytes!!", &united, true),
        context_label: b"client-pfs-public-key-32-bytes!!".to_vec(),
    });
    let frame = build_frame(&mut writer, plaintext);

    let mut reader = EncryptedReader::new(download, united, true);
    let mut header = [0u8; 5];
    header.copy_from_slice(&frame[..5]);
    let opened = reader.decrypt_record(&header, &frame[5..]).expect("open");
    assert_eq!(opened.as_ref(), plaintext);
}

#[test]
fn reversed_direction_fails() {
    let (upload, download, united) = test_keys();
    let mut writer = EncryptedWriter::new(TrafficDirectionKeys {
        aead: TrafficAead::new(b"client-pfs-public-key-32-bytes!!", &united, true),
        context_label: b"client-pfs-public-key-32-bytes!!".to_vec(),
    });
    let frame = build_frame(&mut writer, b"secret");

    // Server upload context cannot decrypt client-upload records.
    let mut wrong_reader = EncryptedReader::new(upload, united, true);
    let mut header = [0u8; 5];
    header.copy_from_slice(&frame[..5]);
    assert!(wrong_reader.decrypt_record(&header, &frame[5..]).is_err());

    let mut reader = EncryptedReader::new(download, united, true);
    assert!(reader.decrypt_record(&header, &frame[5..]).is_ok());
}

#[test]
fn upstream_traffic_golden_aes_seal() {
    let united = {
        let mut arr = [0u8; 96];
        arr[0] = 0x01;
        arr[32] = 0x02;
        arr[64] = 0x03;
        arr
    };
    let ctx = b"golden-traffic-context-1234567890";
    let plaintext = b"vless-traffic-plaintext";
    let mut aead = TrafficAead::new(ctx, &united, true);
    assert_eq!(aead.kind(), TrafficAeadKind::Aes256Gcm);
    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, (plaintext.len() + 16) as u16);
    let mut buffer = plaintext.to_vec();
    let sealed = aead.seal_in_place(&mut buffer, &header).expect("seal");
    assert_eq!(sealed, plaintext.len() + 16);

    let mut reader = TrafficAead::new(ctx, &united, true);
    reader.set_kind(TrafficAeadKind::Aes256Gcm);
    let mut open_buf = buffer.clone();
    let opened = reader
        .open_in_place(&mut open_buf, plaintext.len(), &header)
        .expect("open");
    assert_eq!(&open_buf[..opened], plaintext);
}

#[test]
fn max_plaintext_record_size_is_8192() {
    use crate::vless::encryption::stream::MAX_TRAFFIC_PLAINTEXT_PER_RECORD;
    assert_eq!(MAX_TRAFFIC_PLAINTEXT_PER_RECORD, 8192);
}

#[test]
fn nfs_smoke_fixture_key_tokens() {
    use crate::vless::encryption::{x25519_public_key, X25519SecretKey};
    use base64::Engine;
    let sk = core::array::from_fn(|i| (i + 1) as u8);
    let pk = x25519_public_key(&X25519SecretKey::from_bytes(sk));
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // Committed live-smoke fixture tokens (secret 1..=32).
    assert_eq!(
        enc.encode(sk),
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
    );
    assert_eq!(
        enc.encode(pk.as_bytes()),
        "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw"
    );
}
