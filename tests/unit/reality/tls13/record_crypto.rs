use super::*;
use crate::reality::tls13::{
    key_schedule::derive_traffic_key,
    messages::{parse_key_update_handshake, KEY_UPDATE_NOT_REQUESTED},
    tls13_cipher_suite, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
};
use crate::tls::records::{parse_tls_records, TlsRecordContentType, TLS_RECORD_ALERT};

fn sample_handshake_message() -> Vec<u8> {
    vec![0x08, 0x00, 0x00, 0x00, 0x00]
}

fn aes128_keys() -> Tls13TrafficKeys {
    Tls13TrafficKeys {
        key: (0x10..0x20).collect(),
        iv: (0x01..0x0d).collect(),
    }
}

fn aes256_keys() -> Tls13TrafficKeys {
    Tls13TrafficKeys {
        key: (0x20..0x40).collect(),
        iv: (0x01..0x0d).collect(),
    }
}

fn sample_traffic_secret(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn encryptor_with_traffic_secret(seed: u8) -> Tls13RecordEncryptor {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let traffic_secret = sample_traffic_secret(seed);
    let keys = derive_traffic_key(suite, &traffic_secret).expect("traffic keys");
    Tls13RecordEncryptor::with_traffic_secret(suite, keys, traffic_secret).expect("encryptor")
}

fn decryptor_with_traffic_secret(seed: u8) -> Tls13RecordDecryptor {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let traffic_secret = sample_traffic_secret(seed);
    let keys = derive_traffic_key(suite, &traffic_secret).expect("traffic keys");
    Tls13RecordDecryptor::with_traffic_secret(suite, keys, traffic_secret).expect("decryptor")
}

fn client_app_traffic_pair(seed: u8) -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let traffic_secret = sample_traffic_secret(seed);
    let keys = derive_traffic_key(suite, &traffic_secret).expect("traffic keys");
    let encryptor =
        Tls13RecordEncryptor::with_traffic_secret(suite, keys.clone(), traffic_secret.clone())
            .expect("encryptor");
    let decryptor =
        Tls13RecordDecryptor::with_traffic_secret(suite, keys, traffic_secret).expect("decryptor");
    (encryptor, decryptor)
}

#[test]
fn tls13_record_nonce_sequence_zero_equals_iv() {
    let iv = [0x11; TLS13_IV_LEN];
    let nonce = tls13_record_nonce(&iv, 0).expect("valid nonce");
    assert_eq!(nonce, iv);
}

#[test]
fn tls13_record_nonce_known_xor_case() {
    let iv = [0xff; TLS13_IV_LEN];
    let nonce = tls13_record_nonce(&iv, 1).expect("valid nonce");

    let mut expected = [0xff; TLS13_IV_LEN];
    expected[11] = 0xfe;
    assert_eq!(nonce, expected);
}

#[test]
fn tls13_record_nonce_rejects_wrong_iv_length() {
    let err = tls13_record_nonce(&[0u8; 8], 0).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn encrypt_handshake_message_sequence_increments() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let mut encryptor = Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
    let message = sample_handshake_message();

    assert_eq!(encryptor.sequence, 0);
    let first = encryptor
        .encrypt_handshake_message(&message)
        .expect("valid encrypted record");
    assert_eq!(encryptor.sequence, 1);
    let second = encryptor
        .encrypt_handshake_message(&message)
        .expect("valid encrypted record");
    assert_eq!(encryptor.sequence, 2);

    assert_ne!(first, second);
}

#[test]
fn encrypt_handshake_message_record_header_is_application_data() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let mut encryptor = Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
    let record = encryptor
        .encrypt_handshake_message(&sample_handshake_message())
        .expect("valid encrypted record");

    assert_eq!(record[0], TLS_RECORD_APPLICATION_DATA);
    assert_eq!(record[1..3], TLS_LEGACY_VERSION_1_2);
}

#[test]
fn encrypt_handshake_message_record_length_matches_ciphertext() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let mut encryptor = Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
    let record = encryptor
        .encrypt_handshake_message(&sample_handshake_message())
        .expect("valid encrypted record");

    let payload_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    assert_eq!(payload_len, record.len() - 5);
    assert_eq!(
        payload_len,
        sample_handshake_message().len() + 1 + GCM_TAG_LEN
    );
}

#[test]
fn encrypt_handshake_message_aes128_works() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let mut encryptor = Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
    let record = encryptor
        .encrypt_handshake_message(&sample_handshake_message())
        .expect("valid encrypted record");

    let records = parse_tls_records(&record).expect("parsable record");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert!(records[0].payload.len() > GCM_TAG_LEN);
}

#[test]
fn encrypt_handshake_message_aes256_works() {
    let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
    let mut encryptor = Tls13RecordEncryptor::new(suite, aes256_keys()).expect("valid encryptor");
    let record = encryptor
        .encrypt_handshake_message(&sample_handshake_message())
        .expect("valid encrypted record");

    let records = parse_tls_records(&record).expect("parsable record");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert!(records[0].payload.len() > GCM_TAG_LEN);
}

fn chacha20_keys() -> Tls13TrafficKeys {
    Tls13TrafficKeys {
        key: (0x30..0x50).collect(),
        iv: (0x01..0x0d).collect(),
    }
}

#[test]
fn encrypt_handshake_message_chacha20_works() {
    let suite = tls13_cipher_suite(TLS_CHACHA20_POLY1305_SHA256).expect("known suite");
    let mut encryptor = Tls13RecordEncryptor::new(suite, chacha20_keys()).expect("valid encryptor");
    let record = encryptor
        .encrypt_handshake_message(&sample_handshake_message())
        .expect("valid encrypted record");

    let records = parse_tls_records(&record).expect("parsable record");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert!(records[0].payload.len() > GCM_TAG_LEN);
}

#[test]
fn encrypt_application_data_roundtrip_chacha20() {
    let suite = tls13_cipher_suite(TLS_CHACHA20_POLY1305_SHA256).expect("known suite");
    let keys = chacha20_keys();
    let plaintext = b"chacha application payload";

    let mut encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_application_data(plaintext)
        .expect("valid encrypted record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);
    let decrypted = decryptor
        .decrypt_application_data_record(&record)
        .expect("valid decrypted application data");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn chacha20_poly1305_rfc8439_aead_vector() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [0u8; TLS13_IV_LEN];
    let plaintext = [
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0xa2, 0x24, 0x54, 0x58, 0x20, 0x41, 0x6d, 0x65, 0x73,
    ];
    let aad = [
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x62, 0x62, 0x63,
        0x64, 0x65, 0x66, 0x67,
    ];
    let expected_ciphertext = [
        0x54, 0xd9, 0x26, 0x58, 0xc8, 0x95, 0x04, 0xf5, 0x47, 0x39, 0x7c, 0x20, 0xc2, 0x26, 0x3d,
        0x4c, 0x0f, 0xb0, 0x17, 0xc3, 0x03, 0x10, 0xdd, 0x92, 0x5b, 0x89, 0xb2, 0xa2, 0x26, 0x58,
        0xe0,
    ];

    let ciphertext =
        encrypt_chacha20_poly1305(&key, &nonce, &plaintext, &aad).expect("RFC 8439 encrypt");
    assert_eq!(ciphertext, expected_ciphertext);

    let decrypted =
        decrypt_chacha20_poly1305(&key, &nonce, &ciphertext, &aad).expect("RFC 8439 decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chacha20_tls13_application_record_known_vector() {
    let suite = tls13_cipher_suite(TLS_CHACHA20_POLY1305_SHA256).expect("known suite");
    let keys = Tls13TrafficKeys {
        key: (0x30..0x50).collect(),
        iv: (0x01..0x0d).collect(),
    };
    let plaintext = b"known-vector";

    let mut encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_application_data(plaintext)
        .expect("valid encrypted record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);
    let decrypted = decryptor
        .decrypt_application_data_record(&record)
        .expect("valid decrypted application data");
    assert_eq!(decrypted, plaintext);

    let mut reencryptor = Tls13RecordEncryptor::new(
        suite,
        Tls13TrafficKeys {
            key: (0x30..0x50).collect(),
            iv: (0x01..0x0d).collect(),
        },
    )
    .expect("valid encryptor");
    let replay = reencryptor
        .encrypt_application_data(plaintext)
        .expect("deterministic re-encrypt");
    assert_eq!(record_bytes, replay);
}

#[test]
fn encrypt_handshake_message_is_deterministic() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys();
    let message = sample_handshake_message();

    let mut first = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
    let first_record = first
        .encrypt_handshake_message(&message)
        .expect("valid encrypted record");

    let mut second = Tls13RecordEncryptor::new(suite, keys).expect("valid encryptor");
    let second_record = second
        .encrypt_handshake_message(&message)
        .expect("valid encrypted record");

    assert_eq!(first_record, second_record);
}

fn parse_encrypted_application_record(record_bytes: &[u8]) -> crate::tls::TlsRecord {
    let records = parse_tls_records(record_bytes).expect("parsable record");
    assert_eq!(records.len(), 1);
    records.into_iter().next().expect("single record")
}

#[test]
fn encrypt_application_data_roundtrip_aes128() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys();
    let plaintext = b"hello application data";

    let mut encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_application_data(plaintext)
        .expect("valid encrypted record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);
    let decrypted = decryptor
        .decrypt_application_data_record(&record)
        .expect("valid decrypted application data");

    assert_eq!(decrypted, plaintext);
    assert_eq!(encryptor.sequence, 1);
    assert_eq!(decryptor.sequence, 1);
}

#[test]
fn encrypt_application_data_roundtrip_aes256() {
    let suite = tls13_cipher_suite(TLS_AES_256_GCM_SHA384).expect("known suite");
    let keys = aes256_keys();
    let plaintext = b"aes256 application payload";

    let mut encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_application_data(plaintext)
        .expect("valid encrypted record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);
    let decrypted = decryptor
        .decrypt_application_data_record(&record)
        .expect("valid decrypted application data");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_application_data_wrong_key_fails() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let mut encryptor = Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_application_data(b"secret")
        .expect("valid encrypted record");

    let mut wrong_keys = aes128_keys();
    wrong_keys.key[0] ^= 0x01;
    let mut decryptor = Tls13RecordDecryptor::new(suite, wrong_keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);

    let err = decryptor
        .decrypt_application_data_record(&record)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[test]
fn decrypt_application_data_sequence_mismatch_fails() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys();
    let mut encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_application_data(b"sequence test")
        .expect("valid encrypted record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    decryptor.sequence = 1;
    let record = parse_encrypted_application_record(&record_bytes);

    let err = decryptor
        .decrypt_application_data_record(&record)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[test]
fn decrypt_application_data_rejects_non_application_record() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let mut decryptor = Tls13RecordDecryptor::new(suite, aes128_keys()).expect("valid decryptor");
    let record = crate::tls::TlsRecord {
        content_type: TlsRecordContentType::Handshake,
        legacy_version: TLS_LEGACY_VERSION_1_2,
        payload: vec![0x01, 0x02, 0x03],
        raw: vec![
            TLS_RECORD_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x03,
            0x01,
            0x02,
            0x03,
        ],
    };

    let err = decryptor
        .decrypt_application_data_record(&record)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("ApplicationData"));
}

#[test]
fn decrypt_application_data_strips_zero_padding() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys();
    let plaintext = b"padded payload";

    let mut inner_plaintext = Vec::with_capacity(plaintext.len() + 1 + 4);
    inner_plaintext.extend_from_slice(plaintext);
    inner_plaintext.push(TLS_RECORD_APPLICATION_DATA);
    inner_plaintext.extend_from_slice(&[0, 0, 0, 0]);

    let nonce_bytes = tls13_record_nonce(&keys.iv, 0).expect("valid nonce");
    let ciphertext_len =
        u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).expect("valid ciphertext length");
    let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);
    let ciphertext =
        encrypt_aes128_gcm(&keys.key, &nonce_bytes, &inner_plaintext, &aad).expect("encrypt");
    let record_bytes = build_tls_record(
        TLS_RECORD_APPLICATION_DATA,
        TLS_LEGACY_VERSION_1_2,
        &ciphertext,
    )
    .expect("valid record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);
    let decrypted = decryptor
        .decrypt_application_data_record(&record)
        .expect("valid decrypted application data");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_application_data_rejects_handshake_inner_content_type() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys();
    let handshake_message = sample_handshake_message();

    let mut inner_plaintext = handshake_message.clone();
    inner_plaintext.push(TLS_RECORD_HANDSHAKE);

    let nonce_bytes = tls13_record_nonce(&keys.iv, 0).expect("valid nonce");
    let ciphertext_len =
        u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).expect("valid ciphertext length");
    let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);
    let ciphertext =
        encrypt_aes128_gcm(&keys.key, &nonce_bytes, &inner_plaintext, &aad).expect("encrypt");
    let record_bytes = build_tls_record(
        TLS_RECORD_APPLICATION_DATA,
        TLS_LEGACY_VERSION_1_2,
        &ciphertext,
    )
    .expect("valid record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);
    let err = decryptor
        .decrypt_application_data_record(&record)
        .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn decrypt_handshake_record_roundtrip_with_encrypt_handshake_message() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys();
    let handshake_message = sample_handshake_message();

    let mut encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_handshake_message(&handshake_message)
        .expect("valid encrypted record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);
    let decrypted = decryptor
        .decrypt_handshake_record(&record)
        .expect("valid decrypted handshake message");

    assert_eq!(decrypted, handshake_message);
}

#[test]
fn tls13_inner_plaintext_content_type_reads_trailing_content_type() {
    let inner = vec![0x02, 0x28, TLS_RECORD_ALERT];
    assert_eq!(
        tls13_inner_plaintext_content_type(&inner),
        Some(TLS_RECORD_ALERT)
    );
    assert_eq!(tls13_inner_plaintext_body(&inner), Some(vec![0x02, 0x28]));
}

#[test]
fn decrypt_handshake_record_rejects_encrypted_alert_inner_content() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys();

    let mut inner_plaintext = vec![0x02, 0x28];
    inner_plaintext.push(TLS_RECORD_ALERT);

    let nonce_bytes = tls13_record_nonce(&keys.iv, 0).expect("valid nonce");
    let ciphertext_len =
        u16::try_from(inner_plaintext.len() + GCM_TAG_LEN).expect("valid ciphertext length");
    let aad = build_record_aad(TLS_LEGACY_VERSION_1_2, ciphertext_len);
    let ciphertext =
        encrypt_aes128_gcm(&keys.key, &nonce_bytes, &inner_plaintext, &aad).expect("encrypt");
    let record_bytes = build_tls_record(
        TLS_RECORD_APPLICATION_DATA,
        TLS_LEGACY_VERSION_1_2,
        &ciphertext,
    )
    .expect("valid record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    let record = parse_encrypted_application_record(&record_bytes);
    let err = decryptor.decrypt_handshake_record(&record).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err
        .to_string()
        .contains("unexpected inner content type: 21"));
}

#[test]
fn receiving_key_update_resets_sequence() {
    let mut decryptor = decryptor_with_traffic_secret(0xAA);
    let old_keys = decryptor.keys.clone();
    decryptor.sequence = 4;

    decryptor
        .apply_receiving_traffic_key_update()
        .expect("receiving key update");

    assert_eq!(decryptor.sequence, 0);
    assert_ne!(decryptor.keys.key, old_keys.key);
    assert_ne!(decryptor.keys.iv, old_keys.iv);
}

#[test]
fn sending_key_update_resets_sequence() {
    let mut encryptor = encryptor_with_traffic_secret(0xBB);
    let old_keys = encryptor.keys.clone();
    encryptor.sequence = 7;

    encryptor
        .apply_sending_traffic_key_update()
        .expect("sending key update");

    assert_eq!(encryptor.sequence, 0);
    assert_ne!(encryptor.keys.key, old_keys.key);
    assert_ne!(encryptor.keys.iv, old_keys.iv);
}

#[test]
fn key_update_roundtrip_resets_sequence_for_next_appdata() {
    let (mut encryptor, mut decryptor) = client_app_traffic_pair(0xCC);
    let first_plaintext = b"before key update";
    let second_plaintext = b"after key update";

    let first_record = encryptor
        .encrypt_application_data(first_plaintext)
        .expect("first appdata");
    assert_eq!(encryptor.sequence, 1);

    let key_update_record = encryptor
        .encrypt_key_update(KEY_UPDATE_NOT_REQUESTED)
        .expect("key update");
    assert_eq!(encryptor.sequence, 2);
    encryptor
        .apply_sending_traffic_key_update()
        .expect("sending key update");
    assert_eq!(encryptor.sequence, 0);

    let second_record = encryptor
        .encrypt_application_data(second_plaintext)
        .expect("second appdata");
    assert_eq!(encryptor.sequence, 1);

    let first_parsed = parse_encrypted_application_record(&first_record);
    let decrypted_first = decryptor
        .decrypt_application_data_record(&first_parsed)
        .expect("decrypt first appdata");
    assert_eq!(decrypted_first, first_plaintext);
    assert_eq!(decryptor.sequence, 1);

    let key_update_parsed = parse_encrypted_application_record(&key_update_record);
    let key_update_message = decryptor
        .decrypt_handshake_record(&key_update_parsed)
        .expect("decrypt key update");
    assert_eq!(
        parse_key_update_handshake(&key_update_message).expect("parse key update"),
        KEY_UPDATE_NOT_REQUESTED
    );
    assert_eq!(decryptor.sequence, 2);
    decryptor
        .apply_receiving_traffic_key_update()
        .expect("receiving key update");
    assert_eq!(decryptor.sequence, 0);

    let second_parsed = parse_encrypted_application_record(&second_record);
    let decrypted_second = decryptor
        .decrypt_application_data_record(&second_parsed)
        .expect("decrypt second appdata");
    assert_eq!(decrypted_second, second_plaintext);
    assert_eq!(decryptor.sequence, 1);
}

#[test]
fn tls13_inner_plaintext_application_data_without_padding() {
    let inner = vec![0x48, 0x69, TLS_RECORD_APPLICATION_DATA];
    let (body, content_type, padding_len) =
        tls13_inner_plaintext_metadata(&inner).expect("valid inner plaintext");
    assert_eq!(body, b"Hi");
    assert_eq!(content_type, TLS_RECORD_APPLICATION_DATA);
    assert_eq!(padding_len, 0);
}

#[test]
fn tls13_inner_plaintext_application_data_with_zero_padding() {
    let inner = vec![0x48, 0x69, TLS_RECORD_APPLICATION_DATA, 0, 0, 0];
    let (body, content_type, padding_len) =
        tls13_inner_plaintext_metadata(&inner).expect("valid inner plaintext");
    assert_eq!(body, b"Hi");
    assert_eq!(content_type, TLS_RECORD_APPLICATION_DATA);
    assert_eq!(padding_len, 3);
}

#[test]
fn tls13_inner_plaintext_handshake_key_update() {
    let key_update = build_key_update_message(KEY_UPDATE_NOT_REQUESTED).expect("key update");
    let mut inner = key_update.clone();
    inner.push(TLS_RECORD_HANDSHAKE);

    let (body, content_type, padding_len) =
        tls13_inner_plaintext_metadata(&inner).expect("valid inner plaintext");
    assert_eq!(body, key_update);
    assert_eq!(content_type, TLS_RECORD_HANDSHAKE);
    assert_eq!(padding_len, 0);
    assert_eq!(body[0], 0x18);
}

#[test]
fn tls13_inner_plaintext_all_zeros_invalid() {
    let err = tls13_inner_plaintext_metadata(&[0, 0, 0]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("no content type"));
}

#[test]
fn decrypt_sequence_increments_once_on_success() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let keys = aes128_keys();
    let mut encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_application_data(b"sequence-check")
        .expect("valid encrypted record");

    let mut decryptor = Tls13RecordDecryptor::new(suite, keys).expect("valid decryptor");
    assert_eq!(decryptor.sequence, 0);
    let record = parse_encrypted_application_record(&record_bytes);
    decryptor
        .decrypt_application_data_record(&record)
        .expect("valid decrypted application data");
    assert_eq!(decryptor.sequence, 1);
}

#[test]
fn failed_decrypt_does_not_increment_sequence() {
    let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
    let mut encryptor = Tls13RecordEncryptor::new(suite, aes128_keys()).expect("valid encryptor");
    let record_bytes = encryptor
        .encrypt_application_data(b"sequence-check")
        .expect("valid encrypted record");

    let mut wrong_keys = aes128_keys();
    wrong_keys.key[0] ^= 0x01;
    let mut decryptor = Tls13RecordDecryptor::new(suite, wrong_keys).expect("valid decryptor");
    assert_eq!(decryptor.sequence, 0);
    let record = parse_encrypted_application_record(&record_bytes);
    let err = decryptor
        .decrypt_application_data_record(&record)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(decryptor.sequence, 0);
}

#[test]
fn encrypt_server_key_update_response_uses_old_key_then_resets_sequence() {
    let (mut server_encryptor, mut client_decryptor) = client_app_traffic_pair(0xDD);
    let old_keys = server_encryptor.keys.clone();
    server_encryptor.sequence = 3;

    let key_update_response = server_encryptor
        .encrypt_server_key_update_response()
        .expect("server key update response");
    assert_eq!(server_encryptor.sequence, 0);
    assert_ne!(server_encryptor.keys.key, old_keys.key);
    assert_ne!(server_encryptor.keys.iv, old_keys.iv);

    let follow_up = server_encryptor
        .encrypt_application_data(b"server appdata after key update")
        .expect("server appdata after key update");
    assert_eq!(server_encryptor.sequence, 1);

    client_decryptor.sequence = 3;
    let key_update_parsed = parse_encrypted_application_record(&key_update_response);
    let key_update_message = client_decryptor
        .decrypt_handshake_record(&key_update_parsed)
        .expect("decrypt server key update");
    assert_eq!(
        parse_key_update_handshake(&key_update_message).expect("parse key update"),
        KEY_UPDATE_NOT_REQUESTED
    );
    assert_eq!(client_decryptor.sequence, 4);
    client_decryptor
        .apply_receiving_traffic_key_update()
        .expect("receiving key update");
    assert_eq!(client_decryptor.sequence, 0);

    let follow_up_parsed = parse_encrypted_application_record(&follow_up);
    let decrypted = client_decryptor
        .decrypt_application_data_record(&follow_up_parsed)
        .expect("decrypt server appdata after key update");
    assert_eq!(decrypted, b"server appdata after key update");
    assert_eq!(client_decryptor.sequence, 1);
}
