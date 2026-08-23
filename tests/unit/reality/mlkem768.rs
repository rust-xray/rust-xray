use super::encapsulate_mlkem768;
use crate::reality::key_share::{
    MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN, MLKEM768_SHARED_SECRET_LEN,
};

use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{Decapsulate, FromSeed, Kem, KeyExport, Seed};

fn sample_encapsulation_key_bytes() -> [u8; MLKEM768_ENCAPSULATION_KEY_LEN] {
    let (_dk, ek) = MlKem768::generate_keypair();
    ek.to_bytes().into()
}

#[test]
fn encapsulate_mlkem768_roundtrip_with_decapsulation_key() {
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_bytes = ek.to_bytes();

    let result = encapsulate_mlkem768(ek_bytes.as_slice()).expect("valid encapsulation key");

    assert_eq!(result.ciphertext.len(), MLKEM768_CIPHERTEXT_LEN);
    assert_eq!(result.shared_secret().len(), MLKEM768_SHARED_SECRET_LEN);

    let client_secret = dk
        .decapsulate_slice(&result.ciphertext)
        .expect("valid ciphertext");

    assert_eq!(client_secret.as_slice(), result.shared_secret());
}

#[test]
fn encapsulate_mlkem768_deterministic_seed_regression() {
    let seed = Seed::from([0x42u8; 64]);
    let (dk, ek) = MlKem768::from_seed(&seed);
    let ek_bytes = ek.to_bytes();

    let first = encapsulate_mlkem768(ek_bytes.as_slice()).expect("first encapsulation");
    let second = encapsulate_mlkem768(ek_bytes.as_slice()).expect("second encapsulation");

    assert_ne!(first.ciphertext, second.ciphertext);
    assert_ne!(first.shared_secret(), second.shared_secret());

    let dec_first = dk
        .decapsulate_slice(&first.ciphertext)
        .expect("decapsulate first");
    let dec_second = dk
        .decapsulate_slice(&second.ciphertext)
        .expect("decapsulate second");

    assert_eq!(dec_first.as_slice(), first.shared_secret());
    assert_eq!(dec_second.as_slice(), second.shared_secret());
}

#[test]
fn encapsulate_mlkem768_rejects_empty_input() {
    let err = encapsulate_mlkem768(&[]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("1184"));
}

#[test]
fn encapsulate_mlkem768_rejects_len_1183() {
    let err = encapsulate_mlkem768(&vec![0u8; 1183]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn encapsulate_mlkem768_rejects_len_1185() {
    let err = encapsulate_mlkem768(&vec![0u8; 1185]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn encapsulate_mlkem768_rejects_invalid_encapsulation_key() {
    let mut ek_bytes = sample_encapsulation_key_bytes();
    for byte in ek_bytes.iter_mut() {
        *byte ^= 0xff;
    }

    let err = encapsulate_mlkem768(&ek_bytes).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err
        .to_string()
        .contains("invalid ML-KEM-768 encapsulation key"));
}

#[test]
fn mlkem768_encapsulation_debug_redacts_shared_secret() {
    let ek_bytes = sample_encapsulation_key_bytes();
    let result = encapsulate_mlkem768(&ek_bytes).expect("valid encapsulation key");
    let debug = format!("{result:?}");

    assert!(debug.contains("ciphertext"));
    assert!(debug.contains("shared_secret"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&format!("{:?}", result.shared_secret()[0])));
}
