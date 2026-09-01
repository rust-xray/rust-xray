use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
use crate::vless::encryption::hybrid::PFS_KEY_LEN;
use crate::vless::encryption::{
    compose_pfs_key, compose_united_key, ctr_xor, decapsulate_mlkem768, derive_blake3_key,
    derive_ctr_key, encode_traffic_header, increase_nonce, parse_padding_profile, x25519_ecdh,
    x25519_public_key, TrafficAead, TrafficAeadKind, X25519PublicKey, X25519SecretKey,
};

// Source: Go reference program against crypto/mlkem + lukechampine.com/blake3 (Xray-core 5e245b08).
const GO_X25519_PRIV: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const GO_X25519_PEER_PUB: [u8; 32] = [
    0xf2, 0xa1, 0x1d, 0x3c, 0xe3, 0x58, 0x88, 0x0f, 0xa4, 0xcd, 0x4e, 0x72, 0xe6, 0xbb, 0x6c, 0xb3,
    0x0b, 0x24, 0xfe, 0xf3, 0xde, 0x5d, 0xe0, 0xd4, 0x2d, 0xf2, 0xc2, 0xc5, 0xb9, 0x19, 0x7a, 0x5b,
];
const GO_X25519_PUB: &str = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
const GO_X25519_SHARED: &str = "cdba91c89ed66c7088630d7de3ac0aa82bc5d097134c9719fd494d15aba4a106";
// Go crypto/mlkem decapsulation key seed 0..63 (upstream reference program).
const GO_MLKEM768_EK_CTX32: &str =
    "298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672c";
const GO_MLKEM768_SS: &str = "54c7325d5f713eb1e6c6f243a02455c5a613e02e023cfdf1d2ac392ab5fbddb5";
const GO_BLAKE3_KDF: &str = "d86eb5fdac65d71b20de7f03e5294a3e04b0c27bb608c0b2ef4a28ebd90d7c8e";
const GO_BLAKE3_CTR: &str = "4dd114c0b752f7737f21b420c8e97088546fabc3cefb6f6607b8f25fc4731c13";
const GO_NONCE_AFTER_INC: &str = "0000000000000000000000ff";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex<const N: usize>(value: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (idx, chunk) in value.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(chunk).expect("utf8"), 16).expect("hex");
        out[idx] = byte;
    }
    out
}

#[test]
fn x25519_vectors_match_go() {
    let secret = X25519SecretKey::from_bytes(GO_X25519_PRIV);
    let public = x25519_public_key(&secret);
    assert_eq!(hex(public.as_bytes()), GO_X25519_PUB);

    let peer = X25519PublicKey::from_bytes(GO_X25519_PEER_PUB).expect("valid peer key");
    let shared = x25519_ecdh(&secret, &peer).expect("ecdh");
    assert_eq!(hex(&shared), GO_X25519_SHARED);
}

#[test]
fn x25519_rejects_high_bit_public_key() {
    let mut invalid = GO_X25519_PEER_PUB;
    invalid[31] = 0xff;
    assert!(X25519PublicKey::from_bytes(invalid).is_err());
}

#[test]
fn mlkem_decapsulation_roundtrip() {
    let seed = {
        let mut arr = [0u8; 64];
        for (idx, byte) in arr.iter_mut().enumerate() {
            *byte = idx as u8;
        }
        arr
    };
    let (ciphertext, expected) =
        crate::vless::encryption::encapsulate_mlkem768_with_seed(&seed).expect("enc");
    let decapped = decapsulate_mlkem768(&seed, &ciphertext).expect("decap");
    assert_eq!(decapped.as_bytes(), expected.as_bytes());
}

#[test]
fn hybrid_secret_ordering() {
    let mlkem = [0x11u8; MLKEM768_SHARED_SECRET_LEN];
    let x25519 = [0x22u8; 32];
    let pfs = compose_pfs_key(&mlkem, &x25519);
    assert_eq!(pfs.as_bytes()[0], 0x11);
    assert_eq!(pfs.as_bytes()[MLKEM768_SHARED_SECRET_LEN], 0x22);
    assert_ne!(pfs.as_bytes()[0], 0x22);

    let nfs = [0x33u8; 32];
    let united = compose_united_key(&pfs, &nfs);
    assert_eq!(united.as_bytes()[PFS_KEY_LEN - 1], 0x22);
    assert_eq!(united.as_bytes()[PFS_KEY_LEN], 0x33);
}

#[test]
fn blake3_kdf_matches_go() {
    let mlkem_ss = from_hex::<32>(GO_MLKEM768_SS);
    let x25519_ss = from_hex::<32>(GO_X25519_SHARED);
    let united = [mlkem_ss.as_slice(), x25519_ss.as_slice()].concat();
    let ctx = from_hex::<32>(GO_MLKEM768_EK_CTX32);
    let mut key = [0u8; 32];
    derive_blake3_key(&mut key, &ctx, &united);
    assert_eq!(hex(&key), GO_BLAKE3_KDF);

    let ctr = derive_ctr_key(&united);
    assert_eq!(hex(&ctr), GO_BLAKE3_CTR);
}

#[test]
fn nonce_increment_matches_go() {
    let mut nonce = [0u8; 12];
    nonce[11] = 0xfe;
    increase_nonce(&mut nonce);
    assert_eq!(hex(&nonce), GO_NONCE_AFTER_INC);
}

#[test]
fn aead_roundtrip_and_tamper_detection() {
    let united = [0x01u8; 96];
    let ctx = b"ctx-label";
    let plaintext = b"hello-vless-encryption";
    let aad = b"header-prefix";

    let mut writer = TrafficAead::new(ctx, &united, true);
    let ciphertext = writer.seal(plaintext, aad).expect("seal");
    let mut reader = TrafficAead::new(ctx, &united, true);
    let opened = reader.open(&ciphertext, aad).expect("open");
    assert_eq!(opened, plaintext);

    let mut tampered = ciphertext.clone();
    tampered[3] ^= 0x01;
    assert!(reader.open(&tampered, aad).is_err());
}

#[test]
fn aead_auto_kind_fallback() {
    let united = [0x02u8; 96];
    let ctx = b"ctx2";
    let plaintext = b"payload";
    let aad = b"aad";

    let mut aes = TrafficAead::new(ctx, &united, false);
    aes.set_kind(TrafficAeadKind::ChaCha20Poly1305);
    let ciphertext = aes.seal(plaintext, aad).expect("seal chacha");

    let (opened, kind) =
        TrafficAead::open_auto_kind(ctx, &united, true, &ciphertext, aad).expect("auto");
    assert_eq!(opened, plaintext);
    assert_eq!(kind, TrafficAeadKind::ChaCha20Poly1305);
}

#[test]
fn traffic_header_encode_decode() {
    let mut header = [0u8; 5];
    encode_traffic_header(&mut header, 42);
    assert_eq!(header, [23, 3, 3, 0, 42]);
    assert_eq!(
        crate::vless::encryption::decode_traffic_header(&header).expect("decode"),
        42
    );
}

#[test]
fn ctr_xor_is_deterministic() {
    let united = [0x03u8; 96];
    let iv = [0x04u8; 16];
    let mut left = vec![0u8; 32];
    let mut right = left.clone();
    ctr_xor(&united, &iv, &mut left);
    ctr_xor(&united, &iv, &mut right);
    assert_eq!(left, right);
    assert_ne!(left, vec![0u8; 32]);
}

#[test]
fn padding_profile_default_generation() {
    let profile = parse_padding_profile("").expect("empty profile");
    let (_total, lens, gaps) = crate::vless::encryption::create_padding_lengths(
        &profile,
        &mut crate::vless::encryption::SeededRng::new(1),
    );
    assert!(!lens.is_empty());
    assert_eq!(gaps.len(), 1);
}
