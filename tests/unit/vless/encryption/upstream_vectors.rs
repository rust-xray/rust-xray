use crate::reality::key_share::MLKEM768_CIPHERTEXT_LEN;
use crate::vless::encryption::{
    decapsulate_mlkem768, x25519_ecdh, X25519PublicKey, X25519SecretKey,
};

// Source: Go crypto/mlkem + crypto/ecdh reference (Xray-core 5e245b08).
const GO_MLKEM_SEED: [u8; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
];
const GO_MLKEM_CT: &str = "7d0f453c6bfdba6f9c34bc430d7a0495784ee065f30311056c4921e9e1fc8652c636451d57ab9c20bd3db91e71d0c61dbe3f7a0f494bfb83705040d068237d74425841382d27b756b47d397205e1d77298e9a1b42183cb90a3a4b1f11e163c129123b5a5b70bf9ed3183c9bb320910511a02393381e9512c6870edf0885d42c05db0ba6bbf82ee12638ed589189c0cae2cd17ab0f9baec7d7695f498ad71165187f10d7ba71c532417cdbe3710746a5da9a2f34d3865746ff69bc5212c78b9cd63879db3c395c525d619b1a4c8cfa13e897744372a27a53ded45bedc3ccbd95a794719625405f061fa318b757436a95767d0ad7d14e521b60fd8c9b0c91a6a5586942c6dae4bb521a8372c7d101b806860021a04ba6b8e0da18833c789c23470b76cb72043e1debf592c460718be980fb4d1f0b8b208599c126a76eecaf8b309823b0a0c71a4e220811e9bbdb18b61c8364312ec027ceb7f08eeb5138ff7cdac7fb60a00d6189d309b6698e0b98369053862796a38078e85ba86624f5f002bf336a47b042f7c962b31e3a9150ce7cd2c97a4c238386660e887ee20bc613c8268dc7c2b0dd23fd58493e63313412dba0b4a60422ff6d5e86a31eddbcab0d00a98b2dbbd04400590daaad41cad7bef664b97ad71f3f2da957069fcdd54e55b55c57add47d716f0e519d1191e6bd941152b301978c245f9daace030ffbc56a60af4fd0290d6c33cc30a08e1c0b4fe5856e74d488032491a81a3da742c6389fcda0e66cd363b8acd10427429801713e93e785e301b6c470cd0fc54a39516d61af3ef5273a1fdedf506a66b3b0478bb55abdad08732f7f97d2018b0764c5f8819710b3710f13c7df139ecaed163280acccca6f0e0c3b8053198d17645b7ceade53c727dc1013483d2ff7d8e986d9b6cba1242fcd7896b212f73f57b37ab5c94b397ce42526fd3ad521a357b40d30ac29b706b28f735a79babe0f1740228b47e9dde1ed866c9f08e2d37e3e482ca315dc29990c3cd1920cf962a8bf75d954491c4fd61c60ee1a08f45d475375c59b35bdc27c017a0fa23c5b258c6d44913974f0fd6c921f2d473f7fc4feeeb0c8f1a1fa9d0579038b716a9c39336aeab7f0a846d25a5101b795bb068f94c9f22ff2dd2933ab9290f0a8d8857ec0f61fdf3e1c0ab709de3374dc7df807e2fc6430ff8dbe3fe84b9200189c55208926a9a8cdf300470a0b95f2b6d44f873004a3ffd4741b1c837ee80572b6fdc6d3b3f53027113f378f7066bc5db3e96dd78c60aa32041982d2b1a59a20f87c872a8c45e6339801a0c56cc1663c113e4f3ea1fb4aeda4ad73880bec19d3e517c66b28f2cd1f4921a980f571d0dfc754dfa616c737b218cafce30b8435d6268c24786ed401a24c308215793537effcf75a7ca8a8a4798ec91373ca3da4f26a7664ca31fe13108e9b678c254bc779ec5f1421fced03745b6d68868857ea4257cb42ab4fada6b3b9bc9fa32da0928f1c5ecedae44330e836c8fd385e48f74566427e7a4e886f61b8eb9bdae";
const GO_MLKEM_SS: &str = "4d24b3f1f74874391e385ec0c1de512d5d1e36f26f410763862b2fe9ff7f68d6";
const GO_X25519_SHARED: &str = "cdba91c89ed66c7088630d7de3ac0aa82bc5d097134c9719fd494d15aba4a106";

fn from_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).expect("utf8"), 16).expect("hex")
        })
        .collect()
}

#[test]
fn mlkem_decapsulation_matches_go_crypto_mlkem() {
    let ct = from_hex(GO_MLKEM_CT);
    assert_eq!(ct.len(), MLKEM768_CIPHERTEXT_LEN);
    let ss = decapsulate_mlkem768(&GO_MLKEM_SEED, ct.as_slice()).expect("decap");
    let expected = from_hex(GO_MLKEM_SS);
    assert_eq!(ss.as_bytes(), expected.as_slice());
}

#[test]
fn x25519_shared_secret_matches_go() {
    let priv_bytes = core::array::from_fn(|i| (i + 1) as u8);
    let peer = [
        0xf2, 0xa1, 0x1d, 0x3c, 0xe3, 0x58, 0x88, 0x0f, 0xa4, 0xcd, 0x4e, 0x72, 0xe6, 0xbb, 0x6c,
        0xb3, 0x0b, 0x24, 0xfe, 0xf3, 0xde, 0x5d, 0xe0, 0xd4, 0x2d, 0xf2, 0xc2, 0xc5, 0xb9, 0x19,
        0x7a, 0x5b,
    ];
    let secret = X25519SecretKey::from_bytes(priv_bytes);
    let public = X25519PublicKey::from_bytes(peer).expect("valid peer");
    let shared = x25519_ecdh(&secret, &public).expect("ecdh");
    assert_eq!(hex_encode(shared.as_slice()), GO_X25519_SHARED);
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
