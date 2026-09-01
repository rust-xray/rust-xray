/// Blake3 KDF matching upstream `encryption.NewAEAD` / `NewCTR` key derivation.
///
/// Upstream passes arbitrary byte slices as Go `string(ctx)`; mirror that here.
pub fn derive_blake3_key(out: &mut [u8; 32], context: &[u8], key: &[u8]) {
    // SAFETY: Blake3 accepts arbitrary byte sequences as context; Go uses the same
    // opaque-bytes-as-string semantics for AEAD/CTR derivation labels.
    let context_str = unsafe { std::str::from_utf8_unchecked(context) };
    out.copy_from_slice(&blake3::derive_key(context_str, key));
}

/// CTR stream key derivation (`NewCTR` uses context label `"VLESS"`).
pub fn derive_ctr_key(united_key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    derive_blake3_key(&mut out, b"VLESS", united_key);
    out
}
