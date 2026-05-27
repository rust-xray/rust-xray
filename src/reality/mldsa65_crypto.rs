#![cfg(feature = "reality-mldsa65-crypto")]

use ml_dsa::{Keypair, MlDsa65, SigningKey};

pub struct Mldsa65DerivedKey {
    pub verify_key_bytes: Vec<u8>,
    pub signing_key_bytes: Vec<u8>,
}

pub fn derive_mldsa65_key_from_seed_for_test(
    seed: &crate::reality::Mldsa65Seed,
) -> std::io::Result<Mldsa65DerivedKey> {
    let seed_bytes = ml_dsa::B32::from(*seed.as_bytes());
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_bytes);
    let verifying_key = signing_key.verifying_key();
    let verify_key = verifying_key.encode();
    #[allow(deprecated)]
    let expanded_signing_key = signing_key.expanded_key().to_expanded();

    Ok(Mldsa65DerivedKey {
        verify_key_bytes: verify_key.as_slice().to_vec(),
        signing_key_bytes: expanded_signing_key.as_slice().to_vec(),
    })
}
