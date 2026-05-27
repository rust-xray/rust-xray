#![cfg(feature = "reality-mldsa65-crypto")]

use ml_dsa::{Keypair, MlDsa65, Signature, SignatureEncoding, Signer, SigningKey, Verifier};

pub struct RealityMldsa65CertPatchInput<'a> {
    pub cert_der: &'a mut [u8],
    pub auth_key: &'a [u8; 32],
    pub ed25519_public_key: &'a [u8; 32],
    pub client_hello_original: &'a [u8],
    pub server_hello_original: &'a [u8],
    pub seed: &'a crate::reality::Mldsa65Seed,
}

pub struct Mldsa65DerivedKey {
    pub verify_key_bytes: Vec<u8>,
    pub signing_key_bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct Mldsa65Signature(Vec<u8>);

impl Mldsa65Signature {
    pub fn from_bytes_for_test(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Mldsa65Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mldsa65Signature(<redacted>)")
    }
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

pub fn sign_reality_mldsa65_message_for_test(
    seed: &crate::reality::Mldsa65Seed,
    message: &[u8],
) -> std::io::Result<Mldsa65Signature> {
    let seed_bytes = ml_dsa::B32::from(*seed.as_bytes());
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_bytes);
    let signature: Signature<MlDsa65> = signing_key.try_sign(message).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "ml-dsa crate failed to sign ML-DSA-65 message from seed",
        )
    })?;

    Ok(Mldsa65Signature(signature.to_bytes().as_slice().to_vec()))
}

pub fn verify_reality_mldsa65_signature_for_test(
    verify_key: &crate::reality::Mldsa65VerifyKey,
    message: &[u8],
    signature: &Mldsa65Signature,
) -> std::io::Result<()> {
    let encoded_verify_key =
        ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(verify_key.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "ml-dsa crate cannot import ML-DSA-65 verify key bytes",
            )
        })?;
    let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded_verify_key);
    let signature = Signature::<MlDsa65>::try_from(signature.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid ML-DSA-65 signature bytes",
        )
    })?;

    verifying_key.verify(message, &signature).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ML-DSA-65 signature verification failed",
        )
    })
}

pub fn patch_reality_certificate_der_with_mldsa65_for_test(
    input: RealityMldsa65CertPatchInput<'_>,
) -> std::io::Result<()> {
    if input.cert_der.len() < 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "REALITY certificate DER too short for Ed25519 signature patch: {} bytes (need >= 64)",
                input.cert_der.len()
            ),
        ));
    }

    let extension_end = crate::reality::MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET
        + crate::reality::MLDSA65_SIGNATURE_LEN;
    if input.cert_der.len() < extension_end {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "REALITY certificate DER too short for ML-DSA-65 extension patch: {} bytes (need >= {extension_end})",
                input.cert_der.len()
            ),
        ));
    }

    crate::reality::patch_reality_certificate_der(
        input.cert_der,
        input.ed25519_public_key,
        input.auth_key,
    )?;

    let message = crate::reality::build_reality_mldsa65_message(
        input.auth_key,
        input.ed25519_public_key,
        input.client_hello_original,
        input.server_hello_original,
    );
    let signature = sign_reality_mldsa65_message_for_test(input.seed, &message)?;
    if signature.as_bytes().len() != crate::reality::MLDSA65_SIGNATURE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "invalid ML-DSA-65 signature length: expected {} bytes, got {}",
                crate::reality::MLDSA65_SIGNATURE_LEN,
                signature.as_bytes().len()
            ),
        ));
    }

    input.cert_der[crate::reality::MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET..extension_end]
        .copy_from_slice(signature.as_bytes());

    Ok(())
}
