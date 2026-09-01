use std::fmt;
use std::io::{Error, ErrorKind};

use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{Decapsulate, FromSeed, Seed};
use zeroize::Zeroize;

use crate::reality::key_share::{
    MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN, MLKEM768_SHARED_SECRET_LEN,
};

/// ML-KEM-768 shared secret output (32 bytes).
pub struct MlKem768SharedSecret([u8; MLKEM768_SHARED_SECRET_LEN]);

impl MlKem768SharedSecret {
    pub fn as_bytes(&self) -> &[u8; MLKEM768_SHARED_SECRET_LEN] {
        &self.0
    }
}

impl Drop for MlKem768SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for MlKem768SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<mlkem768 shared secret>")
    }
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}

/// Decapsulate an ML-KEM-768 ciphertext using a 64-byte decapsulation key seed (upstream config form).
pub fn decapsulate_mlkem768(
    decapsulation_key_seed: &[u8; 64],
    ciphertext: &[u8],
) -> Result<MlKem768SharedSecret, Error> {
    if ciphertext.len() != MLKEM768_CIPHERTEXT_LEN {
        return Err(invalid_input(format!(
            "ML-KEM-768 ciphertext must be {} bytes, got {}",
            MLKEM768_CIPHERTEXT_LEN,
            ciphertext.len()
        )));
    }

    let seed = Seed::from(*decapsulation_key_seed);
    let (decapsulation_key, _) = MlKem768::from_seed(&seed);
    let shared_secret = decapsulation_key
        .decapsulate_slice(ciphertext)
        .map_err(|_| invalid_data("ML-KEM-768 decapsulation failed"))?;

    let shared_secret = shared_secret.as_slice().try_into().map_err(|_| {
        invalid_data(format!(
            "ML-KEM-768 shared secret must be {MLKEM768_SHARED_SECRET_LEN} bytes"
        ))
    })?;

    Ok(MlKem768SharedSecret(shared_secret))
}

/// Encapsulate to a peer ML-KEM-768 encapsulation key (1184 bytes).
pub fn encapsulate_mlkem768(
    encapsulation_key: &[u8; MLKEM768_ENCAPSULATION_KEY_LEN],
) -> Result<([u8; MLKEM768_CIPHERTEXT_LEN], MlKem768SharedSecret), Error> {
    use ml_kem::ml_kem_768::EncapsulationKey;
    use ml_kem::{Encapsulate, TryKeyInit};

    let ek = EncapsulationKey::new_from_slice(encapsulation_key)
        .map_err(|_| invalid_input("invalid ML-KEM-768 encapsulation key"))?;
    let (ciphertext, shared_secret) = ek.encapsulate();
    let ciphertext = ciphertext.as_slice().try_into().map_err(|_| {
        invalid_data(format!(
            "ML-KEM-768 ciphertext must be {MLKEM768_CIPHERTEXT_LEN} bytes"
        ))
    })?;
    let shared_secret = shared_secret.as_slice().try_into().map_err(|_| {
        invalid_data(format!(
            "ML-KEM-768 shared secret must be {MLKEM768_SHARED_SECRET_LEN} bytes"
        ))
    })?;
    Ok((ciphertext, MlKem768SharedSecret(shared_secret)))
}

/// Test helper: encapsulate against the public key derived from a decap seed.
#[cfg(test)]
pub(crate) fn encapsulate_mlkem768_with_seed(
    decapsulation_key_seed: &[u8; 64],
) -> Result<([u8; MLKEM768_CIPHERTEXT_LEN], MlKem768SharedSecret), Error> {
    use ml_kem::Encapsulate;

    let seed = Seed::from(*decapsulation_key_seed);
    let (_, encapsulation_key) = MlKem768::from_seed(&seed);
    let (ciphertext, shared_secret) = encapsulation_key.encapsulate();
    let ciphertext = ciphertext.as_slice().try_into().map_err(|_| {
        invalid_data(format!(
            "ML-KEM-768 ciphertext must be {MLKEM768_CIPHERTEXT_LEN} bytes"
        ))
    })?;
    let shared_secret = shared_secret.as_slice().try_into().map_err(|_| {
        invalid_data(format!(
            "ML-KEM-768 shared secret must be {MLKEM768_SHARED_SECRET_LEN} bytes"
        ))
    })?;
    Ok((ciphertext, MlKem768SharedSecret(shared_secret)))
}
