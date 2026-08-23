//! ML-KEM-768 server-side encapsulation primitive (Stage 3).
//!
//! Used by `reality/tls13/key_share.rs` hybrid KEX generation.

use std::fmt;
use std::io::{Error, ErrorKind};

use ml_kem::ml_kem_768::EncapsulationKey;
use ml_kem::{Encapsulate, TryKeyInit};
use zeroize::Zeroize;

use super::key_share::{MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN};

/// ML-KEM-768 encapsulation output for server-side hybrid KEX.
pub(crate) struct MlKem768Encapsulation {
    pub ciphertext: [u8; MLKEM768_CIPHERTEXT_LEN],
    shared_secret: [u8; super::key_share::MLKEM768_SHARED_SECRET_LEN],
}

impl MlKem768Encapsulation {
    pub(crate) fn shared_secret(&self) -> &[u8; super::key_share::MLKEM768_SHARED_SECRET_LEN] {
        &self.shared_secret
    }
}

impl Drop for MlKem768Encapsulation {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl fmt::Debug for MlKem768Encapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768Encapsulation")
            .field("ciphertext", &format!("<{} bytes>", self.ciphertext.len()))
            .field("shared_secret", &"<redacted>")
            .finish()
    }
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, message.into())
}

/// Encapsulates to a peer ML-KEM-768 encapsulation key (1184 bytes).
///
/// Performs FIPS-203 encapsulation-key validation via the `ml-kem` crate.
pub(crate) fn encapsulate_mlkem768(
    encoded_encapsulation_key: &[u8],
) -> std::io::Result<MlKem768Encapsulation> {
    if encoded_encapsulation_key.len() != MLKEM768_ENCAPSULATION_KEY_LEN {
        return Err(invalid_input(format!(
            "ML-KEM-768 encapsulation key must be {} bytes, got {}",
            MLKEM768_ENCAPSULATION_KEY_LEN,
            encoded_encapsulation_key.len()
        )));
    }

    let encapsulation_key = EncapsulationKey::new_from_slice(encoded_encapsulation_key)
        .map_err(|_| invalid_data("invalid ML-KEM-768 encapsulation key"))?;

    let (ciphertext, shared_secret) = encapsulation_key.encapsulate();

    let ciphertext = ciphertext.as_slice().try_into().map_err(|_| {
        invalid_data(format!(
            "ML-KEM-768 ciphertext must be {} bytes",
            MLKEM768_CIPHERTEXT_LEN
        ))
    })?;
    let shared_secret = shared_secret.as_slice().try_into().map_err(|_| {
        invalid_data(format!(
            "ML-KEM-768 shared secret must be {} bytes",
            super::key_share::MLKEM768_SHARED_SECRET_LEN
        ))
    })?;

    Ok(MlKem768Encapsulation {
        ciphertext,
        shared_secret,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/reality/mlkem768.rs"]
mod tests;
