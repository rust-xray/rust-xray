//! The single place where we generate random material for our own use.

use std::vec;
use std::vec::Vec;

/// A source of cryptographically secure randomness.
pub trait SecureRandom: Send + Sync {
    /// Fill the given buffer with random bytes.
    ///
    /// The bytes must be sourced from a cryptographically secure random number
    /// generator seeded with good quality, secret entropy.
    ///
    /// This is used for all randomness required by rustls, but not necessarily
    /// randomness required by the underlying cryptography library.  For example:
    /// [`SupportedKxGroup::start()`] requires random material to generate
    /// an ephemeral key exchange key, but this is not included in the interface with
    /// rustls: it is assumed that the cryptography library provides for this itself.
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
    }
}

/// Make a [`Vec<u8>`] of the given size containing random material.
pub(crate) fn random_vec(
    secure_random: &dyn SecureRandom,
    len: usize,
) -> Result<Vec<u8>, GetRandomFailed> {
    let mut v = vec![0; len];
    secure_random.fill(&mut v)?;
    Ok(v)
}

/// Return a uniformly random [`u32`].
pub(crate) fn random_u32(secure_random: &dyn SecureRandom) -> Result<u32, GetRandomFailed> {
    let mut buf = [0u8; 4];
    secure_random.fill(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Return a uniformly random [`u16`].
pub(crate) fn random_u16(secure_random: &dyn SecureRandom) -> Result<u16, GetRandomFailed> {
    let mut buf = [0u8; 2];
    secure_random.fill(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Random material generation failed.
#[derive(Debug)]
pub struct GetRandomFailed;
