//! Dev tooling helpers for REALITY captured ClientHello fixtures.
//!
//! Does not expose auth keys or other secret material.

use std::io::{Error, ErrorKind, Write};
use std::path::Path;

use crate::codec::{Codec, Reader};
use crate::protocol::structs::ClientHelloPayload;
use crate::tls::parse_client_hello_record_bytes;

use super::auth::derive_reality_auth_key;
use super::session::{open_reality_session_id, short_id_prefix_len, RealitySessionOpenResult};
use super::sni::extract_sni_hostname;

pub const EXPECTED_SNI_FILE: &str = "expected_sni.txt";
pub const EXPECTED_SHORT_ID_FILE: &str = "expected_short_id.hex";
pub const EXPECTED_CLIENT_VERSION_FILE: &str = "expected_client_version.txt";
pub const EXPECTED_UNIX_TIME_FILE: &str = "expected_unix_time.txt";

const EXPECTED_METADATA_FILES: &[&str] = &[
    EXPECTED_SNI_FILE,
    EXPECTED_SHORT_ID_FILE,
    EXPECTED_CLIENT_VERSION_FILE,
    EXPECTED_UNIX_TIME_FILE,
];

/// Metadata written to REALITY fixture `expected_*` files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityFixtureExpectedMetadata {
    pub sni: String,
    pub client_version: String,
    pub unix_time: u32,
    pub short_id_hex: String,
}

/// Result of decoding a REALITY fixture ClientHello through AEAD open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RealityFixtureSessionResult {
    Opened {
        sni: Option<String>,
        client_version: String,
        unix_time: u32,
        short_id_hex: String,
    },
    AuthFailed,
}

/// Formats a four-byte REALITY client version as dotted decimal (`1.8.0.0`).
pub fn format_reality_client_version(version: [u8; 4]) -> String {
    format!(
        "{}.{}.{}.{}",
        version[0], version[1], version[2], version[3]
    )
}

/// Formats the non-zero prefix of a REALITY shortId as lowercase hex.
pub fn format_reality_short_id_hex(short_id: &[u8; 8]) -> String {
    let prefix_len = short_id_prefix_len(short_id);
    short_id[..prefix_len]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Parses a captured ClientHello TLS record and attempts REALITY AEAD session_id open.
pub fn decode_reality_fixture_client_hello(
    client_hello_record: &[u8],
    server_private_key_b64: &str,
) -> std::io::Result<RealityFixtureSessionResult> {
    let record = parse_client_hello_record_bytes(client_hello_record)?;

    let mut rd = Reader::init(&record.handshake_payload);
    let hello = ClientHelloPayload::read(&mut rd).map_err(|err| {
        Error::new(
            ErrorKind::InvalidData,
            format!("ClientHello parse failed: {err:?}"),
        )
    })?;

    let Some(auth) = derive_reality_auth_key(&hello, server_private_key_b64)? else {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "ClientHello missing X25519 key_share for REALITY",
        ));
    };

    match open_reality_session_id(&hello, &record.handshake_message, &auth.auth_key)? {
        RealitySessionOpenResult::Opened(client) => Ok(RealityFixtureSessionResult::Opened {
            sni: extract_sni_hostname(&hello),
            client_version: format_reality_client_version(client.client_version),
            unix_time: client.unix_time,
            short_id_hex: format_reality_short_id_hex(&client.short_id),
        }),
        RealitySessionOpenResult::AuthFailed => Ok(RealityFixtureSessionResult::AuthFailed),
    }
}

/// Builds expected fixture metadata from a successful AEAD open result.
pub fn reality_fixture_expected_metadata(
    result: &RealityFixtureSessionResult,
) -> std::io::Result<RealityFixtureExpectedMetadata> {
    match result {
        RealityFixtureSessionResult::Opened {
            sni,
            client_version,
            unix_time,
            short_id_hex,
        } => {
            let sni = sni.clone().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "REALITY fixture decode missing SNI; expected_sni.txt cannot be written",
                )
            })?;
            Ok(RealityFixtureExpectedMetadata {
                sni,
                client_version: client_version.clone(),
                unix_time: *unix_time,
                short_id_hex: short_id_hex.clone(),
            })
        }
        RealityFixtureSessionResult::AuthFailed => Err(Error::new(
            ErrorKind::InvalidInput,
            "REALITY fixture AEAD auth failed; expected metadata cannot be written",
        )),
    }
}

/// Writes `expected_*` metadata files into a fixture directory.
pub fn write_reality_fixture_expected_files(
    fixture_dir: &Path,
    metadata: &RealityFixtureExpectedMetadata,
    force: bool,
) -> std::io::Result<()> {
    if !fixture_dir.is_dir() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("fixture directory not found: {}", fixture_dir.display()),
        ));
    }

    for file_name in EXPECTED_METADATA_FILES {
        let path = fixture_dir.join(file_name);
        if path.exists() && !force {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "fixture expected file already exists: {}; pass --force to overwrite",
                    path.display()
                ),
            ));
        }
    }

    write_expected_file(
        &fixture_dir.join(EXPECTED_SNI_FILE),
        format!("{}\n", metadata.sni),
    )?;
    write_expected_file(
        &fixture_dir.join(EXPECTED_SHORT_ID_FILE),
        format!("{}\n", metadata.short_id_hex),
    )?;
    write_expected_file(
        &fixture_dir.join(EXPECTED_CLIENT_VERSION_FILE),
        format!("{}\n", metadata.client_version),
    )?;
    write_expected_file(
        &fixture_dir.join(EXPECTED_UNIX_TIME_FILE),
        format!("{}\n", metadata.unix_time),
    )?;

    Ok(())
}

fn write_expected_file(path: &Path, contents: String) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/reality/fixture.rs"]
mod tests;
