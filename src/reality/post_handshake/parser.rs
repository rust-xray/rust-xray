//! Pure parser for consecutive TLS 1.3 post-handshake ApplicationData record wire lengths.

use std::io::{Error, ErrorKind};

use crate::tls::records::{
    TLS_LEGACY_VERSION_1_2, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_HEADER_LEN,
};

/// RFC 8446 maximum ciphertext fragment (2^14 + 256) for TLS 1.3 records.
const TLS13_MAX_ENCRYPTED_RECORD_PAYLOAD_LEN: usize = 16_384 + 256;
const TLS13_MAX_ENCRYPTED_RECORD_WIRE_LEN: usize =
    TLS_RECORD_HEADER_LEN + TLS13_MAX_ENCRYPTED_RECORD_PAYLOAD_LEN;

/// Error while parsing a post-handshake ApplicationData record prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostHandshakeParseError {
    TruncatedHeader {
        offset: usize,
        available: usize,
    },
    TruncatedPayload {
        offset: usize,
        declared_payload_len: usize,
        available_payload_len: usize,
    },
    WrongContentType {
        offset: usize,
        found: u8,
    },
    WrongLegacyVersion {
        offset: usize,
        found: [u8; 2],
    },
    DeclaredLengthExceedsMaximum {
        offset: usize,
        wire_len: usize,
    },
    TrailingIncompleteRecord {
        parsed_lengths: Vec<usize>,
        trailing_len: usize,
    },
}

impl PostHandshakeParseError {
    pub fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidData
    }
}

impl std::fmt::Display for PostHandshakeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader { offset, available } => {
                write!(
                    f,
                    "TLS post-handshake record header truncated at offset {offset} ({available} bytes available, need {TLS_RECORD_HEADER_LEN})"
                )
            }
            Self::TruncatedPayload {
                offset,
                declared_payload_len,
                available_payload_len,
            } => write!(
                f,
                "TLS post-handshake record payload truncated at offset {offset} (declared {declared_payload_len}, available {available_payload_len})"
            ),
            Self::WrongContentType { offset, found } => write!(
                f,
                "TLS post-handshake parser expected ApplicationData (23) at offset {offset}, found 0x{found:02x}"
            ),
            Self::WrongLegacyVersion { offset, found } => write!(
                f,
                "TLS post-handshake parser expected legacy version 0x0303 at offset {offset}, found 0x{:02x}{:02x}",
                found[0], found[1]
            ),
            Self::DeclaredLengthExceedsMaximum { offset, wire_len } => write!(
                f,
                "TLS post-handshake record declared wire length {wire_len} exceeds protocol maximum at offset {offset}"
            ),
            Self::TrailingIncompleteRecord {
                parsed_lengths,
                trailing_len,
            } => write!(
                f,
                "TLS post-handshake parser stopped with {trailing_len} trailing bytes after {} complete records",
                parsed_lengths.len()
            ),
        }
    }
}

impl std::error::Error for PostHandshakeParseError {}

/// Parses consecutive TLS ApplicationData records (`17 03 03 LL LL`) from the start of `bytes`.
///
/// Returns full on-wire record lengths (`5 + declared_payload_len`) for each complete record.
/// Does not decrypt payloads.
///
/// Stops with an error on the first non-ApplicationData record, invalid version, invalid length,
/// or trailing bytes that do not form a complete record header+payload.
pub fn parse_post_handshake_application_record_lengths(
    bytes: &[u8],
) -> Result<Vec<usize>, PostHandshakeParseError> {
    let mut offset = 0;
    let mut lengths = Vec::new();

    while offset < bytes.len() {
        if bytes.len() - offset < TLS_RECORD_HEADER_LEN {
            if offset == 0 {
                return Err(PostHandshakeParseError::TruncatedHeader {
                    offset,
                    available: bytes.len() - offset,
                });
            }
            return Err(PostHandshakeParseError::TrailingIncompleteRecord {
                parsed_lengths: lengths,
                trailing_len: bytes.len() - offset,
            });
        }

        let header = &bytes[offset..offset + TLS_RECORD_HEADER_LEN];
        if header[0] != TLS_RECORD_APPLICATION_DATA {
            if offset == 0 {
                return Err(PostHandshakeParseError::WrongContentType {
                    offset,
                    found: header[0],
                });
            }
            return Err(PostHandshakeParseError::TrailingIncompleteRecord {
                parsed_lengths: lengths,
                trailing_len: bytes.len() - offset,
            });
        }

        if header[1..3] != TLS_LEGACY_VERSION_1_2 {
            if offset == 0 {
                return Err(PostHandshakeParseError::WrongLegacyVersion {
                    offset,
                    found: [header[1], header[2]],
                });
            }
            return Err(PostHandshakeParseError::TrailingIncompleteRecord {
                parsed_lengths: lengths,
                trailing_len: bytes.len() - offset,
            });
        }

        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let wire_len = payload_len.checked_add(TLS_RECORD_HEADER_LEN).ok_or(
            PostHandshakeParseError::DeclaredLengthExceedsMaximum {
                offset,
                wire_len: usize::MAX,
            },
        )?;
        if wire_len > TLS13_MAX_ENCRYPTED_RECORD_WIRE_LEN {
            return Err(PostHandshakeParseError::DeclaredLengthExceedsMaximum { offset, wire_len });
        }

        let available_payload = bytes.len().saturating_sub(offset + TLS_RECORD_HEADER_LEN);
        if payload_len > available_payload {
            return Err(PostHandshakeParseError::TruncatedPayload {
                offset,
                declared_payload_len: payload_len,
                available_payload_len: available_payload,
            });
        }

        lengths.push(wire_len);
        offset = offset
            .checked_add(wire_len)
            .expect("wire_len bounded by input length");
    }

    Ok(lengths)
}

/// Converts a parser error into a standard I/O error for probe completion paths.
pub fn post_handshake_parse_error(err: PostHandshakeParseError) -> Error {
    Error::new(err.kind(), err.to_string())
}
