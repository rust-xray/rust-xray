//! Validation for cached post-handshake TLS record wire lengths.

use crate::tls::records::TLS_RECORD_HEADER_LEN;

/// RFC 8446 max ciphertext fragment (2^14 + 256) plus record header.
const TLS13_MAX_ENCRYPTED_RECORD_WIRE_LEN: usize = TLS_RECORD_HEADER_LEN + 16_384 + 256;

/// Conservative minimum for empty camouflage application-data records (header + type + tag).
const MIN_EMPTY_CAMOUFLAGE_WIRE_LEN: usize = TLS_RECORD_HEADER_LEN + 1 + 16;

/// Returns whether `wire_len` is a plausible cached post-handshake ApplicationData record length.
pub fn is_valid_post_handshake_wire_length(wire_len: usize) -> bool {
    (MIN_EMPTY_CAMOUFLAGE_WIRE_LEN..=TLS13_MAX_ENCRYPTED_RECORD_WIRE_LEN).contains(&wire_len)
}

/// Filters cached wire lengths, dropping values that cannot encode empty camouflage records.
pub fn sanitize_post_handshake_wire_lengths(lengths: Vec<usize>) -> Vec<usize> {
    lengths
        .into_iter()
        .filter(|wire_len| is_valid_post_handshake_wire_length(*wire_len))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_typical_camouflage_lengths() {
        assert!(is_valid_post_handshake_wire_length(100));
        assert!(is_valid_post_handshake_wire_length(
            MIN_EMPTY_CAMOUFLAGE_WIRE_LEN
        ));
    }

    #[test]
    fn rejects_too_small_or_large() {
        assert!(!is_valid_post_handshake_wire_length(5));
        assert!(!is_valid_post_handshake_wire_length(
            TLS13_MAX_ENCRYPTED_RECORD_WIRE_LEN + 1
        ));
    }

    #[test]
    fn sanitize_drops_invalid_entries() {
        assert_eq!(
            sanitize_post_handshake_wire_lengths(vec![100, 5, 200]),
            vec![100, 200]
        );
    }
}
