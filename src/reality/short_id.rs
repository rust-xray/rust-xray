/// Parses an Xray REALITY `shortId` hex string (up to 16 hex chars / 8 bytes).
///
/// An empty string is accepted and returns an empty vector for Xray compatibility.
pub fn parse_short_id_hex(value: &str) -> std::io::Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    if value.len() > 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid shortId {value:?}: hex length must be at most 16 chars, got {}",
                value.len()
            ),
        ));
    }

    if !value.len().is_multiple_of(2) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid shortId {value:?}: hex length must be even, got {}",
                value.len()
            ),
        ));
    }

    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid shortId {value:?}: must be hex"),
        ));
    }

    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid shortId {value:?}: {e}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_short_id_hex_empty_string() {
        assert_eq!(parse_short_id_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn parse_short_id_hex_single_byte() {
        assert_eq!(parse_short_id_hex("00").unwrap(), vec![0x00]);
    }

    #[test]
    fn parse_short_id_hex_max_eight_bytes() {
        assert_eq!(
            parse_short_id_hex("0123456789abcdef").unwrap(),
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn parse_short_id_hex_rejects_odd_length() {
        let err = parse_short_id_hex("abc").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("even"));
    }

    #[test]
    fn parse_short_id_hex_rejects_too_long() {
        let err = parse_short_id_hex("0123456789abcdef0").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("at most 16"));
    }

    #[test]
    fn parse_short_id_hex_rejects_non_hex_symbol() {
        let err = parse_short_id_hex("012g").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("hex"));
    }
}
