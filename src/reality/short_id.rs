/// Parses an Xray REALITY `shortId` hex string (up to 16 hex chars / 8 bytes).
///
/// An empty string is accepted and returns an empty vector for Xray compatibility.
pub fn parse_short_id_hex(value: &str) -> std::io::Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    if value.len() > 16
        || !value.len().is_multiple_of(2)
        || !value.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid REALITY shortId '{value}': must be even-length hex up to 16 chars"),
        ));
    }

    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid REALITY shortId '{value}': must be even-length hex up to 16 chars ({e})"
                ),
            )
        })
}

#[cfg(test)]
#[path = "../../tests/unit/reality/short_id.rs"]
mod tests;
