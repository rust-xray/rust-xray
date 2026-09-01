use std::time::Duration;

use super::keys::KeyMaterialError;

/// Parsed padding profile (`PaddingLens` / `PaddingGaps`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct PaddingProfile {
    pub length_ranges: Vec<[i32; 3]>,
    pub gap_ranges: Vec<[i32; 3]>,
}

impl PaddingProfile {
    pub fn is_empty(&self) -> bool {
        self.length_ranges.is_empty() && self.gap_ranges.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingParseError {
    InvalidToken(String),
    InvalidInteger(String),
    FirstLengthTooSmall,
    TotalLengthTooLarge,
}

impl std::fmt::Display for PaddingParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken(token) => write!(f, "invalid padding length/gap parameter: {token}"),
            Self::InvalidInteger(token) => write!(f, "invalid padding integer in token: {token}"),
            Self::FirstLengthTooSmall => {
                f.write_str("first padding length must not be smaller than 35")
            }
            Self::TotalLengthTooLarge => {
                f.write_str("total padding length must not be larger than 65553")
            }
        }
    }
}

impl std::error::Error for PaddingParseError {}

/// Parse upstream `ParsePadding` grammar.
pub fn parse_padding_profile(padding: &str) -> Result<PaddingProfile, PaddingParseError> {
    if padding.is_empty() {
        return Ok(PaddingProfile::default());
    }

    let mut profile = PaddingProfile::default();
    let mut max_len = 0i32;
    for (index, segment) in padding.split('.').enumerate() {
        let parts: Vec<&str> = segment.split('-').collect();
        if parts.len() < 3 || parts.iter().any(|part| part.is_empty()) {
            return Err(PaddingParseError::InvalidToken(segment.to_string()));
        }
        let values = [
            parse_i32(parts[0], segment)?,
            parse_i32(parts[1], segment)?,
            parse_i32(parts[2], segment)?,
        ];
        if index == 0 && (values[0] < 100 || values[1] < 35 || values[2] < 35) {
            return Err(PaddingParseError::FirstLengthTooSmall);
        }
        if index % 2 == 0 {
            profile.length_ranges.push(values);
            max_len += values[1].max(values[2]);
        } else {
            profile.gap_ranges.push(values);
        }
    }
    if max_len > 18 + 65_535 {
        return Err(PaddingParseError::TotalLengthTooLarge);
    }
    Ok(profile)
}

fn parse_i32(value: &str, token: &str) -> Result<i32, PaddingParseError> {
    value
        .parse::<i32>()
        .map_err(|_| PaddingParseError::InvalidInteger(token.to_string()))
}

/// Deterministic padding generation with injected threshold draw (`0..=100`) and length draw.
pub fn create_padding_lengths<R: RngDraw>(
    profile: &PaddingProfile,
    rng: &mut R,
) -> (usize, Vec<usize>, Vec<Duration>) {
    let (length_ranges, gap_ranges) = if profile.length_ranges.is_empty() {
        (vec![[100, 111, 1111], [50, 0, 3333]], vec![[75, 0, 111]])
    } else {
        (profile.length_ranges.clone(), profile.gap_ranges.clone())
    };

    let mut total = 0usize;
    let mut lens = Vec::new();
    for range in length_ranges {
        let mut length = 0usize;
        if range[0] >= rng.draw_percent() as i32 {
            length = rng.draw_between(range[1], range[2]) as usize;
        }
        lens.push(length);
        total = total.saturating_add(length);
    }

    let mut gaps = Vec::new();
    for range in gap_ranges {
        let mut gap_ms = 0u64;
        if range[0] >= rng.draw_percent() as i32 {
            gap_ms = rng.draw_between(range[1], range[2]) as u64;
        }
        gaps.push(Duration::from_millis(gap_ms));
    }

    (total, lens, gaps)
}

pub trait RngDraw {
    fn draw_percent(&mut self) -> u32;
    fn draw_between(&mut self, min: i32, max: i32) -> u32;
}

#[derive(Debug, Clone, Copy)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }
}

impl RngDraw for SeededRng {
    fn draw_percent(&mut self) -> u32 {
        self.next() % 101
    }

    fn draw_between(&mut self, min: i32, max: i32) -> u32 {
        if max <= min {
            return min.max(0) as u32;
        }
        let span = (max - min).saturating_add(1) as u32;
        min.max(0) as u32 + (self.next() % span)
    }
}

impl From<PaddingParseError> for KeyMaterialError {
    fn from(value: PaddingParseError) -> Self {
        match value {
            PaddingParseError::InvalidToken(_)
            | PaddingParseError::InvalidInteger(_)
            | PaddingParseError::FirstLengthTooSmall
            | PaddingParseError::TotalLengthTooLarge => KeyMaterialError::InvalidBase64,
        }
    }
}
