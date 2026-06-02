use super::raw::XHttpSettings;

pub const DEFAULT_SC_MAX_EACH_POST_BYTES: u64 = 1_000_000;
pub const DEFAULT_SC_MAX_BUFFERED_POSTS: usize = 30;

impl XHttpSettings {
    pub fn effective_mode(&self) -> &str {
        self.mode
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("auto")
    }

    pub fn effective_path(&self) -> &str {
        if self.path.trim().is_empty() {
            "/"
        } else {
            self.path.trim()
        }
    }

    pub fn sc_max_each_post_bytes(&self) -> u64 {
        parse_extra_u64(self, "scMaxEachPostBytes", DEFAULT_SC_MAX_EACH_POST_BYTES)
    }

    pub fn sc_max_buffered_posts(&self) -> usize {
        parse_extra_usize(self, "scMaxBufferedPosts", DEFAULT_SC_MAX_BUFFERED_POSTS)
    }
}

fn parse_extra_u64(settings: &XHttpSettings, key: &str, default: u64) -> u64 {
    settings
        .extra
        .get(key)
        .and_then(|value| match value {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(raw) => raw.trim().parse().ok(),
            _ => None,
        })
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn parse_extra_usize(settings: &XHttpSettings, key: &str, default: usize) -> usize {
    settings
        .extra
        .get(key)
        .and_then(|value| match value {
            serde_json::Value::Number(number) => {
                number.as_u64().and_then(|v| usize::try_from(v).ok())
            }
            serde_json::Value::String(raw) => raw.trim().parse().ok(),
            _ => None,
        })
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
