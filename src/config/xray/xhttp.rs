use super::raw::XHttpSettings;

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
}
