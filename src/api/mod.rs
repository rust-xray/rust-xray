pub mod client;
pub mod diagnostics;
pub mod handler;
pub mod logger;
pub mod proto;
pub mod routing;
pub mod server;
pub mod stats;

use crate::cli::{ApiCommand, StatsApiOptions};

/// API client failure surfaced to the user (stderr, exit 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub message: String,
}

impl ApiError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

/// Run an `api` subcommand.
pub async fn execute(api: ApiCommand) -> Result<(), ApiError> {
    match api {
        ApiCommand::StatsQuery(opts) => client::stats_query(opts).await,
        ApiCommand::Stats(opts) => client::get_stats(opts).await,
    }
}

pub(crate) fn validate_stats_options(
    subcommand: &str,
    opts: &StatsApiOptions,
) -> Result<(), ApiError> {
    if subcommand == "stats" && opts.name.as_deref().unwrap_or("").is_empty() {
        return Err(ApiError::new("missing required -name for api stats"));
    }
    Ok(())
}
