//! Buffered non-blocking tracing output (stdout) via `tracing-appender`.

use tracing::debug;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use crate::cli::Command;

const DEFAULT_BUFFERED_LINES: usize = 65_536;

const ENV_BUFFERED_LINES: &str = "RUST_XRAY_LOG_BUFFERED_LINES";
const ENV_BACKPRESSURE: &str = "RUST_XRAY_LOG_BACKPRESSURE";

/// Used when `RUST_LOG` is unset (`EnvFilter` equivalent to `RUST_LOG=error`).
const DEFAULT_TRACE_FILTER: &str = "error";

/// Keeps the `tracing-appender` worker thread alive until process exit.
pub struct LoggingGuard {
    _worker_guard: WorkerGuard,
}

pub fn default_env_filter(command: &Command) -> &'static str {
    let _ = command;
    DEFAULT_TRACE_FILTER
}

pub fn init_logging(command: &Command) -> std::io::Result<LoggingGuard> {
    let default_filter = default_env_filter(command);
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let buffered_lines = parse_log_buffered_lines_env();
    let backpressure = parse_log_backpressure_env();
    let lossy = !backpressure;

    let (non_blocking, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(buffered_lines)
        .lossy(lossy)
        .finish(std::io::stdout());

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(non_blocking)
        .init();

    debug!(
        writer = "stdout",
        default_filter,
        rust_log_override = std::env::var("RUST_LOG").is_ok(),
        buffered_lines_limit = buffered_lines,
        backpressure,
        lossy,
        "async buffered logging enabled"
    );

    Ok(LoggingGuard {
        _worker_guard: guard,
    })
}

pub fn parse_log_buffered_lines_env() -> usize {
    parse_buffered_lines(std::env::var(ENV_BUFFERED_LINES).ok().as_deref())
}

pub fn parse_log_backpressure_env() -> bool {
    parse_backpressure(std::env::var(ENV_BACKPRESSURE).ok().as_deref())
}

pub fn parse_buffered_lines(value: Option<&str>) -> usize {
    match value {
        Some(raw) => raw.trim().parse().unwrap_or(DEFAULT_BUFFERED_LINES),
        None => DEFAULT_BUFFERED_LINES,
    }
}

pub fn parse_backpressure(value: Option<&str>) -> bool {
    const TRUE: &[&str] = &["1", "true", "yes", "on"];
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) if TRUE.iter().any(|t| raw.eq_ignore_ascii_case(t)) => true,
        _ => false,
    }
}

#[cfg(test)]
#[path = "../tests/unit/logging.rs"]
mod tests;
