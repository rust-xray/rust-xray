//! Supervisor-visible bootstrap and fatal logs on stderr (independent of `RUST_LOG`).

use std::io;
use std::process;

use crate::cli::{Command, RunOptions};
use crate::config::{config_source_kind, redact_config_source};

const PREFIX: &str = "[rust-xray]";

/// Write a bootstrap line to stderr (always visible in supervisor `xray.err.log`).
pub fn eprintln_bootstrap(message: impl AsRef<str>) {
    eprintln!("{PREFIX} {}", message.as_ref());
}

/// Redact argv for logs (http+unix tokens, query strings).
pub fn redact_argv(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg.contains("http+unix://") || arg.contains("token=") {
                redact_config_source(arg)
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn command_mode_label(command: &Command) -> &'static str {
    match command {
        Command::Version => "version",
        Command::Api(_) => "api",
        Command::Run(_) => "run",
    }
}

/// Early bootstrap for long-running server modes (stderr only; version stays one-line on stdout).
pub fn log_server_bootstrap(raw_args: &[String], opts: &RunOptions) {
    eprintln_bootstrap("main_entry start");
    eprintln_bootstrap(format!("argv: {}", redact_argv(raw_args)));
    eprintln_bootstrap(format!(
        "mode: {}",
        command_mode_label(&Command::Run(opts.clone()))
    ));
    eprintln_bootstrap(format!(
        "config_source_kind: {}",
        config_source_kind(&opts.config)
    ));
    if let Some(format) = opts.format.as_deref() {
        eprintln_bootstrap(format!("format: {format}"));
    } else {
        eprintln_bootstrap("format: (default)");
    }
    eprintln_bootstrap(format!("pid: {}", process::id()));
    eprintln_bootstrap(format!("config: {}", redact_config_source(&opts.config)));
}

pub fn eprintln_fatal(err: &(dyn std::error::Error + 'static)) {
    eprintln_bootstrap(format!("fatal: {err:?}"));
}

pub fn eprintln_fatal_message(message: impl AsRef<str>) {
    eprintln_bootstrap(format!("fatal: {}", message.as_ref()));
}

pub fn eprintln_stage(stage: &str, err: &io::Error) {
    eprintln_bootstrap(format!("{stage}: {err}"));
}

pub fn eprintln_api_listen_resolved(
    listen: &str,
    source: &str,
    inbound_tag: Option<&str>,
    api_tag: &str,
) {
    eprintln_bootstrap(format!(
        "API listen resolved: {listen} source={source} inbound_tag={} api_tag={api_tag}",
        inbound_tag.unwrap_or("-")
    ));
}

pub fn eprintln_api_listening(listen: &str, mode: &str) {
    eprintln_bootstrap(format!("Xray API listening on {listen} {mode}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_argv_hides_token_in_http_unix_uri() {
        let args = vec![
            "rw-core".to_string(),
            "-config".to_string(),
            "http+unix:///run/a.sock/internal/get-config?token=secret".to_string(),
            "-format".to_string(),
            "json".to_string(),
        ];
        let redacted = redact_argv(&args);
        assert!(!redacted.contains("secret"));
        assert!(redacted.contains("?<redacted>"));
    }
}
