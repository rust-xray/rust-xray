//! Xray-compatible CLI argument parsing for Remna/Remnawave drop-in usage.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

const KNOWN_COMMANDS: &[&str] = &["run", "version", "api", "help"];

/// Options for `run` / direct `-config` invocations (Xray-compatible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub config: String,
    pub format: Option<String>,
}

/// Parsed top-level command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Run(RunOptions),
    Version,
    Api(ApiCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiCommand {
    StatsQuery(StatsApiOptions),
    Stats(StatsApiOptions),
}

/// Options shared by `api stats` and `api statsquery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsApiOptions {
    pub server: String,
    pub timeout_secs: u64,
    pub name: Option<String>,
    pub pattern: Option<String>,
    pub reset: bool,
}

impl Default for StatsApiOptions {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:8080".to_string(),
            timeout_secs: 3,
            name: None,
            pattern: None,
            reset: false,
        }
    }
}

/// CLI parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
}

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}

/// Parse process arguments (including argv[0] program name).
pub fn parse_args<I, S>(args: I) -> Result<Command, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut argv: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    if argv.is_empty() {
        return Err(CliError::new("missing program name"));
    }
    argv.remove(0);

    if argv.is_empty() {
        return Ok(Command::Run(default_run_options()));
    }

    if argv[0].starts_with('-') {
        if argv.iter().any(|a| a == "-version" || a == "--version") {
            return Ok(Command::Version);
        }
        let opts = parse_run_config_flags(&argv)?;
        return Ok(Command::Run(opts));
    }

    match argv[0].as_str() {
        "run" => {
            let opts = parse_run_config_flags(&argv[1..])?;
            Ok(Command::Run(opts))
        }
        "version" => Ok(Command::Version),
        "api" => parse_api_command(&argv[1..]),
        "help" | "-h" | "--help" => Err(CliError::new(usage_text())),
        cmd if is_legacy_config_invocation(cmd) => Ok(Command::Run(RunOptions {
            config: argv[0].clone(),
            format: None,
        })),
        other => Err(CliError::new(format!("unknown command: {other}"))),
    }
}

fn is_legacy_config_invocation(first: &str) -> bool {
    !KNOWN_COMMANDS.contains(&first)
}

fn default_config_path() -> PathBuf {
    PathBuf::from("./config.json")
}

fn default_run_options() -> RunOptions {
    RunOptions {
        config: default_config_path().display().to_string(),
        format: None,
    }
}

fn parse_run_config_flags(args: &[String]) -> Result<RunOptions, CliError> {
    let mut config: Option<String> = None;
    let mut format: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-version" || arg == "--version" {
            return Err(CliError::new(
                "use `version` subcommand instead of -version flag with run",
            ));
        }
        if matches_flag(arg, "config") || arg == "-c" {
            let path = take_flag_value(args, &mut i, "config")?;
            config = Some(path.to_string());
            i += 1;
            continue;
        }
        if matches_flag(arg, "format") {
            let value = take_flag_value(args, &mut i, "format")?;
            format = Some(value.to_string());
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        if config.is_none() && looks_like_config_source(arg) {
            config = Some(arg.clone());
        }
        i += 1;
    }

    validate_run_format(format.as_deref())?;

    Ok(RunOptions {
        config: config.unwrap_or_else(|| default_config_path().display().to_string()),
        format,
    })
}

fn validate_run_format(format: Option<&str>) -> Result<(), CliError> {
    let Some(format) = format else {
        return Ok(());
    };
    let format = format.trim();
    if format.eq_ignore_ascii_case("json") {
        return Ok(());
    }
    Err(CliError::new(format!(
        "unsupported -format {format:?}; only json is supported"
    )))
}

fn looks_like_config_source(arg: &str) -> bool {
    !arg.starts_with('-')
        && (arg.starts_with("http+unix://") || arg.ends_with(".json") || Path::new(arg).exists())
}

fn parse_api_command(args: &[String]) -> Result<Command, CliError> {
    if args.is_empty() {
        return Err(CliError::new(
            "api subcommand required (e.g. stats, statsquery)",
        ));
    }
    match args[0].as_str() {
        "statsquery" => {
            let opts = parse_stats_api_options(&args[1..])?;
            Ok(Command::Api(ApiCommand::StatsQuery(opts)))
        }
        "stats" => {
            let opts = parse_stats_api_options(&args[1..])?;
            Ok(Command::Api(ApiCommand::Stats(opts)))
        }
        other => Err(CliError::new(format!(
            "unsupported api subcommand: {other} (supported: stats, statsquery)"
        ))),
    }
}

fn parse_stats_api_options(args: &[String]) -> Result<StatsApiOptions, CliError> {
    let mut opts = StatsApiOptions::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if matches_flag(arg, "server") || arg == "-s" {
            opts.server = take_flag_value(args, &mut i, "server")?.to_string();
        } else if matches_flag(arg, "timeout") || arg == "-t" {
            let raw = take_flag_value(args, &mut i, "timeout")?;
            opts.timeout_secs = raw
                .parse()
                .map_err(|_| CliError::new(format!("invalid timeout value: {raw}")))?;
        } else if matches_flag(arg, "name") {
            opts.name = Some(take_flag_value(args, &mut i, "name")?.to_string());
        } else if matches_flag(arg, "pattern") {
            opts.pattern = Some(take_flag_value(args, &mut i, "pattern")?.to_string());
        } else if arg == "-reset" || arg == "--reset" || arg == "reset" {
            opts.reset = true;
        } else if arg.starts_with('-') {
            return Err(CliError::new(format!("unknown api flag: {arg}")));
        }
        i += 1;
    }
    Ok(opts)
}

fn matches_flag(arg: &str, long: &str) -> bool {
    arg == &format!("-{long}")
        || arg == &format!("--{long}")
        || arg.starts_with(&format!("-{long}="))
        || arg.starts_with(&format!("--{long}="))
}

fn take_flag_value<'a>(
    args: &'a [String],
    index: &mut usize,
    long: &str,
) -> Result<&'a str, CliError> {
    let arg = &args[*index];
    if let Some((_, value)) = arg.split_once('=') {
        if value.is_empty() {
            return Err(CliError::new(format!("missing value for --{long}")));
        }
        return Ok(value);
    }
    *index += 1;
    if *index >= args.len() {
        return Err(CliError::new(format!("missing value for -{long}")));
    }
    Ok(args[*index].as_str())
}

/// Single-line Xray-compatible version string (Remnawave entrypoint uses `version | head -n 1`).
pub fn version_line() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let codename = "Xray, Penetrates Everything.";
    let build = "rust-xray compatibility build";
    let target = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    format!("Xray {version} ({codename}) {build} (rustc {os}/{target})")
}

/// Write version to stdout; ignore `BrokenPipe` when the consumer closes early (e.g. `head -n 1`).
pub fn print_version() {
    let line = version_line();
    let mut stdout = io::stdout().lock();
    if let Err(err) = writeln!(stdout, "{line}") {
        if err.kind() != io::ErrorKind::BrokenPipe {
            let _ = writeln!(io::stderr(), "version: {err}");
            std::process::exit(1);
        }
    }
}

fn usage_text() -> String {
    "Usage: xray run -config <file|http+unix://...> [-format json] | xray -config <source> -format json | xray version | xray api statsquery | xray api stats".to_string()
}

#[cfg(test)]
#[path = "../../tests/unit/cli/mod.rs"]
mod tests;
