//! Xray-compatible CLI argument parsing for Remna/Remnawave drop-in usage.

use std::path::{Path, PathBuf};

const KNOWN_COMMANDS: &[&str] = &["run", "version", "api", "help"];

/// Parsed top-level command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Run { config: PathBuf },
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
        return Ok(Command::Run {
            config: default_config_path(),
        });
    }

    if argv[0].starts_with('-') {
        if argv.iter().any(|a| a == "-version" || a == "--version") {
            return Ok(Command::Version);
        }
        let config = parse_run_config_flags(&argv)?;
        return Ok(Command::Run { config });
    }

    match argv[0].as_str() {
        "run" => {
            let config = parse_run_config_flags(&argv[1..])?;
            Ok(Command::Run { config })
        }
        "version" => Ok(Command::Version),
        "api" => parse_api_command(&argv[1..]),
        "help" | "-h" | "--help" => Err(CliError::new(usage_text())),
        cmd if is_legacy_config_invocation(cmd) => Ok(Command::Run {
            config: PathBuf::from(&argv[0]),
        }),
        other => Err(CliError::new(format!("unknown command: {other}"))),
    }
}

fn is_legacy_config_invocation(first: &str) -> bool {
    !KNOWN_COMMANDS.contains(&first)
}

fn default_config_path() -> PathBuf {
    PathBuf::from("./config.json")
}

fn parse_run_config_flags(args: &[String]) -> Result<PathBuf, CliError> {
    let mut config: Option<PathBuf> = None;
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
            config = Some(PathBuf::from(path));
            i += 1;
            continue;
        }
        if arg.starts_with("-") && !arg.starts_with("--config") {
            i += 1;
            continue;
        }
        if config.is_none() && looks_like_config_path(arg) {
            config = Some(PathBuf::from(arg));
        }
        i += 1;
    }

    Ok(config.unwrap_or_else(default_config_path))
}

fn looks_like_config_path(arg: &str) -> bool {
    !arg.starts_with('-') && (arg.ends_with(".json") || Path::new(arg).exists())
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

/// Xray-like version lines written to stdout by `version`.
pub fn version_lines() -> Vec<String> {
    let version = env!("CARGO_PKG_VERSION");
    let codename = "Xray, Penetrates Everything.";
    let intro = "A unified platform for anti-censorship.";
    let build = "rust-xray compatibility build";
    let target = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    vec![
        format!("Xray {version} ({codename}) {build} (rustc {os}/{target})"),
        intro.to_string(),
    ]
}

pub fn print_version() {
    for line in version_lines() {
        println!("{line}");
    }
}

fn usage_text() -> String {
    "Usage: xray run -config <file> | xray -config <file> | xray version | xray api statsquery | xray api stats".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Result<Command, CliError> {
        let mut args = vec!["xray".to_string()];
        args.extend(argv.iter().map(|s| (*s).to_string()));
        parse_args(args)
    }

    #[test]
    fn parse_run_with_config_flag() {
        let cmd = parse(&["run", "-config", "/tmp/c.json"]).unwrap();
        assert_eq!(
            cmd,
            Command::Run {
                config: PathBuf::from("/tmp/c.json")
            }
        );
    }

    #[test]
    fn parse_shorthand_config_flag() {
        let cmd = parse(&["-config", "/tmp/c.json"]).unwrap();
        assert_eq!(
            cmd,
            Command::Run {
                config: PathBuf::from("/tmp/c.json")
            }
        );
    }

    #[test]
    fn parse_double_dash_config_equals() {
        let cmd = parse(&["run", "--config=/tmp/c.json"]).unwrap();
        assert_eq!(
            cmd,
            Command::Run {
                config: PathBuf::from("/tmp/c.json")
            }
        );
    }

    #[test]
    fn parse_version_subcommand() {
        assert_eq!(parse(&["version"]).unwrap(), Command::Version);
    }

    #[test]
    fn parse_version_flag_compat() {
        assert_eq!(parse(&["-version"]).unwrap(), Command::Version);
    }

    #[test]
    fn parse_api_statsquery() {
        let cmd = parse(&["api", "statsquery", "--server=127.0.0.1:10085"]).unwrap();
        assert_eq!(
            cmd,
            Command::Api(ApiCommand::StatsQuery(StatsApiOptions {
                server: "127.0.0.1:10085".to_string(),
                timeout_secs: 3,
                name: None,
                pattern: None,
                reset: false,
            }))
        );
    }

    #[test]
    fn parse_api_statsquery_xray_style_server_equals() {
        let cmd = parse(&["api", "statsquery", "-server=127.0.0.1:10084"]).unwrap();
        assert_eq!(
            cmd,
            Command::Api(ApiCommand::StatsQuery(StatsApiOptions {
                server: "127.0.0.1:10084".to_string(),
                timeout_secs: 3,
                name: None,
                pattern: None,
                reset: false,
            }))
        );
    }

    #[test]
    fn parse_api_stats_with_name_and_reset() {
        let cmd = parse(&[
            "api",
            "stats",
            "-s",
            "127.0.0.1:10085",
            "-name",
            "inbound>>>statin>>>traffic>>>downlink",
            "-reset",
        ])
        .unwrap();
        assert_eq!(
            cmd,
            Command::Api(ApiCommand::Stats(StatsApiOptions {
                server: "127.0.0.1:10085".to_string(),
                timeout_secs: 3,
                name: Some("inbound>>>statin>>>traffic>>>downlink".to_string()),
                pattern: None,
                reset: true,
            }))
        );
    }

    #[test]
    fn parse_legacy_config_path() {
        let cmd = parse(&["./config.json"]).unwrap();
        assert_eq!(
            cmd,
            Command::Run {
                config: PathBuf::from("./config.json")
            }
        );
    }

    #[test]
    fn parse_default_config_when_no_args() {
        let cmd = parse_args(["xray"]).unwrap();
        assert_eq!(
            cmd,
            Command::Run {
                config: PathBuf::from("./config.json")
            }
        );
    }

    #[test]
    fn version_lines_start_with_xray() {
        let lines = version_lines();
        assert!(lines[0].starts_with("Xray "));
        assert_eq!(lines.len(), 2);
    }
}
