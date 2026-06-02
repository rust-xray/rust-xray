use super::*;

fn parse(argv: &[&str]) -> Result<Command, CliError> {
    let mut args = vec!["rw-core".to_string()];
    args.extend(argv.iter().map(|s| (*s).to_string()));
    parse_args(args)
}

#[test]
fn parse_run_with_config_flag() {
    let cmd = parse(&["run", "-config", "/tmp/c.json"]).unwrap();
    assert_eq!(
        cmd,
        Command::Run(RunOptions {
            config: "/tmp/c.json".to_string(),
            format: None,
        })
    );
}

#[test]
fn parse_direct_config_with_format_json() {
    let uri = "http+unix:///run/a.sock/internal/get-config?token=secret";
    let cmd = parse(&["-config", uri, "-format", "json"]).unwrap();
    assert_eq!(
        cmd,
        Command::Run(RunOptions {
            config: uri.to_string(),
            format: Some("json".to_string()),
        })
    );
}

#[test]
fn parse_run_config_with_format_json() {
    let cmd = parse(&["run", "-config", "/tmp/c.json", "-format", "json"]).unwrap();
    assert_eq!(
        cmd,
        Command::Run(RunOptions {
            config: "/tmp/c.json".to_string(),
            format: Some("json".to_string()),
        })
    );
}

#[test]
fn parse_direct_c_flag_with_format_json() {
    let cmd = parse(&["-c", "/tmp/c.json", "-format", "json"]).unwrap();
    assert_eq!(
        cmd,
        Command::Run(RunOptions {
            config: "/tmp/c.json".to_string(),
            format: Some("json".to_string()),
        })
    );
}

#[test]
fn parse_shorthand_c_flag() {
    let cmd = parse(&["run", "-c", "/tmp/c.json"]).unwrap();
    assert_eq!(
        cmd,
        Command::Run(RunOptions {
            config: "/tmp/c.json".to_string(),
            format: None,
        })
    );
}

#[test]
fn parse_unsupported_format_is_error() {
    let err = parse(&["-config", "/tmp/c.json", "-format", "toml"]).unwrap_err();
    assert!(err.message.contains("unsupported -format"));
}

#[test]
fn parse_shorthand_config_flag() {
    let cmd = parse(&["-config", "/tmp/c.json"]).unwrap();
    assert_eq!(
        cmd,
        Command::Run(RunOptions {
            config: "/tmp/c.json".to_string(),
            format: None,
        })
    );
}

#[test]
fn parse_double_dash_config_equals() {
    let cmd = parse(&["run", "--config=/tmp/c.json"]).unwrap();
    assert_eq!(
        cmd,
        Command::Run(RunOptions {
            config: "/tmp/c.json".to_string(),
            format: None,
        })
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
fn version_line_is_single_line() {
    let line = version_line();
    assert!(line.starts_with("Xray "));
    assert!(!line.contains('\n'));
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
        Command::Run(RunOptions {
            config: "./config.json".to_string(),
            format: None,
        })
    );
}

#[test]
fn parse_default_config_when_no_args() {
    let cmd = parse_args(["xray"]).unwrap();
    assert_eq!(cmd, Command::Run(default_run_options()));
}
