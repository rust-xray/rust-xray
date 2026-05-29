use std::path::PathBuf;
use std::process::Command;

use rust_xray::cli::{parse_args, ApiCommand, Command as CliCommand, StatsApiOptions};

fn cargo_bin_rust_xray() -> Command {
    let bin = std::env::var("CARGO_BIN_EXE_rust_xray").unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug/rust-xray")
            .display()
            .to_string()
    });
    let mut cmd = Command::new(bin);
    cmd.env_remove("RUST_BACKTRACE");
    cmd
}

#[test]
fn integration_version_stdout_is_xray_like() {
    let output = cargo_bin_rust_xray()
        .args(["version"])
        .output()
        .expect("spawn rust-xray version");
    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("Xray "));
    assert!(stdout.contains("rust-xray compatibility build"));
}

#[test]
fn integration_api_statsquery_fails_gracefully_without_server() {
    let output = cargo_bin_rust_xray()
        .args(["api", "statsquery", "--server=127.0.0.1:10085", "-t", "1"])
        .output()
        .expect("spawn rust-xray api statsquery");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to dial") || stderr.contains("not implemented"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn integration_api_stats_requires_name() {
    let output = cargo_bin_rust_xray()
        .args(["api", "stats", "--server=127.0.0.1:10085"])
        .output()
        .expect("spawn rust-xray api stats");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing required -name"));
}

#[test]
fn parse_run_and_shorthand_config_equivalent() {
    let run = parse_args(["xray", "run", "-config", "/tmp/a.json"]).unwrap();
    let shorthand = parse_args(["xray", "-config", "/tmp/a.json"]).unwrap();
    assert_eq!(run, shorthand);
}

#[test]
fn parse_api_statsquery_server_flag() {
    let cmd = parse_args(["xray", "api", "statsquery", "--server=127.0.0.1:10085"]).unwrap();
    assert_eq!(
        cmd,
        CliCommand::Api(ApiCommand::StatsQuery(StatsApiOptions {
            server: "127.0.0.1:10085".to_string(),
            timeout_secs: 3,
            name: None,
            pattern: None,
            reset: false,
        }))
    );
}

#[test]
fn parse_api_statsquery_xray_style_server_flag() {
    let cmd = parse_args(["xray", "api", "statsquery", "-server=127.0.0.1:10084"]).unwrap();
    assert_eq!(
        cmd,
        CliCommand::Api(ApiCommand::StatsQuery(StatsApiOptions {
            server: "127.0.0.1:10084".to_string(),
            timeout_secs: 3,
            name: None,
            pattern: None,
            reset: false,
        }))
    );
}
