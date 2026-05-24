use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use rust_xray::reality::{
    decode_reality_fixture_client_hello, reality_fixture_expected_metadata,
    write_reality_fixture_expected_files, RealityFixtureSessionResult,
};

struct CliArgs {
    fixture_dir: PathBuf,
    write_expected: bool,
    force: bool,
}

fn usage() -> ! {
    eprintln!("usage: decode_reality_fixture <fixture-dir> [--write-expected] [--force]");
    eprintln!(
        "example: cargo run --bin decode_reality_fixture -- tests/fixtures/reality/basic-xray"
    );
    eprintln!(
        "example: cargo run --bin decode_reality_fixture -- tests/fixtures/reality/basic-xray --write-expected"
    );
    std::process::exit(1);
}

fn parse_cli_args() -> CliArgs {
    let mut fixture_dir = None;
    let mut write_expected = false;
    let mut force = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--write-expected" => write_expected = true,
            "--force" => force = true,
            other if other.starts_with('-') => {
                eprintln!("unknown flag: {other}");
                usage();
            }
            other => {
                if fixture_dir.is_some() {
                    eprintln!("unexpected extra argument: {other}");
                    usage();
                }
                fixture_dir = Some(PathBuf::from(other));
            }
        }
    }

    CliArgs {
        fixture_dir: fixture_dir.unwrap_or_else(|| usage()),
        write_expected,
        force,
    }
}

fn read_trimmed(path: &PathBuf) -> std::io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

fn main() -> ExitCode {
    let cli = parse_cli_args();

    if !cli.fixture_dir.is_dir() {
        eprintln!("fixture directory not found: {}", cli.fixture_dir.display());
        return ExitCode::from(1);
    }

    let client_hello_path = cli.fixture_dir.join("client_hello.bin");
    let private_key_path = cli.fixture_dir.join("server_private_key.txt");

    let client_hello = match fs::read(&client_hello_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("failed to read {}: {err}", client_hello_path.display());
            return ExitCode::from(1);
        }
    };

    let private_key = match read_trimmed(&private_key_path) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("failed to read {}: {err}", private_key_path.display());
            return ExitCode::from(1);
        }
    };

    match decode_reality_fixture_client_hello(&client_hello, &private_key) {
        Ok(RealityFixtureSessionResult::Opened {
            sni,
            client_version,
            unix_time,
            short_id_hex,
        }) => {
            println!("REALITY fixture decode OK");
            match &sni {
                Some(hostname) => println!("sni={hostname}"),
                None => println!("sni="),
            }
            println!("client_version={client_version}");
            println!("unix_time={unix_time}");
            println!("short_id={short_id_hex}");
            println!("result=Opened");

            if cli.write_expected {
                let opened = RealityFixtureSessionResult::Opened {
                    sni,
                    client_version,
                    unix_time,
                    short_id_hex,
                };
                match reality_fixture_expected_metadata(&opened).and_then(|metadata| {
                    write_reality_fixture_expected_files(&cli.fixture_dir, &metadata, cli.force)
                }) {
                    Ok(()) => {
                        println!("expected metadata written");
                    }
                    Err(err) => {
                        eprintln!("failed to write expected metadata: {err}");
                        return ExitCode::from(1);
                    }
                }
            }

            ExitCode::SUCCESS
        }
        Ok(RealityFixtureSessionResult::AuthFailed) => {
            eprintln!("REALITY AEAD auth failed");
            println!("result=AuthFailed");
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("REALITY fixture decode error: {err}");
            ExitCode::from(1)
        }
    }
}
