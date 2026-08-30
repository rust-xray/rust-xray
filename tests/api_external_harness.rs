//! Reusable external-process gRPC API interoperability harness (Stage 8E5-C).

#![allow(dead_code)]

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use tempfile::TempDir;

pub const CANONICAL_HANDLER: &str = "xray.app.proxyman.command.HandlerService";
pub const CANONICAL_STATS: &str = "xray.app.stats.command.StatsService";
pub const CANONICAL_ROUTING: &str = "xray.app.router.command.RoutingService";
pub const CANONICAL_LOGGER: &str = "xray.app.log.command.LoggerService";
pub const CANONICAL_OBSERVATORY: &str = "xray.core.app.observatory.command.ObservatoryService";

pub const LEGACY_HANDLER: &str = "v2ray.core.app.proxyman.command.HandlerService";
pub const LEGACY_STATS: &str = "v2ray.core.app.stats.command.StatsService";
pub const LEGACY_ROUTING: &str = "v2ray.core.app.router.command.RoutingService";
pub const LEGACY_LOGGER: &str = "v2ray.core.app.log.command.LoggerService";

pub const REFLECTION_V1: &str = "grpc.reflection.v1.ServerReflection";
pub const REFLECTION_V1ALPHA: &str = "grpc.reflection.v1alpha.ServerReflection";

pub const DEFAULT_USER_UUID: &str = "11111111-1111-1111-1111-111111111111";
pub const DEFAULT_USER_EMAIL: &str = "remna-user@example.test";
pub const REALITY_INBOUND_TAG: &str = "vless-reality-in";

#[derive(Debug, Clone)]
pub struct ExternalBinaries {
    pub xray: PathBuf,
    pub grpcurl: PathBuf,
    pub report_path: PathBuf,
}

impl ExternalBinaries {
    pub fn resolve() -> Option<Self> {
        let xray = resolve_binary(
            "XRAY_UPSTREAM_BIN",
            &[
                "/tmp/xray-upstream/xray",
                &format!("{}/go/bin/xray", std::env::var("HOME").unwrap_or_default()),
            ],
        )?;
        let grpcurl = resolve_binary(
            "GRPCURL_BIN",
            &[
                &format!(
                    "{}/go/bin/grpcurl",
                    std::env::var("HOME").unwrap_or_default()
                ),
                "/usr/local/bin/grpcurl",
                "/opt/homebrew/bin/grpcurl",
            ],
        )?;
        let report_path = std::env::temp_dir().join(format!(
            "rust-xray-api-external-interop-{}.jsonl",
            std::process::id()
        ));
        Some(Self {
            xray,
            grpcurl,
            report_path,
        })
    }

    pub fn xray_version(&self, report: &InteropReport) -> String {
        run_command_capture(&self.xray, &["version"], report, "xray version").stdout
    }

    pub fn grpcurl_version(&self, report: &InteropReport) -> String {
        run_command_capture(&self.grpcurl, &["-version"], report, "grpcurl version").stdout
    }
}

fn resolve_binary(env_var: &str, defaults: &[&str]) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(env_var) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    defaults
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

pub fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

pub struct InteropReport {
    path: PathBuf,
}

impl InteropReport {
    pub fn new(path: PathBuf) -> Self {
        let _ = fs::remove_file(&path);
        Self { path }
    }

    pub fn record(&self, case_name: &str, command: &str, output: &CommandOutput) {
        let line = json!({
            "case": case_name,
            "command": command,
            "exit_code": output.status.code(),
            "success": output.status.success(),
            "stdout": output.stdout,
            "stderr": output.stderr,
        });
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .expect("open interop report");
        writeln!(file, "{line}").expect("write interop report");
    }
}

pub struct CommandOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_command_capture(
    bin: &Path,
    args: &[&str],
    report: &InteropReport,
    case_name: &str,
) -> CommandOutput {
    let mut cmd = Command::new(bin);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().expect("spawn external command");
    let parsed = CommandOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    let command = format!("{} {}", bin.display(), args.join(" "));
    report.record(case_name, &command, &parsed);
    parsed
}

pub struct ApiServerHarness {
    pub api_addr: String,
    pub api_port: u16,
    pub temp_dir: TempDir,
    pub error_log: PathBuf,
    pub access_log: PathBuf,
    child: Child,
    report: InteropReport,
}

impl ApiServerHarness {
    pub fn spawn(bins: &ExternalBinaries) -> Self {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let api_port = pick_free_port();
        let reality_port = pick_free_port();
        let api_addr = format!("127.0.0.1:{api_port}");
        let error_log = temp_dir.path().join("error.log");
        let access_log = temp_dir.path().join("access.log");
        let config_path = temp_dir.path().join("config.json");
        let config = build_external_interop_config(api_port, reality_port, &error_log, &access_log);
        fs::write(&config_path, config).expect("write config");

        let rust_xray = std::env::var("CARGO_BIN_EXE_rust-xray").unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/debug/rust-xray")
                .display()
                .to_string()
        });
        let child = Command::new(rust_xray)
            .arg(&config_path)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rust-xray");

        let report = InteropReport::new(bins.report_path.clone());
        let mut harness = Self {
            api_addr: api_addr.clone(),
            api_port,
            temp_dir,
            error_log,
            access_log,
            child,
            report,
        };
        harness.wait_for_api_ready(bins, Duration::from_secs(15));
        harness
    }

    fn wait_for_api_ready(&mut self, bins: &ExternalBinaries, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.child.try_wait().expect("try_wait").is_some() {
                panic!("rust-xray exited before API became ready");
            }
            let output = self.run_grpcurl(
                bins,
                &["-plaintext", &self.api_addr, "list"],
                "api readiness probe",
            );
            if output.status.success() && output.stdout.contains(CANONICAL_STATS) {
                std::thread::sleep(Duration::from_millis(500));
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("API did not become ready on {}", self.api_addr);
    }

    pub fn run_grpcurl(&self, bins: &ExternalBinaries, args: &[&str], case: &str) -> CommandOutput {
        run_command_capture(&bins.grpcurl, args, &self.report, case)
    }

    pub fn run_xray_api(
        &self,
        bins: &ExternalBinaries,
        subcommand: &str,
        extra: &[&str],
        case: &str,
    ) -> CommandOutput {
        let server = self.server_flag();
        let mut full_args = vec!["api", subcommand, server.as_str()];
        full_args.extend(extra.iter().copied());
        run_command_capture(&bins.xray, &full_args, &self.report, case)
    }

    pub fn write_json(&self, name: &str, value: serde_json::Value) -> PathBuf {
        let path = self.temp_dir.path().join(name);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&value).expect("serialize json"),
        )
        .expect("write json fixture");
        path
    }

    pub fn server_flag(&self) -> String {
        format!("--server={}", self.api_addr)
    }
}

impl Drop for ApiServerHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn parse_grpcurl_list(stdout: &str) -> HashSet<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn build_external_interop_config(
    api_port: u16,
    reality_port: u16,
    error_log: &Path,
    access_log: &Path,
) -> String {
    let config = json!({
        "log": {
            "loglevel": "warning",
            "error": error_log.to_string_lossy(),
            "access": access_log.to_string_lossy()
        },
        "api": {
            "tag": "api",
            "listen": format!("127.0.0.1:{api_port}"),
            "services": [
                "ReflectionService",
                "HandlerService",
                "StatsService",
                "RoutingService",
                "LoggerService",
                "ObservatoryService"
            ]
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": true,
                    "statsUserDownlink": true,
                    "statsUserOnline": true
                }
            },
            "system": {
                "statsInboundUplink": true,
                "statsInboundDownlink": true,
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        },
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [
                {
                    "tag": "test-balancer",
                    "selector": ["direct", "alt-direct"],
                    "strategy": { "type": "random" }
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [REALITY_INBOUND_TAG],
                    "outboundTag": "direct"
                }
            ]
        },
        "observatory": {
            "subjectSelector": ["direct"],
            "probeURL": "http://127.0.0.1:1/",
            "probeInterval": "10s"
        },
        "inbounds": [
            {
                "tag": REALITY_INBOUND_TAG,
                "listen": "127.0.0.1",
                "port": reality_port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": DEFAULT_USER_UUID,
                            "email": DEFAULT_USER_EMAIL,
                            "flow": "",
                            "level": 0
                        }
                    ],
                    "decryption": "none",
                    "fallbacks": []
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "dest": "www.microsoft.com:443",
                        "serverNames": ["www.microsoft.com"],
                        "privateKey": "MKVGVTTvyEyI7hpl7vP7WKtRXLhH0JieCMHgFdn6A3s",
                        "shortIds": ["0123456789abcdef"],
                        "maxTimeDiff": 0
                    }
                }
            }
        ],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "alt-direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" }
        ]
    });
    serde_json::to_string_pretty(&config).expect("serialize config")
}

pub fn plain_vless_inbound_json(
    tag: &str,
    port: u16,
    user_id: &str,
    email: &str,
) -> serde_json::Value {
    json!({
        "inbounds": [{
            "tag": tag,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": user_id, "email": email, "level": 0 }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }]
    })
}

pub fn adu_user_json(
    inbound_tag: &str,
    port: u16,
    user_id: &str,
    email: &str,
) -> serde_json::Value {
    json!({
        "inbounds": [{
            "tag": inbound_tag,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": user_id, "email": email, "level": 0 }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            }
        }]
    })
}

pub fn freedom_outbound_json(tag: &str) -> serde_json::Value {
    json!({
        "outbounds": [{
            "tag": tag,
            "protocol": "freedom"
        }]
    })
}

pub fn blackhole_outbound_json(tag: &str) -> serde_json::Value {
    json!({
        "outbounds": [{
            "tag": tag,
            "protocol": "blackhole"
        }]
    })
}

pub fn domain_routing_rule_json(
    rule_tag: &str,
    domain: &str,
    outbound_tag: &str,
) -> serde_json::Value {
    json!({
        "routing": {
            "rules": [{
                "type": "field",
                "ruleTag": rule_tag,
                "domain": [domain],
                "outboundTag": outbound_tag
            }]
        }
    })
}

pub fn build_vless_ip_request(user_id: &[u8; 16], port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0);
    buf.extend_from_slice(user_id);
    buf.push(0);
    buf.push(0x01);
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&[0x01, 127, 0, 0, 1]);
    buf
}

pub fn user_id_bytes(uuid: &str) -> [u8; 16] {
    uuid::Uuid::parse_str(uuid).expect("uuid").into_bytes()
}

pub fn require_external_binaries() -> ExternalBinaries {
    ExternalBinaries::resolve().expect(
        "external binaries missing; set XRAY_UPSTREAM_BIN and GRPCURL_BIN or install defaults",
    )
}
