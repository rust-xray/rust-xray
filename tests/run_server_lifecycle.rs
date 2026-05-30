use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn smoke_server_config(port: u16) -> String {
    format!(
        r#"{{
  "inbounds": [
    {{
      "tag": "vless-reality-in",
      "listen": "127.0.0.1",
      "port": {port},
      "protocol": "vless",
      "settings": {{
        "clients": [
          {{
            "id": "11111111-1111-1111-1111-111111111111",
            "email": "fixture@example.test",
            "flow": ""
          }}
        ],
        "decryption": "none"
      }},
      "streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "dest": "www.microsoft.com:443",
          "serverNames": ["www.microsoft.com"],
          "privateKey": "MKVGVTTvyEyI7hpl7vP7WKtRXLhH0JieCMHgFdn6A3s",
          "shortIds": ["0123456789abcdef"],
          "maxTimeDiff": 0
        }}
      }}
    }}
  ]
}}"#
    )
}

#[test]
fn server_without_api_block_stays_alive_after_reality_listener_start() {
    let port = pick_free_port();
    let config_dir = tempfile::tempdir().expect("tempdir");
    let config_path = config_dir.path().join("server.json");
    std::fs::write(&config_path, smoke_server_config(port)).expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rust-xray"))
        .arg(&config_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-xray");

    thread::sleep(Duration::from_millis(800));

    let status = child.try_wait().expect("try_wait");
    assert!(
        status.is_none(),
        "server exited early with status: {status:?}"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_ok(),
        "REALITY listener should accept TCP connections on 127.0.0.1:{port}"
    );

    child.kill().ok();
    let _ = child.wait();
}
