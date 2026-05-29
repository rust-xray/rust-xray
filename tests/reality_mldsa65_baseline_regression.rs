//! ML-DSA-65 baseline regression guards (built-in crypto, no `reality-mldsa65-crypto` feature).
//!
//! These tests must fail if feature-gated ML-DSA, optional `ml-dsa`, or silent invalid-seed
//! handling is reintroduced. They do not exercise the live Vision/REALITY handshake path.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rust_xray::config::{
    first_reality_inbound_runtime, reality_mldsa65_runtime_mode, RealityMldsa65RuntimeMode,
    XrayConfig,
};
use rust_xray::reality::{select_reality_certificate_patch_mode, RealityCertificatePatchMode};

const WORKSPACE_ROOT: &str = env!("CARGO_MANIFEST_DIR");
const TEST_REALITY_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
const TEST_MLDSA65_SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn workspace_path(rel: &str) -> PathBuf {
    Path::new(WORKSPACE_ROOT).join(rel)
}

fn read_workspace_text(rel: &str) -> String {
    fs::read_to_string(workspace_path(rel)).unwrap_or_else(|err| panic!("read {rel}: {err}"))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn assert_no_removed_mldsa65_feature_markers(contents: &str, label: &str) {
    assert!(
        !contents.contains("reality-mldsa65-crypto"),
        "{label}: removed reality-mldsa65-crypto marker must not return"
    );
    assert!(
        !contents.contains(r#"cfg(feature = "reality-mldsa65-crypto")"#),
        "{label}: cfg(feature = \"reality-mldsa65-crypto\") must not return"
    );
    assert!(
        !contents.contains(r#"cfg(not(feature = "reality-mldsa65-crypto"))"#),
        "{label}: cfg(not(feature = \"reality-mldsa65-crypto\")) must not return"
    );
    assert!(
        !contents.contains("crypto_feature_compiled"),
        "{label}: crypto_feature_compiled marker must not return"
    );
    assert!(
        !contents.contains("requires feature"),
        "{label}: stale requires-feature marker must not return"
    );
}

fn minimal_reality_config_json(mldsa65_seed: Option<&str>) -> String {
    let mldsa65_seed_field = match mldsa65_seed {
        Some(seed) => format!(r#","mldsa65Seed": "{seed}""#),
        None => String::new(),
    };

    format!(
        r#"{{
            "inbounds": [{{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                        {mldsa65_seed_field}
                    }}
                }}
            }}]
        }}"#
    )
}

fn parse_runtime(mldsa65_seed: Option<&str>) -> rust_xray::config::RealityInboundRuntime {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_config_json(mldsa65_seed)).expect("parse config");
    first_reality_inbound_runtime(&config).expect("build runtime config")
}

#[test]
fn cargo_toml_keeps_ml_dsa_builtin_without_feature_gate() {
    let cargo = read_workspace_text("Cargo.toml");
    assert_no_removed_mldsa65_feature_markers(&cargo, "Cargo.toml");
    assert!(
        cargo.lines().any(|line| line.starts_with("ml-dsa = ")),
        "Cargo.toml: ml-dsa must remain a standard dependency"
    );
    assert!(
        !cargo.contains("ml-dsa")
            || !cargo.lines().any(|line| {
                line.contains("ml-dsa") && line.contains("optional") && line.contains("true")
            }),
        "Cargo.toml: ml-dsa must not be marked optional"
    );
}

#[test]
fn src_has_no_removed_mldsa65_feature_cfg() {
    let mut rs_files = Vec::new();
    collect_rs_files(&workspace_path("src"), &mut rs_files).expect("walk src/");
    assert!(!rs_files.is_empty(), "expected Rust sources under src/");

    for path in rs_files {
        let contents = fs::read_to_string(&path).expect("read source file");
        let label = path
            .strip_prefix(WORKSPACE_ROOT)
            .unwrap_or(&path)
            .display()
            .to_string();
        assert_no_removed_mldsa65_feature_markers(&contents, &label);
    }
}

#[test]
fn live_reality_smoke_scripts_have_no_removed_mldsa65_feature_gate() {
    let smoke_dir = workspace_path("scripts/live_reality_smoke");
    let mut files = Vec::new();
    collect_rs_files(&smoke_dir, &mut files).ok();
    for entry in fs::read_dir(&smoke_dir).expect("read smoke dir") {
        let entry = entry.expect("smoke dir entry");
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }

    for path in files {
        let contents = fs::read_to_string(&path).expect("read smoke file");
        let label = path
            .strip_prefix(WORKSPACE_ROOT)
            .unwrap_or(&path)
            .display()
            .to_string();
        assert_no_removed_mldsa65_feature_markers(&contents, &label);
    }
}

#[test]
fn no_seed_config_selects_disabled_runtime_and_hmac_only_patch_mode() {
    let runtime = parse_runtime(None);
    assert!(runtime.mldsa65_seed.is_none());
    assert_eq!(
        reality_mldsa65_runtime_mode(&runtime),
        RealityMldsa65RuntimeMode::Disabled
    );

    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let mode = select_reality_certificate_patch_mode(
        runtime.mldsa65_seed.as_ref(),
        &client_hello,
        &server_hello,
    )
    .expect("HMAC-only patch mode");
    assert!(matches!(mode, RealityCertificatePatchMode::HmacOnly));
}

#[test]
fn seed_config_selects_enabled_runtime_and_hmac_plus_mldsa65_patch_mode() {
    let runtime = parse_runtime(Some(TEST_MLDSA65_SEED));
    assert!(runtime.mldsa65_seed.is_some());
    assert_eq!(
        reality_mldsa65_runtime_mode(&runtime),
        RealityMldsa65RuntimeMode::Enabled
    );

    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let mode = select_reality_certificate_patch_mode(
        runtime.mldsa65_seed.as_ref(),
        &client_hello,
        &server_hello,
    )
    .expect("ML-DSA patch mode");
    assert!(matches!(
        mode,
        RealityCertificatePatchMode::HmacPlusMldsa65 { .. }
    ));
}

#[test]
fn invalid_mldsa65_seed_rejected_at_startup_not_silently_ignored() {
    let config: XrayConfig =
        serde_json::from_str(&minimal_reality_config_json(Some("not-valid-base64!!!")))
            .expect("parse config");
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let err_text = err.to_string();
    assert!(err_text.contains("invalid mldsa65Seed base64"));
    assert!(!err_text.contains("not-valid-base64!!!"));
}

#[test]
fn reality_inbound_runtime_debug_redacts_seed_and_private_key() {
    use rust_xray::config::RealityInboundRuntime;

    let runtime = parse_runtime(Some(TEST_MLDSA65_SEED));
    let debug = format!("{runtime:?}");

    assert!(debug.contains("mldsa65_seed"));
    assert!(debug.contains("private_key"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(TEST_MLDSA65_SEED));
    assert!(!debug.contains(TEST_REALITY_PRIVATE_KEY));

    let _typed: RealityInboundRuntime = runtime;
}
