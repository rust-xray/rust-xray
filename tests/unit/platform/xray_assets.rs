use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::api::proto::common::geodata::domain;
use crate::api::proto::common::geodata::{Domain, GeoSite};
use crate::config::xray::raw::{OutboundObject, RoutingConfig, RoutingRuleObject};
use crate::dns::engine::DnsEngine;
use crate::platform::assets::{XrayAssetResolver, ASSET_LOCATION_ENV_ALT};
use crate::routing::{RouteContext, RuntimeRouter};
use crate::runtime::RuntimeOutboundManager;
use prost::Message;
use tempfile::TempDir;

fn encode_geosite_dat(code: &str, domains: &[Domain]) -> Vec<u8> {
    let geosite = GeoSite {
        code: code.to_string(),
        domain: domains.to_vec(),
    };
    let body = geosite.encode_to_vec();
    let mut out = Vec::with_capacity(1 + 5 + body.len());
    out.push(0);
    let mut value = body.len() as u64;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out.extend(body);
    out
}

fn write_geosite_asset(dir: &std::path::Path, code: &str, domain: &str) {
    let bytes = encode_geosite_dat(
        code,
        &[Domain {
            r#type: domain::Type::Full as i32,
            value: domain.to_string(),
            attribute: vec![],
        }],
    );
    std::fs::write(dir.join("geosite.dat"), bytes).expect("write geosite.dat");
}

#[test]
fn absolute_path_is_preserved() {
    let absolute = PathBuf::from("/tmp/custom/geoip.dat");
    let resolver = XrayAssetResolver::with_search_roots(None, None, Vec::new());
    assert_eq!(resolver.resolve(&absolute), absolute);
}

#[test]
fn configured_asset_directory_wins() {
    let asset_dir = TempDir::new().expect("asset dir");
    std::fs::write(asset_dir.path().join("geoip.dat"), b"asset").expect("write asset");
    let exe_dir = TempDir::new().expect("exe dir");
    std::fs::write(exe_dir.path().join("geoip.dat"), b"exe").expect("write exe");

    let local_share = TempDir::new().expect("share dir");
    std::fs::write(local_share.path().join("geoip.dat"), b"share").expect("write share");

    let resolver = XrayAssetResolver::with_search_roots(
        Some(asset_dir.path().to_path_buf()),
        Some(exe_dir.path().to_path_buf()),
        vec![local_share.path().to_path_buf()],
    );
    let resolved = resolver.resolve(std::path::Path::new("geoip.dat"));
    assert_eq!(resolved, asset_dir.path().join("geoip.dat"));
}

#[test]
fn executable_directory_wins_when_asset_exists_there() {
    let exe_dir = TempDir::new().expect("exe dir");
    std::fs::write(exe_dir.path().join("geosite.dat"), b"exe").expect("write exe");
    let share = TempDir::new().expect("share dir");
    std::fs::write(share.path().join("geosite.dat"), b"share").expect("write share");

    let resolver = XrayAssetResolver::with_search_roots(
        None,
        Some(exe_dir.path().to_path_buf()),
        vec![share.path().to_path_buf()],
    );
    assert_eq!(
        resolver.resolve(std::path::Path::new("geosite.dat")),
        exe_dir.path().join("geosite.dat")
    );
}

#[test]
fn system_share_roots_checked_in_order() {
    let exe_dir = TempDir::new().expect("exe dir");
    let local = TempDir::new().expect("local share");
    let share = TempDir::new().expect("share");
    let opt = TempDir::new().expect("opt share");
    std::fs::write(local.path().join("custom.dat"), b"local").expect("local");
    std::fs::write(share.path().join("custom.dat"), b"share").expect("share");
    std::fs::write(opt.path().join("custom.dat"), b"opt").expect("opt");

    let resolver = XrayAssetResolver::with_search_roots(
        None,
        Some(exe_dir.path().to_path_buf()),
        vec![
            local.path().to_path_buf(),
            share.path().to_path_buf(),
            opt.path().to_path_buf(),
        ],
    );
    assert_eq!(
        resolver.resolve(std::path::Path::new("custom.dat")),
        local.path().join("custom.dat")
    );

    let resolver = XrayAssetResolver::with_search_roots(
        None,
        Some(exe_dir.path().to_path_buf()),
        vec![share.path().to_path_buf(), opt.path().to_path_buf()],
    );
    assert_eq!(
        resolver.resolve(std::path::Path::new("custom.dat")),
        share.path().join("custom.dat")
    );

    let resolver = XrayAssetResolver::with_search_roots(
        None,
        Some(exe_dir.path().to_path_buf()),
        vec![opt.path().to_path_buf()],
    );
    assert_eq!(
        resolver.resolve(std::path::Path::new("custom.dat")),
        opt.path().join("custom.dat")
    );
}

#[test]
fn missing_asset_returns_default_executable_path() {
    let exe_dir = TempDir::new().expect("exe dir");
    let resolver =
        XrayAssetResolver::with_search_roots(None, Some(exe_dir.path().to_path_buf()), Vec::new());
    assert_eq!(
        resolver.resolve(std::path::Path::new("geoip.dat")),
        exe_dir.path().join("geoip.dat")
    );
    assert!(
        !resolver.resolve(std::path::Path::new("geoip.dat")).exists(),
        "missing file must still return default path for caller error"
    );
}

#[test]
fn s6_servicedir_cwd_is_not_used_for_relative_assets() {
    let s6_cwd = TempDir::new().expect("s6 cwd");
    std::fs::write(s6_cwd.path().join("geoip.dat"), b"decoy").expect("cwd decoy");

    let asset_root = TempDir::new().expect("asset root");
    write_geosite_asset(asset_root.path(), "TEST", "example.com");
    std::fs::write(asset_root.path().join("geoip.dat"), b"real").expect("real geoip");

    let exe_dir = TempDir::new().expect("exe dir");
    let previous_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(s6_cwd.path()).expect("set cwd");

    let resolver = XrayAssetResolver::with_search_roots(
        None,
        Some(exe_dir.path().to_path_buf()),
        vec![asset_root.path().to_path_buf()],
    );
    let resolved = resolver.resolve(std::path::Path::new("geoip.dat"));
    assert_eq!(resolved, asset_root.path().join("geoip.dat"));
    assert_ne!(resolved, s6_cwd.path().join("geoip.dat"));

    std::env::set_current_dir(previous_cwd).expect("restore cwd");
}

#[test]
fn ext_custom_dat_uses_asset_resolver_not_cwd() {
    let s6_cwd = TempDir::new().expect("s6 cwd");
    std::fs::write(s6_cwd.path().join("custom.dat"), b"decoy").expect("cwd decoy");

    let asset_root = TempDir::new().expect("asset root");
    std::fs::write(asset_root.path().join("custom.dat"), b"real").expect("real custom");

    let exe_dir = TempDir::new().expect("exe dir");
    let previous_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(s6_cwd.path()).expect("set cwd");

    let resolver = XrayAssetResolver::with_search_roots(
        None,
        Some(exe_dir.path().to_path_buf()),
        vec![asset_root.path().to_path_buf()],
    );
    let resolved = resolver.resolve(std::path::Path::new("custom.dat"));
    assert_eq!(resolved, asset_root.path().join("custom.dat"));

    std::env::set_current_dir(previous_cwd).expect("restore cwd");
}

#[test]
fn runtime_router_geosite_resolution_is_independent_of_cwd() {
    let asset_dir = TempDir::new().expect("asset dir");
    write_geosite_asset(asset_dir.path(), "TEST", "geo.example");

    let s6_cwd = TempDir::new().expect("s6 cwd");
    std::fs::write(s6_cwd.path().join("geosite.dat"), b"decoy").expect("cwd decoy");

    let previous_cwd = std::env::current_dir().expect("cwd");
    let previous_asset = std::env::var(ASSET_LOCATION_ENV_ALT).ok();
    std::env::set_current_dir(s6_cwd.path()).expect("set cwd");
    std::env::set_var(ASSET_LOCATION_ENV_ALT, asset_dir.path());

    let outbound = RuntimeOutboundManager::new();
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("direct".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("outbound");
    outbound
        .register_startup_outbound(&OutboundObject {
            tag: Some("block".to_string()),
            protocol: Some("blackhole".to_string()),
            extra: Default::default(),
        })
        .expect("outbound");

    let routing = RoutingConfig {
        domain_strategy: Some("AsIs".to_string()),
        rules: vec![RoutingRuleObject {
            outbound_tag: Some("block".to_string()),
            rule_type: Some("field".to_string()),
            extra: BTreeMap::from([("domain".to_string(), serde_json::json!(["geosite:TEST"]))]),
            ..Default::default()
        }],
        ..Default::default()
    };

    let router = RuntimeRouter::new(
        Some(&routing),
        outbound,
        Arc::new(DnsEngine::with_mux_defaults()),
        false,
        None,
    )
    .expect("router must load geosite from asset dir, not s6 cwd");

    let decision = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(router.pick_route(RouteContext {
            target_domain: "geo.example".to_string(),
            ..Default::default()
        }))
        .expect("route");
    assert_eq!(decision.outbound_tag, "block");

    if let Some(value) = previous_asset {
        std::env::set_var(ASSET_LOCATION_ENV_ALT, value);
    } else {
        std::env::remove_var(ASSET_LOCATION_ENV_ALT);
    }
    std::env::set_current_dir(previous_cwd).expect("restore cwd");
}
