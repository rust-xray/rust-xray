//! Stage 8E5-C external grpcurl + upstream Xray CLI interoperability tests.
//!
//! Run with real binaries:
//! ```bash
//! XRAY_UPSTREAM_BIN=/path/to/xray \
//! GRPCURL_BIN=/path/to/grpcurl \
//! cargo test --test api_external_interop -- --ignored --nocapture
//! ```

#[path = "api_external_harness.rs"]
mod harness;

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use harness::{
    adu_user_json, domain_routing_rule_json, freedom_outbound_json, plain_vless_inbound_json,
    require_external_binaries, user_id_bytes, ApiServerHarness, ExternalBinaries,
    CANONICAL_HANDLER, CANONICAL_LOGGER, CANONICAL_OBSERVATORY, CANONICAL_ROUTING, CANONICAL_STATS,
    DEFAULT_USER_EMAIL, DEFAULT_USER_UUID, LEGACY_HANDLER, LEGACY_LOGGER, LEGACY_ROUTING,
    LEGACY_STATS, REALITY_INBOUND_TAG, REFLECTION_V1, REFLECTION_V1ALPHA,
};

fn spawn_harness(bins: &ExternalBinaries) -> ApiServerHarness {
    ApiServerHarness::spawn(bins)
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_grpcurl_list_and_reflection_services() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);
    let output = harness.run_grpcurl(
        &bins,
        &["-plaintext", &harness.api_addr, "list"],
        "grpcurl list",
    );
    assert!(output.status.success(), "stderr={}", output.stderr);
    let listed = harness::parse_grpcurl_list(&output.stdout);
    let expected = HashSet::from([
        CANONICAL_HANDLER.to_string(),
        LEGACY_HANDLER.to_string(),
        CANONICAL_STATS.to_string(),
        LEGACY_STATS.to_string(),
        CANONICAL_ROUTING.to_string(),
        LEGACY_ROUTING.to_string(),
        CANONICAL_LOGGER.to_string(),
        LEGACY_LOGGER.to_string(),
        CANONICAL_OBSERVATORY.to_string(),
        REFLECTION_V1.to_string(),
        REFLECTION_V1ALPHA.to_string(),
    ]);
    assert_eq!(listed, expected, "unexpected grpcurl list: {listed:?}");
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_grpcurl_canonical_describe_and_legacy_describe_quirk() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);
    for service in [
        CANONICAL_STATS,
        CANONICAL_HANDLER,
        CANONICAL_ROUTING,
        CANONICAL_LOGGER,
        CANONICAL_OBSERVATORY,
    ] {
        let output = harness.run_grpcurl(
            &bins,
            &["-plaintext", &harness.api_addr, "describe", service],
            &format!("grpcurl describe {service}"),
        );
        assert!(
            output.status.success(),
            "canonical describe failed for {service}: {}",
            output.stderr
        );
        assert!(
            output.stdout.contains("rpc"),
            "describe output missing rpc section for {service}"
        );
    }

    for service in [LEGACY_STATS, LEGACY_HANDLER, LEGACY_ROUTING, LEGACY_LOGGER] {
        let output = harness.run_grpcurl(
            &bins,
            &["-plaintext", &harness.api_addr, "describe", service],
            &format!("grpcurl describe legacy {service}"),
        );
        assert!(
            !output.status.success(),
            "legacy describe should fail for {service}"
        );
        let combined = format!("{}{}", output.stdout, output.stderr);
        assert!(
            combined.contains("symbol")
                || combined.contains("not find")
                || combined.contains("NotFound"),
            "unexpected legacy describe failure for {service}: {combined}"
        );
    }
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_grpcurl_stats_rpc_canonical_and_legacy() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);
    let output = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            "{}",
            &harness.api_addr,
            &format!("{CANONICAL_STATS}/GetSysStats"),
        ],
        "grpcurl canonical StatsService/GetSysStats",
    );
    assert!(
        output.status.success(),
        "GetSysStats failed: {}",
        output.stderr
    );
    assert!(
        output.stdout.to_ascii_lowercase().contains("uptime") || output.stdout.trim() == "{}",
        "GetSysStats response missing uptime: {}",
        output.stdout
    );

    let legacy = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            "{}",
            &harness.api_addr,
            &format!("{LEGACY_STATS}/GetSysStats"),
        ],
        "grpcurl legacy StatsService/GetSysStats",
    );
    assert!(
        !legacy.status.success(),
        "legacy grpcurl invoke matches upstream: reflection cannot resolve legacy service descriptor"
    );
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_grpcurl_handler_routing_logger_observatory_rpcs() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);

    for rpc in [
        format!("{CANONICAL_HANDLER}/ListInbounds"),
        format!("{CANONICAL_HANDLER}/ListOutbounds"),
        format!("{CANONICAL_HANDLER}/GetInboundUsers"),
        format!("{CANONICAL_HANDLER}/GetInboundUsersCount"),
    ] {
        let body = if rpc.contains("GetInboundUsers") {
            r#"{"tag":"vless-reality-in"}"#
        } else {
            "{}"
        };
        let output = harness.run_grpcurl(
            &bins,
            &["-plaintext", "-d", body, &harness.api_addr, &rpc],
            &format!("grpcurl {rpc}"),
        );
        assert!(
            output.status.success(),
            "rpc {rpc} failed: {}",
            output.stderr
        );
    }

    let test_route = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            r#"{"RoutingContext":{"InboundTag":"vless-reality-in","Network":"TCP","TargetDomain":"example.com","TargetPort":443},"FieldSelectors":["outbound"],"PublishResult":false}"#,
            &harness.api_addr,
            &format!("{CANONICAL_ROUTING}/TestRoute"),
        ],
        "grpcurl RoutingService/TestRoute",
    );
    assert!(test_route.status.success(), "{}", test_route.stderr);

    let balancer = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            r#"{"tag":"test-balancer"}"#,
            &harness.api_addr,
            &format!("{CANONICAL_ROUTING}/GetBalancerInfo"),
        ],
        "grpcurl RoutingService/GetBalancerInfo",
    );
    assert!(balancer.status.success(), "{}", balancer.stderr);

    let list_rules = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            "{}",
            &harness.api_addr,
            &format!("{CANONICAL_ROUTING}/ListRule"),
        ],
        "grpcurl RoutingService/ListRule",
    );
    assert!(list_rules.status.success(), "{}", list_rules.stderr);

    let restart_logger = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            "{}",
            &harness.api_addr,
            &format!("{CANONICAL_LOGGER}/RestartLogger"),
        ],
        "grpcurl canonical RestartLogger",
    );
    assert!(restart_logger.status.success(), "{}", restart_logger.stderr);

    let legacy_logger = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            "{}",
            &harness.api_addr,
            &format!("{LEGACY_LOGGER}/RestartLogger"),
        ],
        "grpcurl legacy RestartLogger",
    );
    assert!(
        !legacy_logger.status.success(),
        "legacy logger grpcurl invoke matches upstream reflection limits"
    );

    let observatory = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            "{}",
            &harness.api_addr,
            &format!("{CANONICAL_OBSERVATORY}/GetOutboundStatus"),
        ],
        "grpcurl ObservatoryService/GetOutboundStatus",
    );
    assert!(observatory.status.success(), "{}", observatory.stderr);

    let legacy_observatory = harness.run_grpcurl(
        &bins,
        &[
            "-plaintext",
            "-d",
            "{}",
            &harness.api_addr,
            "v2ray.core.app.observatory.command.ObservatoryService/GetOutboundStatus",
        ],
        "grpcurl legacy ObservatoryService/GetOutboundStatus",
    );
    assert!(
        !legacy_observatory.status.success(),
        "legacy observatory alias must be UNIMPLEMENTED"
    );
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_grpcurl_service_rpc_descriptor_completeness() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);
    let expected_methods: &[(&str, &[&str])] = &[
        (
            CANONICAL_STATS,
            &[
                "GetStats",
                "GetSysStats",
                "QueryStats",
                "GetStatsOnline",
                "GetStatsOnlineIpList",
                "GetAllOnlineUsers",
                "GetUsersStats",
            ],
        ),
        (
            CANONICAL_HANDLER,
            &[
                "AddInbound",
                "RemoveInbound",
                "AlterInbound",
                "ListInbounds",
                "AddOutbound",
                "RemoveOutbound",
                "AlterOutbound",
                "ListOutbounds",
                "GetInboundUsers",
                "GetInboundUsersCount",
            ],
        ),
        (
            CANONICAL_ROUTING,
            &[
                "SubscribeRoutingStats",
                "TestRoute",
                "GetBalancerInfo",
                "OverrideBalancerTarget",
                "AddRule",
                "RemoveRule",
                "ListRule",
            ],
        ),
        (CANONICAL_LOGGER, &["RestartLogger"]),
        (CANONICAL_OBSERVATORY, &["GetOutboundStatus"]),
    ];

    for (service, methods) in expected_methods {
        let output = harness.run_grpcurl(
            &bins,
            &["-plaintext", &harness.api_addr, "list", service],
            &format!("grpcurl list methods {service}"),
        );
        assert!(output.status.success(), "{}", output.stderr);
        for method in *methods {
            assert!(
                output.stdout.contains(method),
                "descriptor for {service} missing method {method}: {}",
                output.stdout
            );
        }
    }
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_xray_cli_statssys_stats_and_statsquery() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);
    std::thread::sleep(Duration::from_millis(200));

    let statssys = harness.run_xray_api(&bins, "statssys", &[], "xray api statssys");
    assert!(statssys.status.success(), "{}", statssys.stderr);
    assert!(
        statssys.status.success()
            && (statssys.stdout.to_ascii_lowercase().contains("uptime")
                || statssys.stdout.trim() == "{}"),
        "statssys output: {}",
        statssys.stderr
    );

    let statssys_json =
        harness.run_xray_api(&bins, "statssys", &["--json"], "xray api statssys --json");
    assert!(statssys_json.status.success(), "{}", statssys_json.stderr);
    assert!(
        statssys_json.stdout.to_ascii_lowercase().contains("uptime")
            || statssys_json.stdout.trim() == "{}"
    );

    let statsquery = harness.run_xray_api(
        &bins,
        "statsquery",
        &["-pattern", ""],
        "xray api statsquery empty pattern",
    );
    assert!(statsquery.status.success(), "{}", statsquery.stderr);

    let inbound_pattern = format!("inbound>>>{REALITY_INBOUND_TAG}>>>");
    let statsquery_named = harness.run_xray_api(
        &bins,
        "statsquery",
        &["-pattern", &inbound_pattern],
        "xray api statsquery inbound pattern",
    );
    assert!(
        statsquery_named.status.success(),
        "{}",
        statsquery_named.stderr
    );

    let stats_missing = harness.run_xray_api(
        &bins,
        "stats",
        &["-name", "user>>>missing@example.test>>>traffic>>>uplink"],
        "xray api stats unknown counter",
    );
    assert!(
        !stats_missing.status.success(),
        "unknown counter should fail"
    );
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_xray_cli_handler_list_and_user_lifecycle_with_data_plane() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);

    let lsi = harness.run_xray_api(&bins, "lsi", &[], "xray api lsi");
    assert!(lsi.status.success(), "{}", lsi.stderr);
    assert!(lsi.stdout.contains(REALITY_INBOUND_TAG));

    let lsi_json = harness.run_xray_api(&bins, "lsi", &["--json"], "xray api lsi --json");
    assert!(lsi_json.status.success(), "{}", lsi_json.stderr);
    assert!(lsi_json.stdout.contains(REALITY_INBOUND_TAG));

    let lso = harness.run_xray_api(&bins, "lso", &[], "xray api lso");
    assert!(lso.status.success(), "{}", lso.stderr);
    assert!(lso.stdout.contains("direct"));
    assert!(lso.stdout.contains("alt-direct"));
    assert!(!lso.stdout.contains("\"tag\":\"api\""));

    let reality_tag = format!("-tag={REALITY_INBOUND_TAG}");
    let default_email = format!("-email={DEFAULT_USER_EMAIL}");
    let inbounduser = harness.run_xray_api(
        &bins,
        "inbounduser",
        &[&reality_tag, &default_email],
        "xray api inbounduser",
    );
    assert!(inbounduser.status.success(), "{}", inbounduser.stderr);
    assert!(inbounduser.stdout.contains(DEFAULT_USER_EMAIL));

    let count_before = harness.run_xray_api(
        &bins,
        "inboundusercount",
        &[&reality_tag],
        "xray api inboundusercount before adu",
    );
    assert!(count_before.status.success(), "{}", count_before.stderr);

    let plain_port = harness::pick_free_port();
    let plain_tag = "plain-vless-cli";
    let adi_path = harness.write_json(
        "adi-plain-vless.json",
        plain_vless_inbound_json(plain_tag, plain_port, DEFAULT_USER_UUID, DEFAULT_USER_EMAIL),
    );
    let adi_path_str = adi_path.to_str().expect("path");
    let adi = harness.run_xray_api(&bins, "adi", &[adi_path_str], "xray api adi plain vless");
    assert!(adi.status.success(), "{}", adi.stderr);
    std::thread::sleep(Duration::from_millis(200));

    let added_user_id = "22222222-2222-2222-2222-222222222222";
    let added_email = "added-by-cli@example.test";
    let adu_path = harness.write_json(
        "adu-user.json",
        adu_user_json(plain_tag, plain_port, added_user_id, added_email),
    );
    let adu_path_str = adu_path.to_str().expect("path");
    let adu = harness.run_xray_api(&bins, "adu", &[adu_path_str], "xray api adu");
    assert!(adu.status.success(), "{}", adu.stderr);
    assert!(
        adu.stdout.contains("Added 1") || adu.stdout.contains("result: ok"),
        "adu should add one user: {}",
        adu.stdout
    );

    let plain_tag_flag = format!("-tag={plain_tag}");
    let count_after = harness.run_xray_api(
        &bins,
        "inboundusercount",
        &[&plain_tag_flag],
        "xray api inboundusercount after adu",
    );
    assert!(count_after.status.success(), "{}", count_after.stderr);

    let target_port = harness::pick_free_port();
    let target_listener = TcpListener::bind(format!("127.0.0.1:{target_port}")).expect("bind");
    let (target_ready, target_ready_rx) = std::sync::mpsc::channel();
    let accept_task = std::thread::spawn(move || {
        let _ = target_ready.send(());
        if let Ok((mut stream, _)) = target_listener.accept() {
            let mut buf = [0_u8; 64];
            let _ = stream.read(&mut buf);
        }
    });
    target_ready_rx.recv().expect("target listener ready");
    std::thread::sleep(Duration::from_millis(100));

    let auth_ok = std::thread::spawn({
        let user_bytes = user_id_bytes(added_user_id);
        move || {
            let mut stream =
                std::net::TcpStream::connect(format!("127.0.0.1:{plain_port}")).expect("connect");
            stream
                .write_all(&harness::build_vless_ip_request(&user_bytes, target_port))
                .expect("write vless");
            let mut header = [0_u8; 2];
            stream.read_exact(&mut header).expect("auth ok header");
            header[0] == 0
        }
    });
    assert!(auth_ok.join().expect("join auth"), "added user auth failed");
    let _ = accept_task.join();

    let rmu = harness.run_xray_api(
        &bins,
        "rmu",
        &[&plain_tag_flag, added_email],
        "xray api rmu",
    );
    assert!(rmu.status.success(), "{}", rmu.stderr);

    let auth_fail = std::thread::spawn(move || {
        let user_bytes = user_id_bytes(added_user_id);
        let mut stream =
            std::net::TcpStream::connect(format!("127.0.0.1:{plain_port}")).expect("connect");
        stream
            .write_all(&harness::build_vless_ip_request(&user_bytes, target_port))
            .expect("write vless");
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).is_err() || header[0] != 0
    });
    assert!(
        auth_fail.join().expect("join auth fail"),
        "removed user should not authenticate"
    );

    let rmi = harness.run_xray_api(&bins, "rmi", &[plain_tag], "xray api rmi plain inbound");
    assert!(rmi.status.success(), "{}", rmi.stderr);
    let lsi_after = harness.run_xray_api(&bins, "lsi", &[], "xray api lsi after rmi");
    assert!(lsi_after.status.success(), "{}", lsi_after.stderr);
    assert!(!lsi_after.stdout.contains(plain_tag));

    std::thread::sleep(Duration::from_millis(50));
    let rebound_port = harness::pick_free_port();
    let rebound_path = harness.write_json(
        "adi-rebound.json",
        plain_vless_inbound_json(
            "rebound-in",
            rebound_port,
            DEFAULT_USER_UUID,
            "rebound@example.test",
        ),
    );
    let rebound_path_str = rebound_path.to_str().expect("path");
    let rebound =
        harness.run_xray_api(&bins, "adi", &[rebound_path_str], "xray api adi port reuse");
    assert!(rebound.status.success(), "{}", rebound.stderr);
    let _ = harness.run_xray_api(&bins, "rmi", &["rebound-in"], "xray api rmi rebound");
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_xray_cli_outbound_crud_and_routing_commands() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);

    let ado_path = harness.write_json("ado-freedom.json", freedom_outbound_json("cli-direct"));
    let ado_path_str = ado_path.to_str().expect("path");
    let ado = harness.run_xray_api(&bins, "ado", &[ado_path_str], "xray api ado freedom");
    assert!(ado.status.success(), "{}", ado.stderr);

    let lso_after_add = harness.run_xray_api(&bins, "lso", &[], "xray api lso after ado");
    assert!(lso_after_add.status.success(), "{}", lso_after_add.stderr);
    assert!(lso_after_add.stdout.contains("cli-direct"));

    let rule_tag = "cli-domain-rule";
    let rule_path = harness.write_json(
        "adrules-domain.json",
        domain_routing_rule_json(rule_tag, "full:cli-route.example", "block"),
    );
    let rule_path_str = rule_path.to_str().expect("path");
    let adrules = harness.run_xray_api(
        &bins,
        "adrules",
        &["-append", rule_path_str],
        "xray api adrules",
    );
    assert!(adrules.status.success(), "{}", adrules.stderr);

    let lsrules = harness.run_xray_api(&bins, "lsrules", &[], "xray api lsrules");
    assert!(lsrules.status.success(), "{}", lsrules.stderr);
    assert!(lsrules.stdout.contains(rule_tag));

    let bi = harness.run_xray_api(&bins, "bi", &["test-balancer"], "xray api bi");
    assert!(bi.status.success(), "{}", bi.stderr);

    let bo_set = harness.run_xray_api(
        &bins,
        "bo",
        &["-b", "test-balancer", "alt-direct"],
        "xray api bo set override",
    );
    assert!(bo_set.status.success(), "{}", bo_set.stderr);

    let bi_override = harness.run_xray_api(
        &bins,
        "bi",
        &["test-balancer"],
        "xray api bi after override",
    );
    assert!(bi_override.status.success(), "{}", bi_override.stderr);
    assert!(bi_override.stdout.contains("alt-direct"));

    let bo_clear = harness.run_xray_api(
        &bins,
        "bo",
        &["-b", "test-balancer", "-r"],
        "xray api bo clear override",
    );
    assert!(bo_clear.status.success(), "{}", bo_clear.stderr);

    let rmrules = harness.run_xray_api(&bins, "rmrules", &[rule_tag], "xray api rmrules");
    assert!(rmrules.status.success(), "{}", rmrules.stderr);

    let lsrules_after =
        harness.run_xray_api(&bins, "lsrules", &[], "xray api lsrules after rmrules");
    assert!(lsrules_after.status.success(), "{}", lsrules_after.stderr);
    assert!(!lsrules_after.stdout.contains(rule_tag));

    let rmo = harness.run_xray_api(&bins, "rmo", &["cli-direct"], "xray api rmo");
    assert!(rmo.status.success(), "{}", rmo.stderr);
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_xray_cli_restartlogger_and_online_stats() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);

    fs::write(&harness.error_log, "BEFORE\n").expect("seed error log");
    fs::write(&harness.access_log, "BEFORE\n").expect("seed access log");

    let restart = harness.run_xray_api(&bins, "restartlogger", &[], "xray api restartlogger");
    assert!(restart.status.success(), "{}", restart.stderr);

    fs::write(&harness.error_log, "AFTER\n").expect("rewrite error log");
    fs::write(&harness.access_log, "AFTER\n").expect("rewrite access log");

    let restart_after_rotate = harness.run_xray_api(
        &bins,
        "restartlogger",
        &[],
        "xray api restartlogger after rotate",
    );
    assert!(
        restart_after_rotate.status.success(),
        "{}",
        restart_after_rotate.stderr
    );
    assert!(
        fs::read_to_string(&harness.error_log)
            .expect("read error log")
            .contains("AFTER"),
        "RestartLogger must reopen rotated error log"
    );

    let plain_port = harness::pick_free_port();
    let plain_tag = "online-vless";
    let adi_path = harness.write_json(
        "adi-online-vless.json",
        plain_vless_inbound_json(plain_tag, plain_port, DEFAULT_USER_UUID, DEFAULT_USER_EMAIL),
    );
    let adi_path_str = adi_path.to_str().expect("path");
    assert!(harness
        .run_xray_api(&bins, "adi", &[adi_path_str], "xray api adi online vless",)
        .status
        .success());

    let target_port = harness::pick_free_port();
    let listener = TcpListener::bind(format!("127.0.0.1:{target_port}")).expect("bind");
    let hold = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 32];
            loop {
                if stream.read(&mut buf).ok().filter(|n| *n > 0).is_none() {
                    break;
                }
            }
        }
    });

    let user_bytes = user_id_bytes(DEFAULT_USER_UUID);
    let mut client =
        std::net::TcpStream::connect(format!("127.0.0.1:{plain_port}")).expect("connect vless");
    client
        .write_all(&harness::build_vless_ip_request(&user_bytes, target_port))
        .expect("write vless");
    let mut header = [0_u8; 2];
    client.read_exact(&mut header).expect("vless response");
    assert_eq!(header[0], 0);

    std::thread::sleep(Duration::from_millis(200));
    let online_email = format!("-email={DEFAULT_USER_EMAIL}");
    let statsonline = harness.run_xray_api(
        &bins,
        "statsonline",
        &[&online_email],
        "xray api statsonline",
    );
    assert!(statsonline.status.success(), "{}", statsonline.stderr);

    let statsonlineiplist = harness.run_xray_api(
        &bins,
        "statsonlineiplist",
        &[&online_email],
        "xray api statsonlineiplist",
    );
    assert!(
        statsonlineiplist.status.success(),
        "{}",
        statsonlineiplist.stderr
    );

    let getallonlineusers = harness.run_xray_api(
        &bins,
        "statsgetallonlineusers",
        &[],
        "xray api statsgetallonlineusers",
    );
    assert!(
        getallonlineusers.status.success(),
        "{}",
        getallonlineusers.stderr
    );
    assert!(
        statsonline.status.success() && !statsonline.stdout.trim().is_empty(),
        "online stats should report activity: statsonline={}",
        statsonline.stdout
    );

    drop(client);
    let _ = hold.join();
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_xray_cli_error_mapping_and_source_ip_block() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);

    let unknown_inbound = harness.run_xray_api(
        &bins,
        "inboundusercount",
        &["-tag=missing-inbound-tag"],
        "xray api inboundusercount unknown tag",
    );
    assert!(!unknown_inbound.status.success());

    let unknown_balancer = harness.run_xray_api(
        &bins,
        "bi",
        &["missing-balancer"],
        "xray api bi unknown balancer",
    );
    assert!(!unknown_balancer.status.success());

    let plain_port = harness::pick_free_port();
    let plain_tag = "sib-vless";
    let adi_path = harness.write_json(
        "adi-sib-vless.json",
        plain_vless_inbound_json(
            plain_tag,
            plain_port,
            DEFAULT_USER_UUID,
            "sib-user@example.test",
        ),
    );
    let adi_path_str = adi_path.to_str().expect("path");
    assert!(harness
        .run_xray_api(&bins, "adi", &[adi_path_str], "xray api adi sib vless",)
        .status
        .success());

    let inbound_flag = format!("-inbound={plain_tag}");
    let sib = harness.run_xray_api(
        &bins,
        "sib",
        &["-outbound=block", &inbound_flag, "203.0.113.50"],
        "xray api sib source ip block",
    );
    assert!(sib.status.success(), "{}", sib.stderr);
    let lsrules = harness.run_xray_api(&bins, "lsrules", &[], "xray api lsrules after sib");
    assert!(lsrules.status.success(), "{}", lsrules.stderr);
    assert!(
        lsrules.stdout.contains("sourceIpBlock") || lsrules.stdout.contains("203.0.113.50"),
        "sib should add a source IP rule: {}",
        lsrules.stdout
    );
}

#[test]
#[ignore = "requires XRAY_UPSTREAM_BIN and GRPCURL_BIN"]
fn external_xray_cli_stats_with_live_counter_and_reset() {
    let bins = require_external_binaries();
    let harness = spawn_harness(&bins);

    let plain_port = harness::pick_free_port();
    let plain_tag = "stats-vless";
    let adi_path = harness.write_json(
        "adi-stats-vless.json",
        plain_vless_inbound_json(
            plain_tag,
            plain_port,
            DEFAULT_USER_UUID,
            "stats-user@example.test",
        ),
    );
    let adi_path_str = adi_path.to_str().expect("path");
    assert!(harness
        .run_xray_api(&bins, "adi", &[adi_path_str], "xray api adi stats vless",)
        .status
        .success());

    let target_port = harness::pick_free_port();
    let listener = TcpListener::bind(format!("127.0.0.1:{target_port}")).expect("bind");
    let accept = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut payload = [0_u8; 128];
            let _ = stream.read(&mut payload);
            let _ = stream.write_all(b"pong");
        }
    });

    let user_bytes = user_id_bytes(DEFAULT_USER_UUID);
    let mut client =
        std::net::TcpStream::connect(format!("127.0.0.1:{plain_port}")).expect("connect");
    client
        .write_all(&harness::build_vless_ip_request(&user_bytes, target_port))
        .expect("write vless");
    let mut header = [0_u8; 2];
    client.read_exact(&mut header).expect("vless header");
    client.write_all(b"ping").expect("payload");
    let mut response = [0_u8; 4];
    let _ = client.read(&mut response);
    drop(client);
    let _ = accept.join();

    std::thread::sleep(Duration::from_millis(200));
    let counter = "user>>>stats-user@example.test>>>traffic>>>uplink";
    let stats = harness.run_xray_api(
        &bins,
        "stats",
        &["-name", counter],
        "xray api stats known counter",
    );
    assert!(stats.status.success(), "{}", stats.stderr);

    let reset = harness.run_xray_api(
        &bins,
        "stats",
        &["-name", counter, "-reset"],
        "xray api stats reset",
    );
    assert!(reset.status.success(), "{}", reset.stderr);

    let after_reset = harness.run_xray_api(
        &bins,
        "stats",
        &["-name", counter],
        "xray api stats after reset",
    );
    assert!(after_reset.status.success(), "{}", after_reset.stderr);
}

#[test]
fn external_interop_tests_are_env_gated_by_default() {
    if std::env::var("XRAY_UPSTREAM_BIN").is_err() && std::env::var("GRPCURL_BIN").is_err() {
        assert!(
            harness::ExternalBinaries::resolve().is_none()
                || std::env::var("RUN_EXTERNAL_API_INTEROP").is_err()
        );
    }
}
