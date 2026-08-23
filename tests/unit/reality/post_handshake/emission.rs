use std::io::Cursor;

use crate::protocol::structs::{ClientExtension, ProtocolName, SessionId};
use crate::reality::post_handshake::alpn::RealityAlpnProfile;
use crate::reality::post_handshake::cache::{PostHandshakeProbeCache, PostHandshakeProbeKey};
use crate::reality::post_handshake::emission::{
    emit_post_handshake_camouflage_records, post_handshake_probe_key,
    resolve_ccs_tolerance_from_cache, resolve_post_handshake_wire_lengths_from_cache,
};
use crate::reality::post_handshake::sanitize_post_handshake_wire_lengths;
use crate::reality::target_server_flight::ObservedTargetTls13ServerFlight;
use crate::reality::tls13::cipher_suite::resolve_tls13_cipher_suite;
use crate::reality::tls13::record_crypto::{
    minimum_tls13_encrypted_application_record_wire_len, parse_tls13_application_inner_plaintext,
    Tls13RecordDecryptor, Tls13RecordEncryptor,
};
use crate::reality::tls13::state::{assemble_server_handshake_flight_out, RealityTls13ServerState};
use crate::reality::tls13::{derive_traffic_key, TLS_AES_128_GCM_SHA256};
use crate::reality::{CcsToleranceProbeCache, RealityCertificatePatchMode, UselessRecordTolerance};
use crate::tls::records::{
    build_handshake_record, parse_tls_records, TlsRecordContentType, TLS_RECORD_APPLICATION_DATA,
    TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};

use super::position6_camouflage::{flight_with_encrypted_lens, flight_with_position6};
use super::{
    build_valid_client_finished_message, build_valid_client_hybrid_share,
    client_hello_with_hybrid_keyshare, client_hello_with_x25519_keyshare, sample_accepted,
    sample_client_hello_handshake_message, valid_observed_hybrid_server_hello,
    valid_observed_server_hello, X25519_MLKEM768_SERVER_KEY_SHARE_LEN,
};

fn client_hello_with_alpn_offers(offers: &[&str]) -> crate::protocol::structs::ClientHelloPayload {
    let client_key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut client_hello =
        client_hello_with_x25519_keyshare(client_key.to_vec(), SessionId::empty());
    if !offers.is_empty() {
        client_hello.extensions.push(ClientExtension::Protocols(
            offers
                .iter()
                .map(|offer| ProtocolName::from(offer.as_bytes().to_vec()))
                .collect(),
        ));
    }
    client_hello
}

fn state_after_client_finished(
    flight: ObservedTargetTls13ServerFlight,
    client_hello: &crate::protocol::structs::ClientHelloPayload,
    observed: crate::reality::handshake::RealityObservedServerHello,
) -> RealityTls13ServerState {
    let mut state =
        RealityTls13ServerState::new(sample_accepted(), observed, flight).expect("valid state");
    state
        .prepare_server_hello(client_hello)
        .expect("ServerHello");
    let transcript_hash = state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("transcript");
    state
        .derive_handshake_secrets(&transcript_hash)
        .expect("handshake secrets");
    let _ = state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("encrypted flight");
    let client_finished = build_valid_client_finished_message(&state);
    assert!(state
        .verify_client_finished_message(&client_finished)
        .expect("verify"));
    state.derive_application_secrets().expect("app secrets");
    state
}

fn server_write_encryptor(state: &RealityTls13ServerState) -> Tls13RecordEncryptor {
    let application_secrets = state.application_secrets.as_ref().expect("app secrets");
    let write_keys = derive_traffic_key(
        state.suite,
        &application_secrets.server_application_traffic_secret,
    )
    .expect("write keys");
    let mut encryptor = Tls13RecordEncryptor::with_traffic_secret(
        state.suite,
        write_keys,
        application_secrets
            .server_application_traffic_secret
            .clone(),
    )
    .expect("encryptor");
    encryptor.sequence = state.server_application_write_sequence;
    encryptor
}

#[tokio::test]
async fn ready_empty_cache_emits_no_records() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = state_after_client_finished(
        flight_with_encrypted_lens(200, 900, 320, 128),
        &client_hello,
        observed,
    );
    let mut encryptor = server_write_encryptor(&state);
    let mut sink = Cursor::new(Vec::new());

    emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &[])
        .await
        .expect("emit");

    assert!(sink.get_ref().is_empty());
    assert_eq!(encryptor.sequence, 0);
}

#[tokio::test]
async fn ready_single_length_emits_one_record() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = state_after_client_finished(
        flight_with_encrypted_lens(200, 900, 320, 128),
        &client_hello,
        observed,
    );
    let target_len = 180;
    let mut encryptor = server_write_encryptor(&state);
    let mut sink = Cursor::new(Vec::new());

    emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &[target_len])
        .await
        .expect("emit");

    let parsed = parse_tls_records(sink.get_ref()).expect("records");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].raw.len(), target_len);
    assert_eq!(encryptor.sequence, 1);
}

#[tokio::test]
async fn ready_multiple_lengths_emit_exact_sequence() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = state_after_client_finished(
        flight_with_encrypted_lens(200, 900, 320, 128),
        &client_hello,
        observed,
    );
    let lengths = vec![120, 180, 256];
    let mut encryptor = server_write_encryptor(&state);
    let mut sink = Cursor::new(Vec::new());

    emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &lengths)
        .await
        .expect("emit");

    let parsed = parse_tls_records(sink.get_ref()).expect("records");
    assert_eq!(
        parsed
            .iter()
            .map(|record| record.raw.len())
            .collect::<Vec<_>>(),
        lengths
    );
    assert_eq!(encryptor.sequence, 3);
}

#[tokio::test]
async fn without_position6_first_record_uses_sequence_zero() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = state_after_client_finished(
        flight_with_encrypted_lens(200, 900, 320, 128),
        &client_hello,
        observed,
    );
    assert_eq!(state.server_application_write_sequence, 0);

    let mut encryptor = server_write_encryptor(&state);
    let mut sink = Cursor::new(Vec::new());
    emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &[180])
        .await
        .expect("emit");

    let record = parse_tls_records(sink.get_ref())
        .expect("records")
        .into_iter()
        .next()
        .expect("one record");
    let application_secrets = state.application_secrets.as_ref().expect("app secrets");
    let write_keys = derive_traffic_key(
        state.suite,
        &application_secrets.server_application_traffic_secret,
    )
    .expect("keys");
    let mut decryptor = Tls13RecordDecryptor::new(state.suite, write_keys).expect("decryptor");
    let inner = decryptor
        .decrypt_record_payload(&record)
        .expect("seq 0 decrypt");
    assert!(parse_tls13_application_inner_plaintext(&inner)
        .expect("inner")
        .is_empty());
    assert_eq!(encryptor.sequence, 1);
}

#[tokio::test]
async fn with_position6_first_record_uses_sequence_one() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = state_after_client_finished(
        flight_with_position6(200, 900, 320, 128, 160),
        &client_hello,
        observed,
    );
    assert_eq!(state.server_application_write_sequence, 1);

    let mut encryptor = server_write_encryptor(&state);
    let mut sink = Cursor::new(Vec::new());
    emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &[180])
        .await
        .expect("emit");

    let record = parse_tls_records(sink.get_ref())
        .expect("records")
        .into_iter()
        .next()
        .expect("one record");
    let application_secrets = state.application_secrets.as_ref().expect("app secrets");
    let write_keys = derive_traffic_key(
        state.suite,
        &application_secrets.server_application_traffic_secret,
    )
    .expect("keys");
    let mut seq0 = Tls13RecordDecryptor::new(state.suite, write_keys.clone()).expect("decryptor");
    assert!(seq0.decrypt_record_payload(&record).is_err());

    let mut seq1 = Tls13RecordDecryptor::new(state.suite, write_keys).expect("decryptor");
    seq1.sequence = 1;
    let inner = seq1.decrypt_record_payload(&record).expect("seq 1 decrypt");
    assert!(parse_tls13_application_inner_plaintext(&inner)
        .expect("inner")
        .is_empty());
}

#[tokio::test]
async fn subsequent_application_data_uses_correct_sequence_offset() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = state_after_client_finished(
        flight_with_encrypted_lens(200, 900, 320, 128),
        &client_hello,
        observed,
    );
    let cached = vec![140, 200];
    let mut encryptor = server_write_encryptor(&state);
    let mut sink = Cursor::new(Vec::new());
    emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &cached)
        .await
        .expect("emit");
    assert_eq!(encryptor.sequence, 2);

    let vless_payload = b"vless-probe";
    let app_record = encryptor
        .encrypt_application_data(vless_payload)
        .expect("app record");
    let application_secrets = state.application_secrets.as_ref().expect("app secrets");
    let write_keys = derive_traffic_key(
        state.suite,
        &application_secrets.server_application_traffic_secret,
    )
    .expect("keys");
    let mut decryptor = Tls13RecordDecryptor::new(state.suite, write_keys).expect("decryptor");
    decryptor.sequence = 2;
    let inner = decryptor
        .decrypt_record_payload(&parse_tls_records(&app_record).expect("parse")[0])
        .expect("seq 2 decrypt");
    let plaintext = parse_tls13_application_inner_plaintext(&inner).expect("inner");
    assert_eq!(plaintext, vless_payload);
}

#[tokio::test]
async fn emission_does_not_change_transcript() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = state_after_client_finished(
        flight_with_encrypted_lens(200, 900, 320, 128),
        &client_hello,
        observed,
    );
    let before = state.transcript.digest();
    let mut encryptor = server_write_encryptor(&state);
    let mut sink = Cursor::new(Vec::new());
    emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &[180, 220])
        .await
        .expect("emit");
    assert_eq!(state.transcript.digest(), before);
}

#[test]
fn invalid_client_finished_skips_post_handshake_emission_prerequisites() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let mut state = RealityTls13ServerState::new(
        sample_accepted(),
        observed,
        flight_with_encrypted_lens(200, 900, 320, 128),
    )
    .expect("valid state");
    state
        .prepare_server_hello(&client_hello)
        .expect("ServerHello");
    let transcript_hash = state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("transcript");
    state
        .derive_handshake_secrets(&transcript_hash)
        .expect("handshake secrets");
    let _ = state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("encrypted flight");

    let transcript_before = state.transcript.digest();
    let mut invalid_finished = build_valid_client_finished_message(&state);
    invalid_finished[7] ^= 0x01;

    let verified = state
        .verify_client_finished_message(&invalid_finished)
        .expect("verify result");
    assert!(!verified);
    assert!(state.application_secrets.is_none());
    assert_eq!(state.transcript.digest(), transcript_before);
}

#[test]
fn probe_key_classifies_alpn_profiles() {
    let dest = "example.com:443";
    let sni = "example.com";

    let none = post_handshake_probe_key(dest, sni, &client_hello_with_alpn_offers(&[]));
    assert_eq!(none.alpn_profile, RealityAlpnProfile::None);

    let http11 = post_handshake_probe_key(dest, sni, &client_hello_with_alpn_offers(&["http/1.1"]));
    assert_eq!(http11.alpn_profile, RealityAlpnProfile::Http11);

    let h2 = post_handshake_probe_key(
        dest,
        sni,
        &client_hello_with_alpn_offers(&["h2", "http/1.1"]),
    );
    assert_eq!(h2.alpn_profile, RealityAlpnProfile::H2);
}

#[tokio::test]
async fn cache_detecting_waiter_receives_ready_lengths() {
    let cache = PostHandshakeProbeCache::new();
    let key = PostHandshakeProbeKey {
        dest_addr: "127.0.0.1:443".to_string(),
        server_name: "example.com".to_string(),
        alpn_profile: RealityAlpnProfile::Http11,
    };
    assert!(cache.try_begin_detection(key.clone()));

    let cache_bg = cache.clone();
    let key_bg = key.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        cache_bg.complete_detection(&key_bg, vec![150]);
    });

    let resolved = resolve_post_handshake_wire_lengths_from_cache(&cache, &key).await;
    assert_eq!(resolved, vec![150]);
}

#[tokio::test]
async fn cache_failure_empty_allows_connection_to_continue() {
    let cache = PostHandshakeProbeCache::new();
    let key = PostHandshakeProbeKey {
        dest_addr: "127.0.0.1:443".to_string(),
        server_name: "example.com".to_string(),
        alpn_profile: RealityAlpnProfile::None,
    };
    assert!(cache.try_begin_detection(key.clone()));
    cache.complete_detection_empty(&key);

    let resolved = resolve_post_handshake_wire_lengths_from_cache(&cache, &key).await;
    assert!(resolved.is_empty());
}

#[tokio::test]
async fn x25519_post_handshake_emission_unaffected_by_key_exchange() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let state = state_after_client_finished(
        flight_with_encrypted_lens(200, 900, 320, 128),
        &client_hello,
        observed,
    );
    let mut encryptor = server_write_encryptor(&state);
    let mut sink = Cursor::new(Vec::new());
    emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &[180])
        .await
        .expect("emit");
    assert_eq!(parse_tls_records(sink.get_ref()).expect("records").len(), 1);
}

#[tokio::test]
async fn hybrid_post_handshake_emission_with_and_without_position6() {
    let (client_hybrid, _, _) = build_valid_client_hybrid_share();
    let client_hello = client_hello_with_hybrid_keyshare(client_hybrid);
    let observed = valid_observed_hybrid_server_hello(
        TLS_AES_128_GCM_SHA256,
        &[0x44; X25519_MLKEM768_SERVER_KEY_SHARE_LEN],
    );

    for position6 in [false, true] {
        let flight = if position6 {
            flight_with_position6(200, 900, 320, 128, 160)
        } else {
            flight_with_encrypted_lens(200, 900, 320, 128)
        };
        let state = state_after_client_finished(flight, &client_hello, observed.clone());
        let expected_initial_seq = u64::from(position6);
        assert_eq!(
            state.server_application_write_sequence,
            expected_initial_seq
        );

        let mut encryptor = server_write_encryptor(&state);
        let mut sink = Cursor::new(Vec::new());
        emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, &[200])
            .await
            .expect("emit");
        assert_eq!(encryptor.sequence, expected_initial_seq + 1);
    }
}

#[test]
fn invalid_cached_lengths_are_skipped_at_insertion() {
    let sanitized = sanitize_post_handshake_wire_lengths(vec![180, 4, 200]);
    assert_eq!(sanitized, vec![180, 200]);

    let suite = resolve_tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("suite");
    let min_wire = minimum_tls13_encrypted_application_record_wire_len(suite, 0).expect("min wire");
    assert!(min_wire > 4);
}

#[tokio::test]
async fn application_sequence_matrix_after_stage5a_and_stage5b() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let cache_lens = [120_usize, 140, 160];

    let cases: &[(bool, &[usize], u64)] = &[
        (false, &[], 0),
        (true, &[], 1),
        (false, &cache_lens, 3),
        (true, &cache_lens, 4),
    ];

    for &(position6, lengths, expected_seq) in cases {
        let flight = if position6 {
            flight_with_position6(200, 900, 320, 128, 160)
        } else {
            flight_with_encrypted_lens(200, 900, 320, 128)
        };
        let state = state_after_client_finished(flight, &client_hello, observed.clone());
        assert_eq!(
            state.server_application_write_sequence,
            u64::from(position6),
            "position6={position6}"
        );

        let mut encryptor = server_write_encryptor(&state);
        let mut sink = Cursor::new(Vec::new());
        emit_post_handshake_camouflage_records(&mut sink, state.suite, &mut encryptor, lengths)
            .await
            .expect("emit");
        assert_eq!(
            encryptor.sequence,
            expected_seq,
            "position6={position6} cache_len={}",
            lengths.len()
        );
    }
}

#[tokio::test]
async fn accepted_path_emission_order_server_flight_then_stage5b_then_application() {
    let client_hello = client_hello_with_x25519_keyshare([0x22; 32].to_vec(), SessionId::empty());
    let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
    let flight = flight_with_position6(200, 900, 320, 128, 160);

    let mut state =
        RealityTls13ServerState::new(sample_accepted(), observed, flight).expect("valid state");
    state
        .prepare_server_hello(&client_hello)
        .expect("ServerHello");
    let transcript_hash = state
        .update_transcript_client_server_hello(&sample_client_hello_handshake_message())
        .expect("transcript");
    state
        .derive_handshake_secrets(&transcript_hash)
        .expect("handshake secrets");
    let server_hello_record =
        build_handshake_record(state.server_hello_message.as_ref().expect("sh")).expect("record");
    let encrypted = state
        .build_encrypted_server_handshake_records(RealityCertificatePatchMode::HmacOnly)
        .expect("encrypted flight");
    let server_flight = assemble_server_handshake_flight_out(&server_hello_record, &encrypted);

    let client_finished = build_valid_client_finished_message(&state);
    assert!(state
        .verify_client_finished_message(&client_finished)
        .expect("verify"));
    let transcript_after_client_finished = state.transcript.digest();
    state.derive_application_secrets().expect("app secrets");

    let mut encryptor = server_write_encryptor(&state);
    let mut stage5b = Cursor::new(Vec::new());
    let stage5b_lengths = [140_usize, 180];
    emit_post_handshake_camouflage_records(
        &mut stage5b,
        state.suite,
        &mut encryptor,
        &stage5b_lengths,
    )
    .await
    .expect("stage5b emit");
    let vless_record = encryptor
        .encrypt_application_data(b"vless-after-stage5b")
        .expect("application record");

    let server_records = parse_tls_records(&server_flight).expect("server flight");
    assert_eq!(server_records.len(), 7, "SH+CCS+EE+Cert+CV+Fin+position6");
    assert_eq!(
        server_records[0].content_type,
        TlsRecordContentType::Handshake
    );
    assert_eq!(
        server_records[1].content_type,
        TlsRecordContentType::ChangeCipherSpec
    );
    assert_eq!(
        server_records[2].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(
        server_records[3].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(
        server_records[4].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(
        server_records[5].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(
        server_records[6].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(server_records[6].raw.len(), 160);

    let stage5b_records = parse_tls_records(stage5b.get_ref()).expect("stage5b records");
    assert_eq!(stage5b_records.len(), stage5b_lengths.len());
    assert!(stage5b_records
        .iter()
        .all(|record| record.content_type == TlsRecordContentType::ApplicationData));
    assert_eq!(
        stage5b_records
            .iter()
            .map(|record| record.raw.len())
            .collect::<Vec<_>>(),
        stage5b_lengths.to_vec()
    );

    let app_records = parse_tls_records(&vless_record).expect("vless record");
    assert_eq!(app_records.len(), 1);
    assert_eq!(
        app_records[0].content_type,
        TlsRecordContentType::ApplicationData
    );
    assert_eq!(
        encryptor.sequence, 4,
        "position6 + two stage5b records + app"
    );

    let application_secrets = state.application_secrets.as_ref().expect("app secrets");
    let write_keys = derive_traffic_key(
        state.suite,
        &application_secrets.server_application_traffic_secret,
    )
    .expect("keys");
    let mut decryptor = Tls13RecordDecryptor::new(state.suite, write_keys).expect("decryptor");
    decryptor.sequence = 3;
    let inner = decryptor
        .decrypt_record_payload(&app_records[0])
        .expect("seq 3 decrypt");
    assert_eq!(
        parse_tls13_application_inner_plaintext(&inner).expect("inner"),
        b"vless-after-stage5b"
    );
    assert_eq!(
        state.transcript.digest(),
        transcript_after_client_finished,
        "Stage5B emission must not alter transcript"
    );

    assert_eq!(server_records[0].raw[0], TLS_RECORD_HANDSHAKE);
    assert_eq!(server_records[1].raw[0], TLS_RECORD_CHANGE_CIPHER_SPEC);
    assert!(server_records[2..=6]
        .iter()
        .all(|record| record.raw[0] == TLS_RECORD_APPLICATION_DATA));
}

#[tokio::test]
async fn ccs_cache_ready_tiers_resolve_for_connection() {
    let key = PostHandshakeProbeKey {
        dest_addr: "example.com:443".to_string(),
        server_name: "example.com".to_string(),
        alpn_profile: RealityAlpnProfile::Http11,
    };

    for tolerance in [
        UselessRecordTolerance::Finite(1),
        UselessRecordTolerance::Finite(16),
        UselessRecordTolerance::Finite(32),
        UselessRecordTolerance::Unlimited,
    ] {
        let cache = CcsToleranceProbeCache::new();
        assert!(cache.try_begin_detection(key.clone()));
        cache.complete_detection(&key, tolerance);
        assert_eq!(
            resolve_ccs_tolerance_from_cache(&cache, &key).await,
            tolerance
        );
    }
}

#[tokio::test]
async fn ccs_cache_detecting_missing_and_failed_default_to_thirty_two() {
    let key = PostHandshakeProbeKey {
        dest_addr: "127.0.0.1:443".to_string(),
        server_name: "example.com".to_string(),
        alpn_profile: RealityAlpnProfile::None,
    };

    let missing = CcsToleranceProbeCache::new();
    assert_eq!(
        resolve_ccs_tolerance_from_cache(&missing, &key).await,
        UselessRecordTolerance::DEFAULT
    );

    let detecting = CcsToleranceProbeCache::new();
    assert!(detecting.try_begin_detection(key.clone()));
    assert_eq!(
        resolve_ccs_tolerance_from_cache(&detecting, &key).await,
        UselessRecordTolerance::DEFAULT
    );

    let failed = CcsToleranceProbeCache::new();
    assert!(failed.try_begin_detection(key.clone()));
    failed.complete_detection_failed(&key);
    assert_eq!(
        resolve_ccs_tolerance_from_cache(&failed, &key).await,
        UselessRecordTolerance::DEFAULT
    );
}
