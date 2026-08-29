use std::io::{Cursor, ErrorKind};

use crate::reality::post_handshake::UselessRecordTolerance;
use crate::reality::tls13::stream::{
    read_client_finished_tls_record_from_stream, ClientFinishedReadError,
};
use crate::reality::tls13::useless_records::{
    classify_record_before_client_finished, classify_record_on_application_stream,
    too_many_ignored_records_error, UselessRecordCounter, UselessRecordOverflow,
};
use crate::tls::records::{
    build_application_data_record, build_tls_record, TLS13_COMPATIBILITY_CCS_RECORD,
    TLS_LEGACY_VERSION_1_2, TLS_RECORD_ALERT, TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};
use crate::tls::TlsRecordContentType;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

async fn read_client_finished_io<S>(
    stream: &mut S,
    tolerance: UselessRecordTolerance,
) -> std::io::Result<crate::tls::TlsRecord>
where
    S: tokio::io::AsyncRead + Unpin,
{
    read_client_finished_tls_record_from_stream(stream, tolerance)
        .await
        .map_err(ClientFinishedReadError::into_io_error)
}

fn compatibility_ccs_record() -> Vec<u8> {
    TLS13_COMPATIBILITY_CCS_RECORD.to_vec()
}

fn finished_flight(ccs_count: usize) -> Vec<u8> {
    let mut input = Vec::new();
    for _ in 0..ccs_count {
        input.extend_from_slice(&compatibility_ccs_record());
    }
    let app_data = build_application_data_record(b"client-finished").expect("app data");
    input.extend_from_slice(&app_data);
    input
}

#[test]
fn counter_finite_one_accepts_first_rejects_second() {
    let mut counter = UselessRecordCounter::new(UselessRecordTolerance::Finite(1));
    counter.observe_useless().expect("first");
    let overflow = counter.observe_useless().unwrap_err();
    assert_eq!(overflow, UselessRecordOverflow { limit: 1 });
}

#[test]
fn counter_finite_sixteen_and_thirty_two_boundaries() {
    for (limit, tolerated) in [(16, 16), (32, 32)] {
        let mut counter = UselessRecordCounter::new(UselessRecordTolerance::Finite(limit));
        for _ in 0..tolerated {
            counter.observe_useless().expect("within limit");
        }
        let overflow = counter.observe_useless().unwrap_err();
        assert_eq!(overflow, UselessRecordOverflow { limit });
    }
}

#[test]
fn counter_unlimited_accepts_large_batch() {
    let mut counter = UselessRecordCounter::new(UselessRecordTolerance::Unlimited);
    for _ in 0..64 {
        counter.observe_useless().expect("unlimited");
    }
    assert_eq!(counter.consecutive(), 64);
}

#[test]
fn counter_resets_on_advancing_record() {
    let mut counter = UselessRecordCounter::new(UselessRecordTolerance::Finite(16));
    for _ in 0..16 {
        counter.observe_useless().expect("first run");
    }
    counter.observe_advancing();
    assert_eq!(counter.consecutive(), 0);
    for _ in 0..16 {
        counter.observe_useless().expect("second run");
    }
    let overflow = counter.observe_useless().unwrap_err();
    assert_eq!(overflow, UselessRecordOverflow { limit: 16 });
}

#[test]
fn malformed_ccs_never_counts_as_useless() {
    let invalid_payload = build_tls_record(
        TLS_RECORD_CHANGE_CIPHER_SPEC,
        TLS_LEGACY_VERSION_1_2,
        &[0x02],
    )
    .expect("record");
    let record = crate::tls::records::parse_tls_records(&invalid_payload)
        .expect("parse")
        .into_iter()
        .next()
        .expect("one record");
    let err = classify_record_before_client_finished(&record).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("invalid ChangeCipherSpec payload"));
}

#[test]
fn wrong_ccs_length_rejects() {
    let short = build_tls_record(TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_LEGACY_VERSION_1_2, &[])
        .expect("record");
    let record = crate::tls::records::parse_tls_records(&short)
        .expect("parse")
        .into_iter()
        .next()
        .expect("one record");
    assert!(classify_record_before_client_finished(&record).is_err());
}

#[test]
fn wrong_ccs_version_rejects() {
    let wrong_version =
        build_tls_record(TLS_RECORD_CHANGE_CIPHER_SPEC, [0x03, 0x04], &[0x01]).expect("record");
    let record = crate::tls::records::parse_tls_records(&wrong_version)
        .expect("parse")
        .into_iter()
        .next()
        .expect("one record");
    let err = classify_record_before_client_finished(&record).unwrap_err();
    assert!(err.to_string().contains("legacy version"));
}

#[test]
fn warning_alert_is_useless_before_finished() {
    let alert =
        build_tls_record(TLS_RECORD_ALERT, TLS_LEGACY_VERSION_1_2, &[0x01, 0x00]).expect("alert");
    let record = crate::tls::records::parse_tls_records(&alert)
        .expect("parse")
        .into_iter()
        .next()
        .expect("one record");
    assert!(classify_record_before_client_finished(&record).expect("classify"));
}

#[test]
fn fatal_user_canceled_is_useless_before_finished() {
    let alert =
        build_tls_record(TLS_RECORD_ALERT, TLS_LEGACY_VERSION_1_2, &[0x02, 0x5a]).expect("alert");
    let record = crate::tls::records::parse_tls_records(&alert)
        .expect("parse")
        .into_iter()
        .next()
        .expect("one record");
    assert!(classify_record_before_client_finished(&record).expect("classify"));
}

#[test]
fn application_stream_classifies_valid_ccs_as_useless() {
    let record = crate::tls::records::parse_tls_records(&compatibility_ccs_record())
        .expect("parse")
        .into_iter()
        .next()
        .expect("one record");
    assert!(classify_record_on_application_stream(&record).expect("classify"));
}

#[test]
fn read_client_finished_finite_one_matrix() {
    block_on(async {
        let tolerance = UselessRecordTolerance::Finite(1);
        let ok = read_client_finished_io(&mut Cursor::new(finished_flight(1)), tolerance)
            .await
            .expect("ccs+finished");
        assert_eq!(ok.content_type, TlsRecordContentType::ApplicationData);

        let err = read_client_finished_io(&mut Cursor::new(finished_flight(2)), tolerance)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("limit=1"));
    });
}

#[test]
fn read_client_finished_finite_sixteen_matrix() {
    block_on(async {
        let tolerance = UselessRecordTolerance::Finite(16);
        read_client_finished_io(&mut Cursor::new(finished_flight(16)), tolerance)
            .await
            .expect("16 ccs");

        let err = read_client_finished_io(&mut Cursor::new(finished_flight(17)), tolerance)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("limit=16"));
    });
}

#[test]
fn read_client_finished_finite_thirty_two_matrix() {
    block_on(async {
        let tolerance = UselessRecordTolerance::Finite(32);
        read_client_finished_io(&mut Cursor::new(finished_flight(32)), tolerance)
            .await
            .expect("32 ccs");

        let err = read_client_finished_io(&mut Cursor::new(finished_flight(33)), tolerance)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("limit=32"));
    });
}

#[test]
fn read_client_finished_unlimited_accepts_sixty_four() {
    block_on(async {
        read_client_finished_io(
            &mut Cursor::new(finished_flight(64)),
            UselessRecordTolerance::Unlimited,
        )
        .await
        .expect("64 ccs");
    });
}

#[test]
fn read_client_finished_rejects_unexpected_handshake_record() {
    block_on(async {
        let handshake = build_tls_record(TLS_RECORD_HANDSHAKE, TLS_LEGACY_VERSION_1_2, &[0x01])
            .expect("handshake");
        let err =
            read_client_finished_io(&mut Cursor::new(handshake), UselessRecordTolerance::DEFAULT)
                .await
                .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    });
}

#[test]
fn too_many_error_message_matches_upstream_shape() {
    let err = too_many_ignored_records_error(32);
    assert!(err.to_string().contains("too many ignored records"));
    assert!(err.to_string().contains("limit=32"));
}
