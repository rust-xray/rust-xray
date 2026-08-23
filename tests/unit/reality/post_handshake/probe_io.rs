use crate::reality::post_handshake::probe_io::{
    build_fatal_unexpected_message_alert_record, InboundAlertObserver, OutgoingTlsRecordBuffer,
};
use crate::tls::records::TLS13_COMPATIBILITY_CCS_RECORD;

#[test]
fn outgoing_buffer_splits_coalesced_ccs_and_app_data() {
    let mut buf = OutgoingTlsRecordBuffer::default();
    let mut coalesced = Vec::new();
    coalesced.extend_from_slice(&TLS13_COMPATIBILITY_CCS_RECORD);
    coalesced.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03]);
    buf.push_chunk(&coalesced);

    let first = buf.pop_complete_record().expect("ccs record");
    assert_eq!(first, TLS13_COMPATIBILITY_CCS_RECORD.as_slice());

    let second = buf.pop_complete_record().expect("app data record");
    assert_eq!(second.len(), 8);
    assert_eq!(second[0], 0x17);
}

#[test]
fn outgoing_buffer_handles_split_header_and_payload() {
    let mut buf = OutgoingTlsRecordBuffer::default();
    buf.push_chunk(&TLS13_COMPATIBILITY_CCS_RECORD[..3]);
    assert!(buf.pop_complete_record().is_none());
    buf.push_chunk(&TLS13_COMPATIBILITY_CCS_RECORD[3..]);

    let record = buf.pop_complete_record().expect("complete after split");
    assert_eq!(record, TLS13_COMPATIBILITY_CCS_RECORD.as_slice());
}

#[test]
fn alert_observer_detects_valid_alert_record_only() {
    let mut observer = InboundAlertObserver::default();
    observer.begin_observation();

    let alert = build_fatal_unexpected_message_alert_record();
    observer.ingest(&alert);
    assert!(observer.alert_seen_in_current_observation());
}

#[test]
fn alert_observer_ignores_bare_0x15_byte() {
    let mut observer = InboundAlertObserver::default();
    observer.begin_observation();
    observer.ingest(&[0x15, 0x03]);
    assert!(!observer.alert_seen_in_current_observation());
}

#[test]
fn alert_observer_detects_fragmented_alert_after_reassembly() {
    let mut observer = InboundAlertObserver::default();
    observer.begin_observation();
    let alert = build_fatal_unexpected_message_alert_record();
    observer.ingest(&alert[..4]);
    assert!(!observer.alert_seen_in_current_observation());
    observer.ingest(&alert[4..]);
    assert!(observer.alert_seen_in_current_observation());
}

#[test]
fn alert_observer_coalesced_records_with_leading_app_data() {
    let mut observer = InboundAlertObserver::default();
    observer.begin_observation();

    let mut chunk = vec![0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
    chunk.extend_from_slice(&build_fatal_unexpected_message_alert_record());
    observer.ingest(&chunk);
    assert!(observer.alert_seen_in_current_observation());
}

#[test]
fn fragmented_alert_must_arrive_within_same_observation_window() {
    let mut observer = InboundAlertObserver::default();
    observer.begin_observation();
    let alert = build_fatal_unexpected_message_alert_record();
    observer.ingest(&alert[..4]);
    observer.end_observation();

    observer.begin_observation();
    observer.ingest(&alert[4..]);
    assert!(!observer.alert_seen_in_current_observation());
}

#[test]
fn late_alert_after_end_observation_does_not_count_for_new_batch() {
    let mut observer = InboundAlertObserver::default();
    observer.begin_observation();
    observer.end_observation();

    let alert = build_fatal_unexpected_message_alert_record();
    observer.ingest(&alert);

    observer.begin_observation();
    assert!(!observer.alert_seen_in_current_observation());
}
