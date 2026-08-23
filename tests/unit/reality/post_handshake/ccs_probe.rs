use crate::reality::{
    build_extra_ccs_probe_payload, CcsProbeStage, CcsProbeStep, CcsToleranceProbe,
    UselessRecordTolerance, CCS_PROBE_CUMULATIVE_SENT, CCS_PROBE_INCREMENTAL_BATCHES,
    CCS_PROBE_RESULTS_ON_ALERT,
};
use crate::tls::records::TLS13_COMPATIBILITY_CCS_RECORD;

fn send_pending_batch(probe: &mut CcsToleranceProbe) -> usize {
    let count = probe.pending_batch_count().expect("expected pending batch");
    probe.record_batch_sent();
    count
}

#[test]
fn incremental_batches_are_two_fifteen_sixteen() {
    assert_eq!(CCS_PROBE_INCREMENTAL_BATCHES.as_slice(), &[2, 15, 16]);
}

#[test]
fn cumulative_sent_is_two_seventeen_thirty_three() {
    assert_eq!(CCS_PROBE_CUMULATIVE_SENT.as_slice(), &[2, 17, 33]);
}

#[test]
fn alert_results_map_to_one_sixteen_thirty_two() {
    assert_eq!(
        CCS_PROBE_RESULTS_ON_ALERT.as_slice(),
        &[
            UselessRecordTolerance::Finite(1),
            UselessRecordTolerance::Finite(16),
            UselessRecordTolerance::Finite(32),
        ]
    );
}

#[test]
fn alert_after_first_batch_yields_finite_one() {
    let mut probe = CcsToleranceProbe::new();
    assert_eq!(probe.pending_batch_count(), Some(2));
    assert_eq!(send_pending_batch(&mut probe), 2);
    assert_eq!(probe.cumulative_sent(), 2);

    let result = probe.observe_alert();
    assert_eq!(result, UselessRecordTolerance::Finite(1));
    assert!(probe.is_complete());
    assert_eq!(probe.stage(), CcsProbeStage::Complete);
}

#[test]
fn alert_after_second_batch_yields_finite_sixteen() {
    let mut probe = CcsToleranceProbe::new();
    assert_eq!(send_pending_batch(&mut probe), 2);
    assert_eq!(probe.observe_no_alert(), CcsProbeStep::SendBatch(15));

    assert_eq!(send_pending_batch(&mut probe), 15);
    assert_eq!(probe.cumulative_sent(), 17);

    let result = probe.observe_alert();
    assert_eq!(result, UselessRecordTolerance::Finite(16));
    assert!(probe.is_complete());
}

#[test]
fn alert_after_third_batch_yields_finite_thirty_two() {
    let mut probe = CcsToleranceProbe::new();
    assert_eq!(send_pending_batch(&mut probe), 2);
    assert_eq!(probe.observe_no_alert(), CcsProbeStep::SendBatch(15));
    assert_eq!(send_pending_batch(&mut probe), 15);
    assert_eq!(probe.observe_no_alert(), CcsProbeStep::SendBatch(16));

    assert_eq!(send_pending_batch(&mut probe), 16);
    assert_eq!(probe.cumulative_sent(), 33);

    let result = probe.observe_alert();
    assert_eq!(result, UselessRecordTolerance::Finite(32));
    assert!(probe.is_complete());
}

#[test]
fn no_alerts_through_all_batches_yields_unlimited() {
    let mut probe = CcsToleranceProbe::new();
    assert_eq!(send_pending_batch(&mut probe), 2);
    assert_eq!(probe.observe_no_alert(), CcsProbeStep::SendBatch(15));
    assert_eq!(send_pending_batch(&mut probe), 15);
    assert_eq!(probe.observe_no_alert(), CcsProbeStep::SendBatch(16));
    assert_eq!(send_pending_batch(&mut probe), 16);
    assert_eq!(probe.cumulative_sent(), 33);

    assert_eq!(
        probe.observe_no_alert(),
        CcsProbeStep::Complete(UselessRecordTolerance::Unlimited)
    );
    assert!(probe.is_complete());
    assert_eq!(probe.result(), Some(UselessRecordTolerance::Unlimited));
}

#[test]
fn extra_ccs_payload_repeats_compatibility_record() {
    let payload = build_extra_ccs_probe_payload(3);
    let expected = [
        TLS13_COMPATIBILITY_CCS_RECORD.as_slice(),
        TLS13_COMPATIBILITY_CCS_RECORD.as_slice(),
        TLS13_COMPATIBILITY_CCS_RECORD.as_slice(),
    ]
    .concat();
    assert_eq!(payload, expected);
}

#[test]
fn full_happy_path_batch_sequence() {
    let mut probe = CcsToleranceProbe::new();
    let mut batches = Vec::new();

    for expected in CCS_PROBE_INCREMENTAL_BATCHES {
        let count = probe.pending_batch_count().expect("pending batch");
        assert_eq!(count, expected);
        batches.push(count);
        probe.record_batch_sent();
        if expected != 16 {
            assert!(matches!(
                probe.observe_no_alert(),
                CcsProbeStep::SendBatch(_)
            ));
        }
    }

    assert_eq!(batches, vec![2, 15, 16]);
    assert_eq!(probe.cumulative_sent(), 33);
    assert_eq!(
        probe.observe_no_alert(),
        CcsProbeStep::Complete(UselessRecordTolerance::Unlimited)
    );
}
