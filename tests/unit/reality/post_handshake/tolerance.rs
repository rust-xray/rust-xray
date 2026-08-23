use crate::reality::UselessRecordTolerance;

#[test]
fn default_is_finite_thirty_two() {
    assert_eq!(
        UselessRecordTolerance::DEFAULT,
        UselessRecordTolerance::Finite(32)
    );
}

#[test]
fn effective_limit_for_finite_and_unlimited() {
    assert_eq!(
        UselessRecordTolerance::Finite(16).effective_limit(),
        Some(16)
    );
    assert_eq!(UselessRecordTolerance::Unlimited.effective_limit(), None);
}

#[test]
fn probe_tier_results_are_recognized() {
    assert!(UselessRecordTolerance::PROBE_FINITE_ONE.is_probe_tier_result());
    assert!(UselessRecordTolerance::PROBE_FINITE_SIXTEEN.is_probe_tier_result());
    assert!(UselessRecordTolerance::PROBE_FINITE_THIRTY_TWO.is_probe_tier_result());
    assert!(UselessRecordTolerance::Unlimited.is_probe_tier_result());
    assert!(UselessRecordTolerance::DEFAULT.is_probe_tier_result());
    assert!(!UselessRecordTolerance::Finite(7).is_probe_tier_result());
}
