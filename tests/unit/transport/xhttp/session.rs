use super::*;
use std::thread;
use std::time::Duration as StdDuration;

#[test]
fn validate_session_id_rejects_empty_and_invalid() {
    assert_eq!(
        XHttpSessionManager::validate_session_id(""),
        Err(XHttpSessionError::EmptySessionId)
    );
    assert_eq!(
        XHttpSessionManager::validate_session_id("   "),
        Err(XHttpSessionError::EmptySessionId)
    );
    assert_eq!(
        XHttpSessionManager::validate_session_id("bad/id"),
        Err(XHttpSessionError::InvalidSessionIdCharset)
    );
    assert_eq!(
        XHttpSessionManager::validate_session_id(".."),
        Err(XHttpSessionError::InvalidSessionIdCharset)
    );
    assert_eq!(
        XHttpSessionManager::validate_session_id("bad id"),
        Err(XHttpSessionError::InvalidSessionIdCharset)
    );
    let too_long = "a".repeat(MAX_SESSION_ID_LEN + 1);
    assert_eq!(
        XHttpSessionManager::validate_session_id(&too_long),
        Err(XHttpSessionError::SessionIdTooLong)
    );
}

#[test]
fn validate_session_id_accepts_uuid_like_values() {
    assert!(
        XHttpSessionManager::validate_session_id("0897e374-2f32-4d61-aee9-b9c8523aa358").is_ok()
    );
}

#[test]
fn create_session() {
    let manager = XHttpSessionManager::for_test(Duration::from_secs(30), 8);
    let outcome = manager
        .ensure_session("session-a", EffectiveXHttpMode::PacketUp)
        .expect("create");
    assert_eq!(outcome, XHttpSessionEnsureOutcome::Created);
    assert_eq!(manager.session_count(), 1);
    let session = manager.get("session-a").expect("session");
    assert_eq!(session.mode, EffectiveXHttpMode::PacketUp);
    assert_eq!(session.state, XHttpSessionState::Opening);
}

#[test]
fn reuse_session() {
    let manager = XHttpSessionManager::for_test(Duration::from_secs(30), 8);
    assert_eq!(
        manager
            .ensure_session("session-a", EffectiveXHttpMode::StreamUp)
            .expect("create"),
        XHttpSessionEnsureOutcome::Created
    );
    assert_eq!(
        manager
            .ensure_session("session-a", EffectiveXHttpMode::StreamUp)
            .expect("reuse"),
        XHttpSessionEnsureOutcome::Reused
    );
    assert_eq!(manager.session_count(), 1);
    let session = manager.get("session-a").expect("session");
    assert_eq!(session.state, XHttpSessionState::Active);
}

#[test]
fn max_sessions_enforced() {
    let manager = XHttpSessionManager::for_test(Duration::from_secs(30), 2);
    manager
        .ensure_session("one", EffectiveXHttpMode::PacketUp)
        .expect("one");
    manager
        .ensure_session("two", EffectiveXHttpMode::PacketUp)
        .expect("two");
    assert_eq!(
        manager.ensure_session("three", EffectiveXHttpMode::PacketUp),
        Err(XHttpSessionError::MaxSessionsReached)
    );
    assert_eq!(manager.session_count(), 2);
}

#[test]
fn idle_cleanup_removes_old_sessions() {
    let manager = XHttpSessionManager::for_test(Duration::from_millis(20), 8);
    manager
        .ensure_session("stale", EffectiveXHttpMode::PacketUp)
        .expect("create");
    thread::sleep(StdDuration::from_millis(30));
    let removed = manager.cleanup_idle();
    assert_eq!(removed, 1);
    assert_eq!(manager.session_count(), 0);
    assert_eq!(
        manager.get("stale"),
        Err(XHttpSessionError::SessionNotFound)
    );
}

#[test]
fn close_session_removes_state() {
    let manager = XHttpSessionManager::for_test(Duration::from_secs(30), 8);
    manager
        .ensure_session("session-a", EffectiveXHttpMode::PacketUp)
        .expect("create");
    manager.close("session-a", "test_done").expect("close");
    assert_eq!(manager.session_count(), 0);
    assert_eq!(
        manager.get("session-a"),
        Err(XHttpSessionError::SessionNotFound)
    );
}

#[test]
fn ensure_session_rejects_invalid_id() {
    let manager = XHttpSessionManager::for_test(Duration::from_secs(30), 8);
    assert_eq!(
        manager.ensure_session("", EffectiveXHttpMode::PacketUp),
        Err(XHttpSessionError::EmptySessionId)
    );
}

#[test]
fn cleanup_idle_runs_before_create_when_at_capacity_boundary() {
    let manager = XHttpSessionManager::for_test(Duration::from_millis(20), 1);
    manager
        .ensure_session("stale", EffectiveXHttpMode::PacketUp)
        .expect("create stale");
    thread::sleep(StdDuration::from_millis(30));
    let outcome = manager
        .ensure_session("fresh", EffectiveXHttpMode::PacketUp)
        .expect("create after idle cleanup");
    assert_eq!(outcome, XHttpSessionEnsureOutcome::Created);
    assert_eq!(manager.session_count(), 1);
    assert!(manager.get("fresh").is_ok());
}
