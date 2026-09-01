//! 0-RTT session cache, expiry, replay, noise, and cache-boundary tests.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
use crate::vless::encryption::header::decode_traffic_header;
use crate::vless::encryption::hybrid::compose_pfs_key;
use crate::vless::encryption::{
    generate_invalid_ticket_noise, invalid_ticket_noise_length, HandshakeError, MockCacheTime,
    SessionCache, SessionLookupError, TicketLifetimeRange, VlessEncryptionServer,
    INVALID_TICKET_NOISE_MAX, INVALID_TICKET_NOISE_MIN, MAX_STORED_SESSIONS,
};

use super::client_sim::{
    build_zero_rtt_client_hello, perform_1rtt_and_capture_resume,
    server_config_with_ticket_lifetime, server_secret_for_tests, ClientResumeState,
};
use super::stream_helpers::ScriptStream;
use super::test_rng::TestHandshakeRng;

fn sample_pfs() -> crate::vless::encryption::hybrid::PfsKey {
    compose_pfs_key(&[0x11u8; MLKEM768_SHARED_SECRET_LEN], &[0x22u8; 32])
}

fn sample_ticket(id: u8) -> [u8; 16] {
    [id; 16]
}

fn mock_cache(lifetime_secs: u64) -> (SessionCache, Arc<RwLock<MockCacheTime>>) {
    let start = Instant::now();
    let mock = Arc::new(RwLock::new(MockCacheTime {
        instant: start,
        unix_secs: 1_700_000_000,
    }));
    let cache = SessionCache::new_with_mock_time(
        TicketLifetimeRange {
            min_secs: lifetime_secs,
            max_secs: lifetime_secs,
        },
        Arc::clone(&mock),
    );
    (cache, mock)
}

#[test]
fn expiry_boundary_strict_less_than() {
    let (cache, mock) = mock_cache(120);
    let ticket = sample_ticket(1);
    let start_instant = mock.read().expect("lock").instant;
    cache.insert(ticket, sample_pfs(), 120);
    let nfs_before = [0xA1u8; 32];
    let nfs_at = [0xA2u8; 32];
    let nfs_after = [0xA3u8; 32];

    mock.write().expect("lock").instant = start_instant + Duration::from_secs(119);
    cache
        .lookup_for_resume(&ticket, &nfs_before)
        .expect("valid before expiry");

    mock.write().expect("lock").instant = start_instant + Duration::from_secs(120);
    assert!(matches!(
        cache.lookup_for_resume(&ticket, &nfs_at),
        Err(SessionLookupError::UnknownSession)
    ));

    mock.write().expect("lock").instant = start_instant + Duration::from_secs(121);
    assert!(matches!(
        cache.lookup_for_resume(&ticket, &nfs_after),
        Err(SessionLookupError::UnknownSession)
    ));
}

#[test]
fn minute_bucket_prunes_before_per_entry_expiry() {
    let (cache, mock) = mock_cache(3600);
    let ticket = sample_ticket(9);
    let start_instant = mock.read().expect("lock").instant;
    let start_unix = mock.read().expect("lock").unix_secs;
    cache.insert(ticket, sample_pfs(), 3600);
    let nfs = [0xBBu8; 32];
    cache
        .lookup_for_resume(&ticket, &nfs)
        .expect("valid before bucket prune");

    {
        let mut guard = mock.write().expect("lock");
        guard.unix_secs = start_unix + 3600 + 120;
        assert_eq!(guard.instant, start_instant);
    }
    assert!(matches!(
        cache.lookup_for_resume(&ticket, &nfs),
        Err(SessionLookupError::UnknownSession)
    ));
}

#[test]
fn ticket_reusable_with_fresh_nfs_exchange() {
    let cache = SessionCache::new(TicketLifetimeRange {
        min_secs: 600,
        max_secs: 600,
    });
    let ticket = sample_ticket(3);
    let nfs_a = [0xAAu8; 32];
    let nfs_b = [0xBBu8; 32];
    let nfs_c = [0xCCu8; 32];
    cache.insert(ticket, sample_pfs(), 600);
    cache
        .lookup_for_resume(&ticket, &nfs_a)
        .expect("first resume");
    cache
        .lookup_for_resume(&ticket, &nfs_b)
        .expect("second resume fresh nfs");
    cache
        .lookup_for_resume(&ticket, &nfs_c)
        .expect("third resume fresh nfs");
    assert!(matches!(
        cache.lookup_for_resume(&ticket, &nfs_a),
        Err(SessionLookupError::ReplayDetected)
    ));
}

#[test]
fn replay_keys_cleared_when_session_removed() {
    let (cache, mock) = mock_cache(10);
    let ticket = sample_ticket(4);
    cache.insert(ticket, sample_pfs(), 10);
    let nfs = [0xDDu8; 32];
    cache.lookup_for_resume(&ticket, &nfs).expect("use");
    assert_eq!(cache.replay_key_count(&ticket), 1);
    mock.write().expect("lock").instant += Duration::from_secs(11);
    assert!(matches!(
        cache.lookup_for_resume(&ticket, &nfs),
        Err(SessionLookupError::ExpiredSession | SessionLookupError::UnknownSession)
    ));
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.replay_key_count(&ticket), 0);
}

#[test]
fn replay_keys_accumulate_only_during_active_session() {
    let (cache, mock) = mock_cache(60);
    let ticket = sample_ticket(7);
    cache.insert(ticket, sample_pfs(), 60);
    for i in 0..50u8 {
        let mut nfs = [0u8; 32];
        nfs[0] = i;
        cache
            .lookup_for_resume(&ticket, &nfs)
            .expect("fresh nfs resume");
    }
    assert_eq!(cache.replay_key_count(&ticket), 50);
    mock.write().expect("lock").instant += Duration::from_secs(61);
    let nfs = [0xFFu8; 32];
    assert!(matches!(
        cache.lookup_for_resume(&ticket, &nfs),
        Err(SessionLookupError::UnknownSession)
    ));
    assert_eq!(cache.replay_key_count(&ticket), 0);
}

#[test]
fn cache_overflow_at_1023_1024_1025() {
    let cache = SessionCache::new(TicketLifetimeRange {
        min_secs: 60,
        max_secs: 60,
    });
    for i in 0..1023u16 {
        let mut ticket = [0u8; 16];
        ticket[0] = (i >> 8) as u8;
        ticket[1] = (i & 0xFF) as u8;
        cache.insert(ticket, sample_pfs(), 60);
    }
    assert_eq!(cache.len(), 1023);
    cache.insert(
        {
            let mut t = [0u8; 16];
            t[0] = 0xFD;
            t
        },
        sample_pfs(),
        60,
    );
    assert_eq!(cache.len(), 1024);
    cache.insert(
        {
            let mut t = [0u8; 16];
            t[0] = 0xFE;
            t
        },
        sample_pfs(),
        60,
    );
    assert!(cache.len() <= MAX_STORED_SESSIONS);
    let fresh = {
        let mut t = [0u8; 16];
        t[0] = 0xFF;
        t
    };
    cache.insert(fresh, sample_pfs(), 60);
    cache
        .lookup_for_resume(&fresh, &[0x11u8; 32])
        .expect("fresh ticket works after overflow clear");
}

#[test]
fn disabled_lifetime_no_server_state() {
    let secret = server_secret_for_tests();
    let mut config = server_config_with_ticket_lifetime(&secret, 0, 0);
    config.ticket_lifetime = TicketLifetimeRange::disabled();
    let server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let (resume, _) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
        .block_on(async { perform_1rtt_and_capture_resume(&server, &config, 99).await });
    assert_eq!(server.session_cache().len(), 0);
    let fake = ClientResumeState {
        ticket: resume.ticket,
        pfs_key: resume.pfs_key,
        client_iv: resume.client_iv,
        use_aes: resume.use_aes,
    };
    let (hello, _, _) =
        build_zero_rtt_client_hello(&config, &fake, &secret, &mut TestHandshakeRng::new(1));
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
        .block_on(async {
            server
                .handshake(
                    ScriptStream::from_read(hello),
                    &mut TestHandshakeRng::new(2),
                )
                .await
        });
    assert!(matches!(
        err,
        Err(HandshakeError::ResumeNotAllowed) | Err(HandshakeError::UnknownSession)
    ));
}

#[test]
fn noise_length_bounds_and_invalid_header() {
    let mut rng = TestHandshakeRng::new(77);
    for _ in 0..32 {
        let len = invalid_ticket_noise_length(&mut rng);
        assert!((INVALID_TICKET_NOISE_MIN..=INVALID_TICKET_NOISE_MAX).contains(&len));
        let (noise, n) = generate_invalid_ticket_noise(&mut rng);
        assert_eq!(noise.len(), n);
        assert!((INVALID_TICKET_NOISE_MIN..=INVALID_TICKET_NOISE_MAX).contains(&noise.len()));
        if noise.len() >= 5 {
            assert!(decode_traffic_header(noise[..5].try_into().expect("hdr")).is_err());
        }
    }
}

#[tokio::test]
async fn unknown_and_expired_ticket_emit_equivalent_noise_class() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);

    let fake = ClientResumeState {
        ticket: [0xEE; 16],
        pfs_key: [0x11; 64],
        client_iv: [0u8; 16],
        use_aes: true,
    };
    let (unknown_hello, _, _) =
        build_zero_rtt_client_hello(&config, &fake, &secret, &mut TestHandshakeRng::new(3));
    let unknown_server = VlessEncryptionServer::from_config(config.clone()).expect("server");
    let mut unknown_io = ScriptStream::from_read(unknown_hello);
    let _ = unknown_server
        .handshake(&mut unknown_io, &mut TestHandshakeRng::new(4))
        .await;
    let unknown_noise = unknown_io.into_written();

    let mock = Arc::new(RwLock::new(MockCacheTime {
        instant: Instant::now(),
        unix_secs: 1_700_000_000,
    }));
    let config_for_server = config.clone();
    let cache = SessionCache::new_with_mock_time(
        config_for_server.ticket_lifetime.clone(),
        Arc::clone(&mock),
    );
    let expired_server =
        VlessEncryptionServer::from_config_with_session_cache(config_for_server, cache)
            .expect("server");
    let (resume, _) = perform_1rtt_and_capture_resume(&expired_server, &config, 99).await;
    mock.write().expect("lock").instant += Duration::from_secs(601);

    let (expired_hello, _, _) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(5));
    let mut expired_io = ScriptStream::from_read(expired_hello);
    let _ = expired_server
        .handshake(&mut expired_io, &mut TestHandshakeRng::new(6))
        .await;
    let expired_noise = expired_io.into_written();

    assert!((INVALID_TICKET_NOISE_MIN..=INVALID_TICKET_NOISE_MAX).contains(&unknown_noise.len()));
    assert!((INVALID_TICKET_NOISE_MIN..=INVALID_TICKET_NOISE_MAX).contains(&expired_noise.len()));
    if unknown_noise.len() >= 5 {
        assert!(decode_traffic_header(unknown_noise[..5].try_into().unwrap()).is_err());
    }
    if expired_noise.len() >= 5 {
        assert!(decode_traffic_header(expired_noise[..5].try_into().unwrap()).is_err());
    }
}

#[tokio::test]
async fn concurrent_fresh_nfs_same_ticket_both_succeed() {
    let secret = server_secret_for_tests();
    let config = server_config_with_ticket_lifetime(&secret, 600, 600);
    let server = Arc::new(VlessEncryptionServer::from_config(config.clone()).expect("server"));
    let (resume, _) = perform_1rtt_and_capture_resume(server.as_ref(), &config, 99).await;

    let (hello_a, parts_a, enc_a) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(10));
    let (hello_b, parts_b, enc_b) =
        build_zero_rtt_client_hello(&config, &resume, &secret, &mut TestHandshakeRng::new(11));
    let mut wire_a = hello_a;
    let mut wire_b = hello_b;
    wire_a.extend_from_slice(
        &super::client_sim::seal_client_traffic(
            &mut super::client_sim::client_zero_rtt_upload_writer(&resume, &parts_a, &enc_a),
            b"a",
        )
        .unwrap(),
    );
    wire_b.extend_from_slice(
        &super::client_sim::seal_client_traffic(
            &mut super::client_sim::client_zero_rtt_upload_writer(&resume, &parts_b, &enc_b),
            b"b",
        )
        .unwrap(),
    );

    let sa = server.clone();
    let sb = server.clone();
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move {
            sa.handshake(
                ScriptStream::from_read(wire_a),
                &mut TestHandshakeRng::new(5),
            )
            .await
        }),
        tokio::spawn(async move {
            sb.handshake(
                ScriptStream::from_read(wire_b),
                &mut TestHandshakeRng::new(6),
            )
            .await
        }),
    );
    assert!(ra.expect("a").is_ok());
    assert!(rb.expect("b").is_ok());
}
