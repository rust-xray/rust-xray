use sha2::{Digest, Sha256, Sha384};

use super::*;

const SHA256_EMPTY_DIGEST: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

const SHA384_EMPTY_DIGEST: [u8; 48] = [
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
];

#[test]
fn empty_sha256_digest_matches_known_value() {
    let transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
    assert_eq!(transcript.digest(), SHA256_EMPTY_DIGEST);
}

#[test]
fn empty_sha384_digest_matches_known_value() {
    let transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha384);
    assert_eq!(transcript.digest(), SHA384_EMPTY_DIGEST);
}

#[test]
fn update_order_matters_for_concatenation() {
    let mut split = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
    split.update(b"a");
    split.update(b"b");

    let mut combined = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
    combined.update(b"ab");

    assert_eq!(split.digest(), combined.digest());
}

#[test]
fn debug_does_not_include_raw_buffer_content() {
    let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
    transcript.update(&[0xde, 0xad, 0xbe, 0xef]);

    let debug = format!("{transcript:?}");

    assert!(debug.contains("Sha256"));
    assert!(debug.contains("len: 4"));
    assert!(!debug.contains("deadbeef"));
    assert!(!debug.contains("buffer"));
    assert!(!debug.contains("de"));
}

#[test]
fn len_tracks_total_transcript_bytes() {
    let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha384);

    assert_eq!(transcript.len(), 0);
    transcript.update(b"hello");
    assert_eq!(transcript.len(), 5);
    transcript.update(b" world");
    assert_eq!(transcript.len(), 11);
}

#[test]
fn repeated_digest_does_not_advance_transcript_state() {
    let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
    transcript.update(b"client");
    transcript.update(b"server");

    let first = transcript.digest();
    let second = transcript.digest();
    assert_eq!(first, second);

    transcript.update(b"ee");
    assert_ne!(transcript.digest(), first);
}

#[test]
fn streaming_digest_matches_independent_sha256_reference() {
    let messages: [&[u8]; 4] = [
        b"client-hello",
        b"server-hello",
        b"certificate",
        b"finished",
    ];
    let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
    for message in messages {
        transcript.update(message);
    }

    let mut reference = Sha256::new();
    for message in messages {
        reference.update(message);
    }

    assert_eq!(transcript.digest(), reference.finalize().to_vec());
}

#[test]
fn streaming_digest_matches_independent_sha384_reference() {
    let messages: [&[u8]; 2] = [b"sha384-client", b"sha384-server"];
    let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha384);
    for message in messages {
        transcript.update(message);
    }

    let mut reference = Sha384::new();
    for message in messages {
        reference.update(message);
    }

    assert_eq!(transcript.digest(), reference.finalize().to_vec());
}

/// Golden handshake-stage digests for a deterministic fixture sequence (SHA-256).
#[test]
fn handshake_stage_digests_match_golden_sha256_vectors() {
    const CLIENT_HELLO: &[u8] = b"fixture-client-hello-message";
    const SERVER_HELLO: &[u8] = b"fixture-server-hello-message";
    const ENCRYPTED_EXTENSIONS: &[u8] = b"fixture-encrypted-extensions";
    const CERTIFICATE: &[u8] = b"fixture-certificate-message";
    const CERTIFICATE_VERIFY: &[u8] = b"fixture-certificate-verify";
    const SERVER_FINISHED: &[u8] = b"fixture-server-finished";
    const CLIENT_FINISHED: &[u8] = b"fixture-client-finished";

    fn stage_digest(messages: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for message in messages {
            hasher.update(message);
        }
        hasher.finalize().into()
    }

    let golden = [
        stage_digest(&[]),
        stage_digest(&[CLIENT_HELLO]),
        stage_digest(&[CLIENT_HELLO, SERVER_HELLO]),
        stage_digest(&[
            CLIENT_HELLO,
            SERVER_HELLO,
            ENCRYPTED_EXTENSIONS,
            CERTIFICATE,
            CERTIFICATE_VERIFY,
        ]),
        stage_digest(&[
            CLIENT_HELLO,
            SERVER_HELLO,
            ENCRYPTED_EXTENSIONS,
            CERTIFICATE,
            CERTIFICATE_VERIFY,
            SERVER_FINISHED,
        ]),
        stage_digest(&[
            CLIENT_HELLO,
            SERVER_HELLO,
            ENCRYPTED_EXTENSIONS,
            CERTIFICATE,
            CERTIFICATE_VERIFY,
            SERVER_FINISHED,
            CLIENT_FINISHED,
        ]),
    ];

    let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
    assert_eq!(transcript.digest(), golden[0]);

    transcript.update(CLIENT_HELLO);
    assert_eq!(transcript.digest(), golden[1]);

    transcript.update(SERVER_HELLO);
    assert_eq!(transcript.digest(), golden[2]);

    transcript.update(ENCRYPTED_EXTENSIONS);
    transcript.update(CERTIFICATE);
    transcript.update(CERTIFICATE_VERIFY);
    assert_eq!(transcript.digest(), golden[3]);

    transcript.update(SERVER_FINISHED);
    assert_eq!(transcript.digest(), golden[4]);

    transcript.update(CLIENT_FINISHED);
    assert_eq!(transcript.digest(), golden[5]);
}

/// Informational transcript throughput benchmark (not run in normal CI).
#[ignore]
#[test]
fn transcript_digest_benchmark() {
    use std::time::Instant;

    const ITERATIONS: usize = 10_000;
    const MESSAGE: &[u8] = b"deterministic-handshake-message-bytes-for-benchmark";

    let mut transcript = TranscriptHash::new(Tls13HashAlgorithm::Sha256);
    transcript.update(MESSAGE);
    transcript.update(MESSAGE);
    transcript.update(MESSAGE);

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let digest = transcript.digest();
        assert_eq!(digest.len(), 32);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "MEASURED transcript digest bench iters={ITERATIONS} total={elapsed:?} per_digest={:?}",
        elapsed / ITERATIONS as u32
    );
}
