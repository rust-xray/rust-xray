# REALITY accepted path

This guide describes the implementation compared with
[Xray-core @ `5ca6f4b7d4dc20a881d4330e498892697627ec0c`](https://github.com/XTLS/Xray-core/commit/5ca6f4b7d4dc20a881d4330e498892697627ec0c)
and [REALITY @ `8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8`](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8).
For scope and gaps, use the [compatibility matrix](../compatibility-status.md).

The listener reads a bounded ClientHello record, checks SNI, session AEAD,
short ID, client version, and time window in the documented order, and either
falls back or accepts. Before acceptance the fallback target can receive normal
non-REALITY traffic. Acceptance changes the security boundary: target probing,
TLS, VLESS, encryption, and application failures must close the client
connection. They must never re-enter `dest` fallback.

On acceptance the server probes the target flight, mirrors the observed key
exchange group, and runs its own TLS 1.3 state machine. X25519 shares are 32
bytes. The hybrid X25519MLKEM768 share has the ML-KEM-768 encapsulation key plus
an X25519 public key (1184 + 32 bytes); its server response combines the
ML-KEM ciphertext and X25519 share (1088 + 32 bytes). The resulting hybrid
secret feeds the TLS schedule. The target supplies camouflage shape, never the
accepted application's TLS secrets.

The accepted application stream owns one mutable server write sequence. Normal
application records, position-6 camouflage, an encrypted fatal
`unexpected_message` alert for useless-record overflow, and every later record
consume that one sequence in wire order. Position-6 is encrypted application
data emitted from target-flight shape; post-handshake probes provide additional
camouflage lengths. Cloning an encryptor or sequence for a special record
creates two records with the same nonce/sequence and corrupts all following
traffic.

The reader tolerates bounded target-probed useless records such as compatible
CCS where policy permits. A tolerance overflow first asks the sole writer to
drain pending ciphertext and emit one best-effort encrypted fatal alert. EOF
and `close_notify` are clean peer-close signals; a FIN that truncates a TLS
record or handshake is an error. Vision may request DIRECT only after its
framed output drains, so raw bytes cannot overtake a partial TLS record.

Implementation detail and probe limitations are recorded in
[reality-accepted-path.md](../reality-accepted-path.md).
