# Upstream parity policy

Xray-core is authoritative for wire semantics, protocol semantics, security
semantics, and externally observable behavior. This pass uses
[Xray-core @ `52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`](https://github.com/XTLS/Xray-core/commit/52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120)
and [REALITY @ `8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8`](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8)
as reviewable references. Say “Xray-compatible”, “upstream-compatible”, or
“wire-compatible with Xray-core @ SHA” only for the behavior and evidence in
scope. The [compatibility matrix](../compatibility-status.md) remains the
authority for what is implemented.

Implement the observable result in idiomatic Rust. Do not mechanically port
goroutines, mutex topology, Go interfaces, or Go memory ownership patterns.
Rust task ownership, `Arc`, cancellation, and split I/O may differ as long as
wire bytes, ordering, error classification, security boundaries, and visible
lifecycle behavior remain compatible.

Recommended workflow:

1. Pin the upstream commit and locate the source behavior.
2. Classify its observable wire, protocol, security, and lifecycle semantics.
3. Add an upstream/reference vector or a failing regression.
4. Implement the smallest idiomatic Rust owner of that behavior.
5. Run deterministic tests, then differential or live smoke coverage.
6. Record harness limitations and any scoped divergence in the matrix.

When behavior cannot be demonstrated against the pinned reference, describe the
evidence honestly. A self-generated Rust fixture protects regression but does
not prove interoperability. Do not widen support claims because a related path
passes.

## TODO/FIXME audit

The repository search for `TODO|FIXME|HACK|temporary|experimental|Stage [0-9]|PERF-`
was reviewed for this pass. `experimental` in README, the compatibility matrix,
and the ML-DSA baseline is **VALID** scope wording. `config-architecture.md`'s
Migration TODO is **PLANNED**. The transcript/random TODOs in TLS state,
certificate TODOs, `close_notify` TODO, and the protocol RFC-reference TODO are
all **PLANNED** implementation limits. The accepted-path TODO matrix is
**HISTORICAL/PLANNED**, not a support claim. No `FIXME` or `HACK` remains in the
searched paths. Numeric project-stage labels were removed from developer-facing
comments and the accepted-path guide; no stale chat terminology was added.
