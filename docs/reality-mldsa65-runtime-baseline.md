# REALITY ML-DSA-65 Runtime Baseline

**Status:** experimental baseline on `experiment` (not full PQ roadmap).  
**Runtime matrix:** [compatibility-status.md](./compatibility-status.md)

This document records the confirmed live smoke baseline for built-in ML-DSA-65
REALITY support. It is intended as a regression guard for later REALITY/Vision
work.

## Historical baseline and current coverage

The numbers in the former local smoke capture are historical and are not used as
a current verification snapshot. Current live evidence must come from the
repository smoke harness. Its relevant coverage includes:

- full mldsa65 raw vision curl succeeded
- fallback matrix PASS: default, SNI/name, HTTP path, ALPN http/1.1, ALPN h2,
  ALPN h2 curl, xver=1 PROXY v1, xver=2 PROXY v2
- cipher matrix PASS: AES128, AES256, ChaCha20
- UDP/Mux/XUDP are documented and exercised separately by the current UDP smoke;
  native UDP, generic Mux UDP, and XUDP are supported forward-inbound behavior,
  while Vision native UDP is intentionally rejected. See
  [compatibility-status.md](./compatibility-status.md).

## Invariants

- ML-DSA-65 is a standard dependency, not feature-gated.
- The removed ML-DSA crypto feature gate must not exist.
- Config without `mldsa65Seed` uses `HmacOnly`.
- Config with `mldsa65Seed` uses `HmacPlusMldsa65`.
- The seed path must not fall back to `HmacOnly` on ML-DSA-65 patch errors.
- Invalid `mldsa65Seed` is rejected at startup.
- The seed must not be logged or exposed in debug output.
