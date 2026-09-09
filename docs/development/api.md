# API and runtime managers

`src/api` implements the meaningful Xray-compatible gRPC surface without
exposing generated protobuf internals as developer API. The service modules
adapt protobuf requests to runtime managers; `proto/` and `build.rs` own
generation. Direct listeners support the documented TCP, filesystem Unix,
Linux abstract Unix, and internal Commander modes. Plaintext gRPC is the
Xray-compatible default; direct TLS/mTLS is a rust-xray extension.

The implemented services are Stats, Handler, Routing, Logger, Observatory, and
optional reflection. Stats reads runtime counters. Handler manages supported
inbound/outbound objects and dynamic VLESS users. Routing reads/mutates runtime
rules and balancer state. Logger restarts supported sinks. Observatory provides
the health inputs consumed by eligible balancers. Generated service definitions
may contain more names than the meaningful runtime surface, so consult the
[compatibility matrix](../compatibility-status.md) before claiming support.

RemnaNode compatibility targets the implemented API/runtime behavior, currently
documented as scoped compatibility with RemnaNode 3.3.2. The integration notes
and local harness live in [remna-compat.md](../remna-compat.md); they do not
assert future panel or full Xray API compatibility.
