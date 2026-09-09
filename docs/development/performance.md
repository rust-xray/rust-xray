# Performance principles

Profile before changing ownership or allocation behavior. The durable default
is shared immutable `Bytes` for payload ownership, connection-local scratch
for connection work, and session-local scratch for protocol state. Retained
capacity must be bounded by protocol limits and released when a session ends;
reusing a large allocation trades allocations for RSS, so measure the workload
that motivates it.

Avoid global `Vec` pools and global mutex-protected allocator pools by default.
They couple unrelated connections, retain hostile peak capacity, complicate
shutdown, and make task ownership harder to audit. Never pool secret buffers:
private keys and derived cryptographic material can outlive their intended
connection and become observable through reuse.

Keep locks short and never hold them across network I/O. Use bounded channels
for child/task backpressure, retain join/abort ownership at the parent, and
avoid eager expensive log formatting when its tracing level is disabled. The
Vision parser moves safe fragmented state rather than copying it, and its
pending output advances through owned `Bytes`; preserve those principles without
tying future code to a particular allocation layout.

`tcpFastOpen` is recognized in configuration in boolean and numeric forms. An
enabled value currently logs a warning and uses normal TCP; socket-level TFO and
packet-level SYN-data are not implemented. Platform-specific socket work is
required before this can be called supported.
