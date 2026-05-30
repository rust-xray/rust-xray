# DNS runtime — future work

The DNS engine core (cache, UDP/TCP transport, Mux UDP DNS) is implemented. The items
below are **not** implemented yet; they are documented for routing/outbound integration
follow-ups.

## Inbound / hijack

- **dokodemo-door UDP :53** — accept DNS queries on a local listener, forward to
  `DnsEngine::query_raw`, write raw response back to client.
- **DNS inbound tag** — route `inboundTag: dns-in` to internal DNS handler instead of
  VLESS relay.
- **DNS hijack** — transparently capture client DNS (iptables/nft or socket redirect) and
  answer from `DnsEngine` without system resolver.

## Outbound

- **`protocol: "dns"` outbound** — config parses safely; `DnsOutboundPlaceholder` returns
  explicit unsupported until full egress is implemented.
- **DNS-over-TCP through proxy outbound** — use routing-selected VLESS/freedom dial for
  `tcp://` DNS servers (today: freedom direct numeric IP only).

## FakeDNS / full Xray parity

- **FakeDNS** — map domains to fake IPs and reverse lookup in routing.
- **Full routing execution** — apply domain/IP rules before outbound dial (today: strategy
  + freedom connect only).
- **Parallel DNS / balancer** — not planned on current branch.

## References

- [compatibility-status.md](./compatibility-status.md) — observed behavior matrix
- [config-compatibility-audit.md](./config-compatibility-audit.md) — parse policy
