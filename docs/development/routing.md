# Routing and DNS

`RouteContext` is the one input to both data-plane routing and
`RoutingService.TestRoute`. `RuntimeRouter` compiles configuration into an
immutable `RouteTable` snapshot, evaluates rules in order, and publishes a new
snapshot for mutations. First match wins; when no rule matches,
`pick_route_with_default` selects the outbound manager's default if present.
`OutboundRegistry`/the runtime outbound manager owns registered targets, while
balancers select among their configured members using their supported strategy.

Domain matching preserves the original destination spelling for outbound and
SNI use. A lowercase domain and lowercase attribute map are cached only for one
route decision so repeated rules do not repeat normalization. DNS-derived IPs
go in `target_ips`; they must not be cached as if they were original domain
matcher input. GeoIP/GeoSite data is loaded through the geodata cache and
protocol sniffing/webhooks contribute the documented route context.

`DomainStrategy::AsIs` does no routing DNS resolution. `IpOnDemand` resolves
when an IP condition requires it during the first rule pass. `IpIfNonMatch`
runs a first pass using the original context, resolves only after it fails when
needed, then runs a second pass with `target_ips`. Normalization caches may be
reused across the passes; conditions that depend on resolved IP data must be
evaluated again.

The DNS engine caches responses and coalesces identical in-flight queries. One
leader performs upstream work while waiters await publication. Success and
failure publish a result then wake waiters. If a leader task is canceled before
publication, its guard clears the active flag and notifies waiters; they remove
the stale exact entry, allowing the next request to become leader. This prevents
a canceled query from becoming a permanent waiter/memory leak.

See [compatibility-status.md](../compatibility-status.md) for current geodata,
process/attribute extraction, and intentional-divergence scope.
