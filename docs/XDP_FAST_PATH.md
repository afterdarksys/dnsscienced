# XDP and AF_XDP Fast-Path Design

## Decision

The first XDP implementation should redirect selected UDP/53 traffic to one
AF_XDP socket per NIC receive queue. It should not answer DNS queries inside the
eBPF program.

This follows the practical boundary used by
[NSD's experimental XDP path](https://nsd.docs.nlnetlabs.nl/en/latest/xdp.html):
XDP bypasses the ordinary network stack for UDP and AF_XDP moves frames through
user-space rings. The Linux kernel's
[AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html) describes
the queue-bound XSK map, UMEM, RX/TX rings, copy and zero-copy modes, and
single-producer/single-consumer ownership constraints.

Direct `XDP_TX` cache responses remain a later research item. They require safe
variable-length DNS parsing, Ethernet/IP/UDP response construction, IPv4 and
mandatory IPv6 checksums, EDNS sizing, DNS cookies, RRL, policy generations,
fragment handling, and exact fallback behavior. Moving only part of that policy
into eBPF would make the fast path a security bypass.

## Existing `driver/` assessment

`driver/dns_firewall.c` is a Netfilter kernel module, not eBPF or XDP. It runs
after SKB allocation and implements a separate IPv4/UDP RPZ drop/mark table.
It is not reusable as the XDP data plane because it:

- has no IPv6 or TCP path;
- inspects both source and destination port 53 rather than a dedicated ingress
  service profile;
- implements only a simplified QNAME parser and divergent RPZ semantics;
- has an independent policy hash with no atomic generation shared with the
  production server;
- defaults to packet-triggered kernel logging;
- exposes rule mutation through a world-writable `/proc` file.

The module must be treated as experimental and must not be loaded in a
production or root-server deployment. Its immediate security defects should be
fixed separately; it should then be deprecated in favor of the generation-based
XDP/AF_XDP architecture.

## Phase 1: guarded redirect

The eBPF program performs only bounded L2/L3/L4 checks:

1. Accept Ethernet with an optional bounded VLAN parse.
2. Recognize IPv4 and IPv6 without walking unbounded extension-header chains.
3. Pass fragments, unsupported encapsulation, malformed frames, TCP, non-DNS
   traffic, and uncertain cases to the normal kernel stack.
4. For UDP addressed to an explicitly configured service address and port,
   look up the RX queue in `BPF_MAP_TYPE_XSKMAP`.
5. Redirect only when a live socket is present for the exact interface/queue;
   otherwise return `XDP_PASS`, never a default drop.

The Linux kernel validates that an XSK map entry matches the device and queue.
An empty or mismatched redirect can drop traffic, so the explicit lookup and
pass fallback are mandatory. See the kernel's
[XDP redirect documentation](https://docs.kernel.org/bpf/redirect.html).

Required maps:

| Map | Purpose |
|---|---|
| `xsks_map` | RX queue to live AF_XDP socket |
| `service_config` | Enabled generation, interface, addresses, UDP port, mode |
| `per_cpu_stats` | Pass, redirect, malformed, fragment, no-socket, and error counters |

Program loading is opt-in. A small privileged launcher attaches/pins the program
and maps, then drops privileges. The DNS daemon does not run permanently with
`CAP_SYS_ADMIN`, `CAP_BPF`, or `CAP_NET_ADMIN`. Shutdown first disables redirect,
waits for readers, and only then tears down sockets/maps.

## Phase 2: queue-owned user-space engine

- Create one AF_XDP socket per selected RX queue and one fixed worker per socket.
- Preserve the rings' single-producer/single-consumer ownership; do not share a
  ring across arbitrary goroutines.
- Prefer service-manager/container CPU sets. Pin a queue worker only after
  measurements include NUMA locality and Go scheduler effects.
- Use bounded UMEM frame counts and explicit headroom. Account for every frame
  across fill, RX, TX, and completion rings so overload cannot leak ownership.
- Probe native driver mode and zero-copy. Support copy mode for qualification,
  and fall back to the ordinary UDP listener when the driver/kernel cannot meet
  the configured requirements.
- Keep TCP, DoT, DoH, transfers, UPDATE, and control traffic on the complete
  socket path.

The AF_XDP worker must call the same immutable zone snapshot, cache policy, RPZ,
ACL, cookie, RRL, DNSSEC, audit, and metrics contracts as the portable server.
Unsupported queries go to the complete user-space handler; they are not silently
dropped and do not bypass checks.

## State and cache coherence

Fast-path state uses immutable generations:

1. Build and validate generation `N+1` in user space.
2. Publish it to all queue workers.
3. Atomically switch the active generation.
4. Retire generation `N` only after every worker reports a quiescent point.

Cache entries carry the cache generation, expiration, DNSSEC/policy status,
response-size class, and mutation requirements such as transaction ID. RPZ,
keys, ACLs, RRL configuration, cookies, and zones must change generations
together when their combined decision changes.

No BPF map should contain the full recursive cache in Phase 1. AF_XDP user space
can use the existing cache snapshot without verifier-limited DNS parsing or
duplicating expiry and security policy in kernel state.

## Failure and security rules

- `XDP_PASS` is the default for parse uncertainty, missing maps/sockets,
  disabled generations, fragments, and unsupported protocol features.
- A worker or daemon crash must fail back to the kernel socket path through a
  watchdog-controlled disable operation.
- An attach, detach, or generation failure is surfaced as a health failure and
  audit event; it is never reported as an enabled fast path.
- Per-queue overload counters, ring occupancy, fill starvation, completion
  backlog, redirect/pass counts, invalid descriptors, and fallback reasons are
  exported.
- Fast-path response bytes are differentially compared with the portable path
  for a shared corpus, fuzz cases, and every enabled policy combination.
- Root-authoritative mode cannot graduate until IPv4/IPv6, UDP/TCP fallback,
  EDNS, DNSSEC, cookies, RRL, fragments, and overload behavior pass the root
  conformance and differential suites.

## Qualification matrix

| Stage | Required evidence |
|---|---|
| Verifier | Programs load on supported LTS kernels and fail closed to `XDP_PASS` on unsupported layouts |
| Virtual | veth/netns tests cover IPv4, IPv6, VLAN, fragments, malformed input, map loss, worker death, attach/detach, and rolling generations |
| Hardware | At least two NIC/driver families; native, copy, and zero-copy modes reported separately |
| Correctness | Byte/semantic differential tests against the portable path and BIND/NSD where applicable |
| Performance | Sustained QPS plus p99/p99.9, loss, CPU/query, ring drops, RSS, and fallback rate under realistic and hostile traffic |
| Operations | Least-privilege loader, bpffs ownership, upgrade/rollback, watchdog, metrics, runbook, and safe normal-socket fallback |

Only Phase 1 guarded redirect and Phase 2 AF_XDP user-space processing are on the
near-term implementation path. In-kernel cache response generation needs its own
threat model, proof corpus, and measured advantage over AF_XDP before approval.

