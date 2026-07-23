# Runtime and Resolver Performance Tuning

DNSScienced exposes separate controls for Go runtime concurrency, network
listeners, recursive work, authoritative query fan-out, and cache capacity.
They are intentionally independent: an OS thread is not a resolver worker, and
a UDP listener is not a worker.

## Capability summary

| Question | Current behavior |
|---|---|
| Can threads be tuned? | `runtime.max_procs` controls how many CPUs may execute Go code simultaneously. Go still creates and schedules OS threads as needed. |
| How many threads are supported? | There is no fixed application thread count. `max_procs` accepts 1–65,536, but values near the available CPU quota are normally appropriate. |
| Do workers have CPU affinity? | No. Resolver workers are goroutines and may move between OS threads. Apply affinity to the process with a service manager or container CPU set. |
| Can cache sizes be tuned? | Yes: `cache.max_entries`, `cache.max_memory_mb`, and `cache.shard_count`. |
| Is prefetch supported? | Yes. Near-expiry entries can refresh asynchronously, duplicate refreshes are suppressed, and the admin Prefetch RPC initiates real bounded lookups. |
| Can ISP resolvers be bypassed? | Yes. The current recursive path performs iterative resolution from root hints and does not use the host or ISP resolver. Explicit public-resolver and conditional-forwarding modes remain planned. |
| Is parsing zero-copy? | Not end to end. Production output and encrypted-transport buffers are pooled; the audited `miekg/dns` UDP server also pools input buffers. DNS message decoding still constructs Go objects. |
| Is I/O asynchronous? | Go's network poller provides nonblocking readiness underneath the goroutine API. DNS handlers use ordinary synchronous-looking Go calls; there is no application-specific `io_uring` path. |
| Is `sync.Pool` used for byte buffers? | Yes, on measured production UDP/TCP response packing and DoT/DoH framing paths. The pools store pointers to fixed arrays so pool use itself does not allocate. |
| Is the cache lock-free? | No. It uses many independently locked shards and atomic counters. Reads contend only within a shard; expiry and capacity eviction use a per-shard indexed min-heap. |
| Are worker pools fixed and routed? | Yes. Distinct recursive cache misses enter a bounded fixed worker pool. Coalesced requests share one lookup. A full queue fails fast with SERVFAIL. |

## Configuration

```yaml
runtime:
  max_procs: 0           # 0 preserves Go/container-aware GOMAXPROCS
  gc_percent: 100        # optional; omit to preserve GOGC, -1 disables GC
  memory_limit_mb: 768   # 0 preserves GOMEMLIMIT/default

server:
  udp_listeners: 4       # SO_REUSEPORT sockets; default is runtime.NumCPU()
  recursive:
    workers: 100
    worker_queue_size: 1000
    nameserver_parallelism: 2
    nameserver_hedge_delay: 25ms

cache:
  max_entries: 100000
  max_memory_mb: 512
  shard_count: 256
  prefetch: true
  prefetch_min_ttl_pct: 0.1
```

Runtime memory is a soft process-wide Go limit, not a cache limit. Leave room
above `cache.max_memory_mb` for parsed messages, zones, worker stacks, transport
buffers, telemetry, and non-Go memory. An initial 25–50% margin is reasonable,
then tune from heap profiles and production resident-set measurements.

`udp_listeners`, `workers`, and `nameserver_parallelism` multiply different
resources. Raising all three at once can increase socket buffers, queued work,
authoritative fan-out, and tail latency. Change one dimension at a time.

## CPU affinity

Per-worker pinning is intentionally unsupported. `runtime.LockOSThread` would
bind implementation goroutines to OS threads, interfere with Go scheduling, and
does not map cleanly to resolver workers. Prefer process-level controls:

```ini
# systemd service override
[Service]
CPUAffinity=0-7
```

For containers, use the runtime's CPU quota or cpuset. Keep
`runtime.max_procs: 0` unless measurements show the automatically detected value
is unsuitable.

## Starting points

- CPU-limited authoritative service: start with `max_procs` at the CPU quota and
  `udp_listeners` at or below that value.
- Recursive service: start with 100 workers, 10 queued requests per worker,
  nameserver parallelism 2, and a 25 ms hedge delay.
- Memory-limited service: size the cache first, set the Go memory limit with
  headroom, and watch eviction rate, GC CPU, heap size, queue saturation, and
  p95/p99 latency together.

These are starting points, not capacity guarantees. Network latency and the
ratio of cached to uncached names usually dominate a recursive workload.

## Measure before and after

Run focused allocation and resolver benchmarks:

```sh
go test ./internal/server -run '^$' -bench BenchmarkResponsePacking -benchmem
go test ./internal/resolver -run '^$' -bench 'BenchmarkResolve_CacheHit|BenchmarkFindGlue' -benchmem
go test ./internal/transport -run '^$' -bench 'BenchmarkDNSASMParsing|BenchmarkFullPipeline' -benchmem
```

For a deployment, record p50/p95/p99 latency, QPS, SERVFAIL rate, worker queue
depth/rejections, cache hit/eviction rate, heap size, allocation rate, GC CPU,
and process RSS. Compare one configuration change at a time under the same
query mix.

The assembly-parser UDP server is experimental. Its microbenchmarks do not
establish feature, protocol, or security parity with the production server.

## Measured packet-header parsing

The DNS header fast path now uses `ParseHeaderInto`, a bounds-checked scalar Go
parser with caller-owned storage. The x86 assembly implementation remains
buildable for research, but it is not selected by the production UDP listener.

In a Linux/amd64 container on an Intel i9-9880H, five benchmark runs produced:

| Parser | Time | Allocations | Decision |
|---|---:|---:|---|
| One header through cgo/assembly | 101.7–111.9 ns | 1 | Do not use for header rejection |
| Scalar Go, caller-owned output | 4.58–4.81 ns/header | 0 | Selected fast path |
| Public scalar Go API | 5.22–5.76 ns/header | 0 | Selected compatibility path |
| 64-header fixed-stride Go batch | 8.04–8.22 ns/header | 0 | Suitable input layout for a future `recvmmsg` prototype |

The assembly parser was also corrected to read exactly 12 bytes rather than
over-reading a 16-byte vector at the end of a short buffer. It now uses baseline
SSE2 and its response-header builder no longer corrupts the output pointer.
AVX2/AVX-512 are not justified for one 12-byte DNS header; any future SIMD work
must benchmark multiple independent headers per vector and include runtime CPU
feature dispatch.

Linux `recvmmsg` receive batching is available as an opt-in production-handler
transport. It remains disabled by default until end-to-end NIC/RSS testing beats
the portable listener for throughput and p99/p99.9 latency. `sendmmsg` remains
an isolated primitive; synchronous DNS handler responses are not buffered.
XDP/eBPF is a separate deployment architecture: it needs cache-coherency,
policy-parity, privilege, observability, and fallback designs before code is
attached to a network interface.

## Measured Linux UDP batching

`UDPBatchConn` uses the Go `x/net` wrappers that issue
`recvmmsg` and `sendmmsg` on Linux. It bounds batches at 256 datagrams, defaults
to 64, reuses receive storage, reports truncation, and has IPv4 and IPv6
loopback coverage.

Enable production receive batching explicitly:

```yaml
server:
  udp_listeners: 4
  udp_batch_size: 64
```

Each SO_REUSEPORT listener owns one batch reader. Received packets continue
through the normal `miekg/dns` parser and the complete TSIG, ACL, RRL, cookie,
policy, authoritative, and recursive handler chain. Packet destination metadata
is retained so wildcard and multihomed listeners reply from the queried local
address. `UDPBatchReadCalls`, `UDPBatchDatagrams`, and `UDPBatchTruncated`
statistics expose actual batch fill and oversized traffic; average fill is
`UDPBatchDatagrams / UDPBatchReadCalls`.

In a Linux/amd64 Docker loopback benchmark on an Intel i9-9880H:

| Operation | Conventional syscalls | Batched syscall | Observed change |
|---|---:|---:|---:|
| Receive 64-byte datagrams | 23.7–26.9 MB/s | 29.3–30.6 MB/s | about 10–29% higher |
| Send 64 datagrams per operation | 28.0–28.4 MB/s | 38.6–39.8 MB/s | about 37–42% higher |

The receive generator queued only about 1.6 datagrams per `recvmmsg` call, so
this is evidence to retain the prototype, not a production capacity claim.
Promotion requires a real Linux NIC/RSS setup, one socket per fixed worker,
full request processing, security-policy equivalence, and p99/p99.9 results.

## Measured cache eviction

The per-shard indexed expiry heap replaces a full map scan at capacity. On the
project's 4,096-entry single-shard benchmark, insertion at capacity improved
from roughly 92–96 µs/op to 4.1–4.4 µs/op (about 22x) on an Intel i9-9880H.
Allocations remained at 10/op; most are entry/event construction outside the
eviction index. Treat this as a focused microbenchmark, not a production QPS
claim.

## Remaining performance work

- Add production-like mixed hit/miss and slow-authority load tests with explicit
  p95/p99 and overload budgets.
- Expose explicit public-recursive and conditional-forwarding modes.
- Profile long-running memory behavior and tune pool retention under realistic
  packet-size distributions.
- Prototype Linux `recvmmsg`/`sendmmsg`, then retain it only if complete
  receive-parse-route-send benchmarks improve throughput and tail latency.
- Evaluate an opt-in XDP cache-hit path separately from the portable resolver.
