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
| Is the cache lock-free? | No. It uses many independently locked shards and atomic counters. Reads contend only within a shard, but replacement currently performs linear eviction while holding that shard's lock. |
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

## Remaining performance work

- Replace linear oldest-entry scanning under a shard lock with a measured
  low-contention eviction policy.
- Add production-like mixed hit/miss and slow-authority load tests with explicit
  p95/p99 and overload budgets.
- Expose explicit public-recursive and conditional-forwarding modes.
- Profile long-running memory behavior and tune pool retention under realistic
  packet-size distributions.
- Consider platform-specific receive/send batching only after the production
  protocol and security behavior has regression coverage.
