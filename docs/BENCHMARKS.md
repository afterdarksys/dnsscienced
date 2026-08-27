# DNSScienced Benchmark Specifications

> **Benchmark design and historical results:** This document includes proposed
> benchmark harnesses, targets, and example configurations in addition to
> measurements. A code block or target below is not evidence that the harness
> is currently automated. See the [README performance section](../README.md#performance)
> for the interpretation rules applied to public claims.

Comparative wire-level load tests should use
[DNSBlast](https://github.com/afterdarksys/dnsblast), the sibling Rust toolkit
built for synchronized DNSScienced/BIND/NSD workloads, bounded HDR latency
aggregation, deterministic query plans, and versioned JSON output. The small
Go driver under `tools/bench_throughput.go` remains useful for local smoke
measurements but is not the preferred comparative harness.

## Performance Targets

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PERFORMANCE TARGETS BY TIER                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TIER 1: STANDARD                                                          │
│  ════════════════════════════════════════════════════════════════════════  │
│  Target: Small to medium deployments                                       │
│  Hardware: 4 cores, 8GB RAM, SSD                                          │
│                                                                             │
│  Metric                     Target          Notes                          │
│  ───────────────────────────────────────────────────────────────────────   │
│  UDP QPS (cached)           100,000         Single instance                │
│  UDP QPS (recursive)        10,000          Full resolution                │
│  TCP QPS                    20,000          Pipelined                      │
│  Latency p50 (cached)       < 100 μs                                      │
│  Latency p99 (cached)       < 500 μs                                      │
│  Latency p50 (recursive)    < 20 ms                                       │
│  Latency p99 (recursive)    < 100 ms                                      │
│  Memory per cached entry    < 1 KB                                        │
│  Cache capacity             1M entries      With 8GB RAM                  │
│                                                                             │
│  TIER 2: HIGH PERFORMANCE                                                  │
│  ════════════════════════════════════════════════════════════════════════  │
│  Target: Large enterprise, ISP                                            │
│  Hardware: 16 cores, 64GB RAM, NVMe                                       │
│                                                                             │
│  Metric                     Target          Notes                          │
│  ───────────────────────────────────────────────────────────────────────   │
│  UDP QPS (cached)           500,000         Single instance                │
│  UDP QPS (recursive)        50,000          With prefetch                  │
│  TCP QPS                    100,000         Pipelined                      │
│  DoT QPS                    50,000          TLS 1.3                        │
│  DoH QPS                    30,000          HTTP/2                         │
│  Latency p50 (cached)       < 50 μs                                       │
│  Latency p99 (cached)       < 200 μs                                      │
│  Memory per cached entry    < 800 bytes                                   │
│  Cache capacity             10M entries     With 64GB RAM                 │
│                                                                             │
│  TIER 3: ULTRA-LOW LATENCY                                                 │
│  ════════════════════════════════════════════════════════════════════════  │
│  Target: Financial services, HFT                                          │
│  Hardware: Dedicated cores, DPDK, huge pages                              │
│                                                                             │
│  Metric                     Target          Notes                          │
│  ───────────────────────────────────────────────────────────────────────   │
│  UDP QPS (cached)           1,000,000+      Kernel bypass                  │
│  Latency p50 (cached)       < 10 μs                                       │
│  Latency p99 (cached)       < 50 μs                                       │
│  Latency jitter             < 20 μs         Standard deviation            │
│  CPU cycles per query       < 5,000                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Benchmark Categories

### 1. Throughput Benchmarks

```go
// Queries Per Second (QPS) measurement

type ThroughputBenchmark struct {
    Name        string
    Config      BenchConfig
    Warmup      time.Duration
    Duration    time.Duration
    Clients     int
    Metrics     []string
}

var ThroughputBenchmarks = []ThroughputBenchmark{
    {
        Name: "UDP-Simple-A-Query",
        Config: BenchConfig{
            Transport:    "udp",
            QueryType:    dns.TypeA,
            QueryPattern: "www.example.com",
            CacheState:   "hot",
        },
        Duration: 60 * time.Second,
        Clients:  100,
        Metrics:  []string{"qps", "success_rate", "errors"},
    },
    {
        Name: "UDP-Mixed-Queries",
        Config: BenchConfig{
            Transport: "udp",
            QueryMix: map[uint16]float64{
                dns.TypeA:    0.60,
                dns.TypeAAAA: 0.20,
                dns.TypeMX:   0.10,
                dns.TypeTXT:  0.10,
            },
            QueryPattern: "*.example.com",
            CacheState:   "mixed",
        },
        Duration: 120 * time.Second,
        Clients:  200,
    },
    {
        Name: "TCP-Pipelined",
        Config: BenchConfig{
            Transport:       "tcp",
            PipelineDepth:   10,
            QueryType:       dns.TypeA,
            ReuseConnection: true,
        },
        Duration: 60 * time.Second,
        Clients:  50,
    },
    {
        Name: "DoT-TLS13",
        Config: BenchConfig{
            Transport:  "dot",
            TLSVersion: tls.VersionTLS13,
            QueryType:  dns.TypeA,
        },
        Duration: 60 * time.Second,
        Clients:  50,
    },
    {
        Name: "DoH-HTTP2",
        Config: BenchConfig{
            Transport:  "doh",
            HTTPVersion: 2,
            Method:     "POST",
        },
        Duration: 60 * time.Second,
        Clients:  100,
    },
    {
        Name: "Recursive-Full",
        Config: BenchConfig{
            Transport:    "udp",
            QueryType:    dns.TypeA,
            QueryPattern: "*.real-domain.com",
            CacheState:   "cold",
            Recursive:    true,
        },
        Duration: 300 * time.Second,
        Clients:  50,
    },
}
```

### 2. Latency Benchmarks

```go
// Latency distribution measurement

type LatencyBenchmark struct {
    Name       string
    Config     BenchConfig
    Duration   time.Duration
    Rate       int // Queries per second (fixed rate)
    Percentiles []float64
}

var LatencyBenchmarks = []LatencyBenchmark{
    {
        Name: "Cache-Hit-Latency",
        Config: BenchConfig{
            Transport:  "udp",
            CacheState: "hot",
            QueryType:  dns.TypeA,
        },
        Rate:        10000,
        Duration:    60 * time.Second,
        Percentiles: []float64{0.50, 0.90, 0.95, 0.99, 0.999},
    },
    {
        Name: "Cache-Miss-Latency",
        Config: BenchConfig{
            Transport:  "udp",
            CacheState: "cold",
            Recursive:  true,
        },
        Rate:        1000,
        Duration:    120 * time.Second,
        Percentiles: []float64{0.50, 0.90, 0.95, 0.99, 0.999},
    },
    {
        Name: "DNSSEC-Validation-Latency",
        Config: BenchConfig{
            Transport: "udp",
            DNSSEC:    true,
            CacheState: "cold",
        },
        Rate:        500,
        Duration:    120 * time.Second,
        Percentiles: []float64{0.50, 0.90, 0.95, 0.99},
    },
    {
        Name: "DoT-Handshake-Latency",
        Config: BenchConfig{
            Transport:       "dot",
            ReuseConnection: false, // Force new handshake
        },
        Rate:        100,
        Duration:    60 * time.Second,
        Percentiles: []float64{0.50, 0.90, 0.99},
    },
}
```

### 3. Memory Benchmarks

```go
// Memory usage measurement

type MemoryBenchmark struct {
    Name        string
    Config      BenchConfig
    CacheSize   int
    Duration    time.Duration
    Metrics     []string
}

var MemoryBenchmarks = []MemoryBenchmark{
    {
        Name: "Cache-Memory-Efficiency",
        Config: BenchConfig{
            CacheType: "memory",
        },
        CacheSize: 1000000, // 1M entries
        Duration:  300 * time.Second,
        Metrics: []string{
            "heap_alloc",
            "heap_inuse",
            "bytes_per_entry",
            "gc_pause_total",
            "gc_pause_max",
        },
    },
    {
        Name: "Zone-Memory-Usage",
        Config: BenchConfig{
            ZoneRecords: 1000000, // 1M records
        },
        Duration: 60 * time.Second,
        Metrics: []string{
            "zone_memory",
            "index_memory",
            "total_memory",
        },
    },
    {
        Name: "Connection-Memory",
        Config: BenchConfig{
            Transport:   "tcp",
            Connections: 10000,
        },
        Duration: 300 * time.Second,
        Metrics: []string{
            "memory_per_connection",
            "total_connection_memory",
        },
    },
}
```

### 4. Scalability Benchmarks

```go
// Scalability measurement

type ScalabilityBenchmark struct {
    Name       string
    Variable   string // What we're scaling
    Range      []int
    FixedRate  int
    Duration   time.Duration
}

var ScalabilityBenchmarks = []ScalabilityBenchmark{
    {
        Name:     "Client-Scalability",
        Variable: "clients",
        Range:    []int{10, 50, 100, 200, 500, 1000},
        FixedRate: 100000,
        Duration:  60 * time.Second,
    },
    {
        Name:     "Cache-Size-Scalability",
        Variable: "cache_entries",
        Range:    []int{100000, 500000, 1000000, 5000000, 10000000},
        FixedRate: 50000,
        Duration:  120 * time.Second,
    },
    {
        Name:     "Zone-Size-Scalability",
        Variable: "zone_records",
        Range:    []int{1000, 10000, 100000, 1000000},
        FixedRate: 10000,
        Duration:  60 * time.Second,
    },
    {
        Name:     "CPU-Core-Scalability",
        Variable: "gomaxprocs",
        Range:    []int{1, 2, 4, 8, 16, 32},
        FixedRate: 0, // Max throughput
        Duration:  60 * time.Second,
    },
}
```

---

## Benchmark Methodology

### Test Harness

```go
// Benchmark harness implementation

type BenchmarkHarness struct {
    Server     *Server
    Client     *BenchClient
    Metrics    *MetricsCollector
    Reporter   *Reporter
}

func (h *BenchmarkHarness) Run(b *Benchmark) *BenchmarkResult {
    // Phase 1: Warmup
    h.runWarmup(b.Warmup)

    // Phase 2: Measurement
    h.Metrics.Start()
    h.runMeasurement(b.Duration, b.Config)
    h.Metrics.Stop()

    // Phase 3: Cooldown and collection
    return h.collectResults()
}

type BenchmarkResult struct {
    Throughput ThroughputMetrics
    Latency    LatencyMetrics
    Memory     MemoryMetrics
    Errors     ErrorMetrics
    System     SystemMetrics
}

type ThroughputMetrics struct {
    QueriesTotal    int64
    QueriesPerSec   float64
    BytesSent       int64
    BytesReceived   int64
    SuccessRate     float64
}

type LatencyMetrics struct {
    Min    time.Duration
    Max    time.Duration
    Mean   time.Duration
    StdDev time.Duration
    P50    time.Duration
    P90    time.Duration
    P95    time.Duration
    P99    time.Duration
    P999   time.Duration
}
```

### Load Generation

```go
// Query generator for benchmarks

type QueryGenerator struct {
    Pattern     string
    Type        uint16
    Mix         map[uint16]float64
    Randomizer  *rand.Rand
}

func (g *QueryGenerator) Next() *dns.Message {
    qtype := g.selectType()
    qname := g.expandPattern()

    return &dns.Message{
        Header: dns.Header{
            ID:               g.nextID(),
            RecursionDesired: true,
        },
        Questions: []dns.Question{
            {Name: qname, Type: qtype, Class: dns.ClassINET},
        },
    }
}

// Pattern expansion
// "www.example.com"           -> static
// "*.example.com"             -> random subdomain
// "{seq}.example.com"         -> sequential
// "{random:8}.example.com"    -> random 8-char string
```

### Statistical Analysis

```go
// Statistical analysis of benchmark results

type StatisticalAnalysis struct {
    Samples     []float64
    Confidence  float64
}

func (s *StatisticalAnalysis) Analyze() *AnalysisResult {
    return &AnalysisResult{
        Mean:              s.mean(),
        Median:            s.percentile(0.50),
        StdDev:            s.stdDev(),
        Variance:          s.variance(),
        ConfidenceInterval: s.confidenceInterval(),
        Outliers:          s.detectOutliers(),
        Distribution:      s.fitDistribution(),
    }
}

// Detect if results are statistically significant
func (s *StatisticalAnalysis) IsSignificant(other *StatisticalAnalysis) bool {
    // Two-sample t-test
    t := s.tTest(other)
    return t > s.criticalValue()
}
```

---

## Benchmark Environment

### Hardware Specifications

```yaml
# Standard benchmark hardware profiles

profiles:
  standard:
    cpu:
      model: "Intel Xeon E-2288G"
      cores: 8
      threads: 16
      frequency: "3.7 GHz base, 5.0 GHz turbo"
    memory:
      size: 32GB
      type: "DDR4-2666 ECC"
    storage:
      type: "NVMe SSD"
      size: 500GB
      iops: "100K read, 50K write"
    network:
      speed: "10 Gbps"
      nic: "Intel X710"

  high-performance:
    cpu:
      model: "AMD EPYC 7742"
      cores: 64
      threads: 128
      frequency: "2.25 GHz base, 3.4 GHz boost"
    memory:
      size: 256GB
      type: "DDR4-3200 ECC"
    storage:
      type: "NVMe SSD RAID-0"
      size: 2TB
      iops: "500K read, 250K write"
    network:
      speed: "100 Gbps"
      nic: "Mellanox ConnectX-6"

  ultra-low-latency:
    cpu:
      model: "Intel Xeon Gold 6258R"
      cores: 28
      threads: 56
      frequency: "2.7 GHz (turbo disabled)"
    memory:
      size: 384GB
      type: "DDR4-2933 ECC"
      numa: "local only"
    storage:
      type: "Intel Optane"
      size: 1.5TB
    network:
      speed: "100 Gbps"
      nic: "Mellanox ConnectX-6 Dx"
      dpdk: true
    tuning:
      isolcpus: true
      nohz_full: true
      rcu_nocbs: true
      hugepages: "1GB"
```

### System Configuration

```bash
#!/bin/bash
# Benchmark system preparation script

# Disable CPU frequency scaling
echo "performance" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable turbo boost (for consistent results)
echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo

# Set up huge pages
echo 1024 > /proc/sys/vm/nr_hugepages

# Network tuning
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728
sysctl -w net.core.netdev_max_backlog=300000
sysctl -w net.ipv4.udp_mem="134217728 134217728 134217728"

# Disable IRQ balancing
service irqbalance stop

# Pin NIC IRQs to specific CPUs
./set_irq_affinity.sh eth0 0-3

# Disable NUMA balancing
echo 0 > /proc/sys/kernel/numa_balancing
```

---

## Benchmark Reporting

### Report Format

```yaml
# Benchmark report structure

report:
  metadata:
    timestamp: "2024-01-15T10:30:00Z"
    version: "1.0.0"
    commit: "abc123"
    environment:
      os: "Linux 6.1.0"
      cpu: "Intel Xeon E-2288G"
      memory: "32GB"
      go_version: "1.22.0"

  summary:
    throughput:
      udp_cached_qps: 450000
      tcp_qps: 85000
      dot_qps: 42000
      doh_qps: 28000
    latency:
      cached_p50: "45μs"
      cached_p99: "180μs"
      recursive_p50: "18ms"
      recursive_p99: "85ms"
    memory:
      cache_1m_entries: "850MB"
      bytes_per_entry: 850

  detailed:
    - benchmark: "UDP-Simple-A-Query"
      results:
        qps: 452340
        qps_stddev: 12500
        success_rate: 0.9999
        latency_p50: "42μs"
        latency_p99: "175μs"
        cpu_usage: 0.78
        memory_usage: "1.2GB"

  comparison:
    baseline:
      version: "0.9.0"
      date: "2024-01-01"
    changes:
      - metric: "udp_qps"
        baseline: 420000
        current: 452340
        change: "+7.7%"
      - metric: "latency_p99"
        baseline: "210μs"
        current: "175μs"
        change: "-16.7%"
```

### Visualization

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    THROUGHPUT COMPARISON                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  UDP Cached    ████████████████████████████████████████████████  452K QPS  │
│  TCP           ██████████████████                                  85K QPS  │
│  DoT           █████████                                           42K QPS  │
│  DoH           ██████                                              28K QPS  │
│  Recursive     ███                                                 12K QPS  │
│                                                                             │
│                0       100K     200K     300K     400K     500K             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    LATENCY DISTRIBUTION (Cached)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│     Count                                                                   │
│       │                                                                     │
│  100K │    ▄▄▄▄                                                            │
│       │   ██████                                                           │
│   50K │  ████████▄                                                         │
│       │ ██████████▄▄                                                       │
│    0  └──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──                                   │
│          10  20  40  60  80 100 150 200 500   μs                           │
│                                                                             │
│  p50: 42μs  p90: 95μs  p99: 175μs  p999: 450μs                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Comparison Benchmarks

### vs. Other DNS Servers

```yaml
# Comparison benchmark suite

comparisons:
  - name: "BIND 9.18"
    config:
      server: "bind9"
      version: "9.18.20"
    benchmarks:
      - throughput
      - latency
      - memory

  - name: "Unbound 1.19"
    config:
      server: "unbound"
      version: "1.19.0"
    benchmarks:
      - throughput
      - latency
      - memory
      - dnssec-validation

  - name: "PowerDNS Recursor 5.0"
    config:
      server: "pdns-recursor"
      version: "5.0.1"
    benchmarks:
      - throughput
      - latency

  - name: "CoreDNS 1.11"
    config:
      server: "coredns"
      version: "1.11.1"
    benchmarks:
      - throughput
      - latency
      - memory
```

### Benchmark Results Template

```markdown
## Benchmark Results: v1.0.0 vs Competitors

### Throughput (Queries/Second)

| Server | UDP Cached | TCP | DoT | DoH |
|--------|------------|-----|-----|-----|
| DNSScienced | **452,340** | **85,000** | **42,000** | **28,000** |
| BIND 9.18 | 320,000 | 45,000 | 25,000 | 18,000 |
| Unbound 1.19 | 380,000 | 55,000 | 30,000 | N/A |
| CoreDNS 1.11 | 290,000 | 40,000 | 22,000 | 15,000 |

### Latency P99 (microseconds)

| Server | UDP Cached | Recursive |
|--------|------------|-----------|
| DNSScienced | **175** | **85,000** |
| BIND 9.18 | 350 | 95,000 |
| Unbound 1.19 | 220 | 78,000 |
| CoreDNS 1.11 | 280 | 92,000 |

### Memory Efficiency (MB per 1M cache entries)

| Server | Memory |
|--------|--------|
| DNSScienced | **850** |
| BIND 9.18 | 1,200 |
| Unbound 1.19 | 950 |
```

---

## Continuous Benchmarking

### Regression Detection

```yaml
# Benchmark regression thresholds

thresholds:
  throughput:
    # Alert if throughput drops by more than 5%
    warning: -5%
    critical: -10%

  latency:
    # Alert if latency increases by more than 10%
    warning: +10%
    critical: +20%

  memory:
    # Alert if memory usage increases by more than 15%
    warning: +15%
    critical: +30%

# Automated benchmark on every commit
automation:
  on_commit:
    - quick-benchmark  # 5 minutes, catches major regressions

  on_merge:
    - full-benchmark   # 30 minutes, comprehensive

  nightly:
    - extended-benchmark  # 2 hours, with comparisons
```

---

*Document Version: 1.0*
*Benchmark Specification*
