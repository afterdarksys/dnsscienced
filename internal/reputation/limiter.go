// Package reputation implements bounded, adaptive per-client DNS admission
// control. It intentionally performs no background work: score decay and token
// refill are applied lazily on the query path.
package reputation

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const maxShardCount = 64

var (
	limitedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dnsscienced_client_reputation_limited_total",
		Help: "Total DNS queries denied by adaptive client reputation limits.",
	})
	signalsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dnsscienced_client_reputation_signals_total",
		Help: "Total suspicious client reputation signals by bounded signal type.",
	}, []string{"signal"})
	evictionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dnsscienced_client_reputation_evictions_total",
		Help: "Total client reputation entries evicted from the bounded cache.",
	})
)

// Config controls adaptive client reputation admission.
type Config struct {
	Enabled           bool     `yaml:"enabled"`
	BaseQPS           int      `yaml:"base_qps"`
	MinimumQPS        int      `yaml:"minimum_qps"`
	Burst             int      `yaml:"burst"`
	MaxEntries        int      `yaml:"max_entries"`
	MaxScore          int      `yaml:"max_score"`
	DecayPerSecond    int      `yaml:"decay_per_second"`
	ProtocolPenalty   int      `yaml:"protocol_penalty"`
	ComplexityPenalty int      `yaml:"complexity_penalty"`
	PolicyPenalty     int      `yaml:"policy_penalty"`
	RateLimitPenalty  int      `yaml:"rate_limit_penalty"`
	IPv4PrefixLen     int      `yaml:"ipv4_prefix_len"`
	IPv6PrefixLen     int      `yaml:"ipv6_prefix_len"`
	Action            string   `yaml:"action"`
	ExemptCIDRs       []string `yaml:"exempt_cidrs"`
}

// DefaultConfig returns secure, carrier-oriented defaults. Exact IPv4 clients
// are tracked independently while IPv6 clients are grouped by /64 to prevent
// trivial address rotation within a subscriber prefix.
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		BaseQPS:           500,
		MinimumQPS:        25,
		Burst:             1000,
		MaxEntries:        65536,
		MaxScore:          100,
		DecayPerSecond:    1,
		ProtocolPenalty:   20,
		ComplexityPenalty: 40,
		PolicyPenalty:     2,
		RateLimitPenalty:  5,
		IPv4PrefixLen:     32,
		IPv6PrefixLen:     64,
		Action:            "drop",
		ExemptCIDRs:       []string{"127.0.0.0/8", "::1/128"},
	}
}

// Signal identifies a bounded class of suspicious behavior.
type Signal uint8

const (
	SignalProtocol Signal = iota
	SignalComplexity
	SignalPolicy
	SignalRateLimited
)

func (s Signal) String() string {
	switch s {
	case SignalProtocol:
		return "protocol"
	case SignalComplexity:
		return "complexity"
	case SignalPolicy:
		return "policy"
	case SignalRateLimited:
		return "rate_limited"
	default:
		return "unknown"
	}
}

type clientKey struct {
	addr netip.Addr
}

type entry struct {
	score      int
	tokens     float64
	lastRefill int64
	lastDecay  int64
}

type shard struct {
	mu       sync.Mutex
	entries  map[clientKey]*entry
	ring     []clientKey
	cursor   int
	capacity int
}

// Limiter is a fixed-capacity, sharded adaptive admission limiter.
type Limiter struct {
	cfg      Config
	shards   []shard
	exempt   []netip.Prefix
	tracked  atomic.Int64
	allowed  atomic.Uint64
	limited  atomic.Uint64
	observed atomic.Uint64
	evicted  atomic.Uint64
}

// Stats is an atomic snapshot of limiter activity.
type Stats struct {
	Tracked  int64
	Allowed  uint64
	Limited  uint64
	Observed uint64
	Evicted  uint64
}

// New validates cfg and creates a limiter without background goroutines.
func New(cfg Config) (*Limiter, error) {
	if !cfg.Enabled {
		return &Limiter{cfg: cfg}, nil
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	exempt := make([]netip.Prefix, 0, len(cfg.ExemptCIDRs))
	for _, raw := range cfg.ExemptCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("client_reputation.exempt_cidrs %q: %w", raw, err)
		}
		exempt = append(exempt, prefix.Masked())
	}
	shardCount := min(maxShardCount, cfg.MaxEntries)
	l := &Limiter{
		cfg:    cfg,
		shards: make([]shard, shardCount),
		exempt: exempt,
	}
	baseCapacity := cfg.MaxEntries / shardCount
	remainder := cfg.MaxEntries % shardCount
	for i := range l.shards {
		capacity := baseCapacity
		if i < remainder {
			capacity++
		}
		l.shards[i] = shard{
			entries:  make(map[clientKey]*entry, capacity),
			ring:     make([]clientKey, 0, capacity),
			capacity: capacity,
		}
	}
	return l, nil
}

func validateConfig(cfg Config) error {
	values := []struct {
		name, requirement string
		value, min, max   int
	}{
		{"base_qps", "between 1 and 10000000", cfg.BaseQPS, 1, 10_000_000},
		{"minimum_qps", "between 1 and base_qps", cfg.MinimumQPS, 1, cfg.BaseQPS},
		{"burst", "between 1 and 10000000", cfg.Burst, 1, 10_000_000},
		{"max_entries", "between 1 and 1048576", cfg.MaxEntries, 1, 1_048_576},
		{"max_score", "between 1 and 1000000", cfg.MaxScore, 1, 1_000_000},
		{"decay_per_second", "between 1 and max_score", cfg.DecayPerSecond, 1, cfg.MaxScore},
		{"protocol_penalty", "between 1 and max_score", cfg.ProtocolPenalty, 1, cfg.MaxScore},
		{"complexity_penalty", "between 1 and max_score", cfg.ComplexityPenalty, 1, cfg.MaxScore},
		{"policy_penalty", "between 1 and max_score", cfg.PolicyPenalty, 1, cfg.MaxScore},
		{"rate_limit_penalty", "between 1 and max_score", cfg.RateLimitPenalty, 1, cfg.MaxScore},
		{"ipv4_prefix_len", "between 0 and 32", cfg.IPv4PrefixLen, 0, 32},
		{"ipv6_prefix_len", "between 0 and 128", cfg.IPv6PrefixLen, 0, 128},
	}
	for _, field := range values {
		if field.value < field.min || field.value > field.max {
			return fmt.Errorf("client_reputation.%s must be %s", field.name, field.requirement)
		}
	}
	if cfg.Action != "drop" && cfg.Action != "refused" {
		return fmt.Errorf("client_reputation.action must be drop or refused")
	}
	return nil
}

// Allow reports whether a query from ip is admitted at now.
func (l *Limiter) Allow(ip net.IP, now time.Time) bool {
	if l == nil || !l.cfg.Enabled || ip == nil || l.isExempt(ip) {
		if l != nil {
			l.allowed.Add(1)
		}
		return true
	}
	key, ok := l.keyFor(ip)
	if !ok {
		l.allowed.Add(1)
		return true
	}
	nowNS := now.UnixNano()
	s := &l.shards[shardIndex(key, len(l.shards))]
	s.mu.Lock()
	e := l.getOrInsertLocked(s, key, nowNS)
	l.decayLocked(e, nowNS)
	rate := l.effectiveRate(e.score)
	elapsed := float64(nowNS-e.lastRefill) / float64(time.Second)
	if elapsed > 0 {
		e.tokens = math.Min(float64(l.cfg.Burst), e.tokens+elapsed*rate)
		e.lastRefill = nowNS
	}
	if e.tokens >= 1 {
		e.tokens--
		s.mu.Unlock()
		l.allowed.Add(1)
		return true
	}
	e.score = min(l.cfg.MaxScore, e.score+l.cfg.RateLimitPenalty)
	s.mu.Unlock()
	l.limited.Add(1)
	l.observed.Add(1)
	limitedTotal.Inc()
	signalsTotal.WithLabelValues(SignalRateLimited.String()).Inc()
	return false
}

// Observe applies a suspicious-behavior signal to ip at now.
func (l *Limiter) Observe(ip net.IP, signal Signal, now time.Time) {
	if l == nil || !l.cfg.Enabled || ip == nil || l.isExempt(ip) {
		return
	}
	key, ok := l.keyFor(ip)
	if !ok {
		return
	}
	nowNS := now.UnixNano()
	s := &l.shards[shardIndex(key, len(l.shards))]
	s.mu.Lock()
	e := l.getOrInsertLocked(s, key, nowNS)
	l.decayLocked(e, nowNS)
	e.score = min(l.cfg.MaxScore, e.score+l.penalty(signal))
	s.mu.Unlock()
	l.observed.Add(1)
	signalsTotal.WithLabelValues(signal.String()).Inc()
}

// Action returns the configured denial action.
func (l *Limiter) Action() string {
	if l == nil {
		return "drop"
	}
	return l.cfg.Action
}

// Stats returns an atomic activity snapshot.
func (l *Limiter) Stats() Stats {
	if l == nil {
		return Stats{}
	}
	return Stats{
		Tracked:  l.tracked.Load(),
		Allowed:  l.allowed.Load(),
		Limited:  l.limited.Load(),
		Observed: l.observed.Load(),
		Evicted:  l.evicted.Load(),
	}
}

func (l *Limiter) getOrInsertLocked(s *shard, key clientKey, nowNS int64) *entry {
	if existing, ok := s.entries[key]; ok {
		return existing
	}
	if len(s.entries) == s.capacity {
		victim := s.ring[s.cursor]
		delete(s.entries, victim)
		s.ring[s.cursor] = key
		s.cursor = (s.cursor + 1) % s.capacity
		l.evicted.Add(1)
		evictionsTotal.Inc()
	} else {
		s.ring = append(s.ring, key)
		l.tracked.Add(1)
	}
	e := &entry{
		tokens:     float64(l.cfg.Burst),
		lastRefill: nowNS,
		lastDecay:  nowNS,
	}
	s.entries[key] = e
	return e
}

func (l *Limiter) decayLocked(e *entry, nowNS int64) {
	elapsedSeconds := (nowNS - e.lastDecay) / int64(time.Second)
	if elapsedSeconds <= 0 {
		return
	}
	decay := elapsedSeconds * int64(l.cfg.DecayPerSecond)
	if decay >= int64(e.score) {
		e.score = 0
	} else {
		e.score -= int(decay)
	}
	e.lastDecay += elapsedSeconds * int64(time.Second)
}

func (l *Limiter) effectiveRate(score int) float64 {
	span := l.cfg.BaseQPS - l.cfg.MinimumQPS
	reduction := float64(span*score) / float64(l.cfg.MaxScore)
	return math.Max(float64(l.cfg.MinimumQPS), float64(l.cfg.BaseQPS)-reduction)
}

func (l *Limiter) penalty(signal Signal) int {
	switch signal {
	case SignalProtocol:
		return l.cfg.ProtocolPenalty
	case SignalComplexity:
		return l.cfg.ComplexityPenalty
	case SignalPolicy:
		return l.cfg.PolicyPenalty
	case SignalRateLimited:
		return l.cfg.RateLimitPenalty
	default:
		return l.cfg.ProtocolPenalty
	}
}

func (l *Limiter) isExempt(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range l.exempt {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (l *Limiter) keyFor(ip net.IP) (clientKey, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return clientKey{}, false
	}
	addr = addr.Unmap()
	bits := l.cfg.IPv6PrefixLen
	if addr.Is4() {
		bits = l.cfg.IPv4PrefixLen
	}
	return clientKey{addr: netip.PrefixFrom(addr, bits).Masked().Addr()}, true
}

func shardIndex(key clientKey, count int) int {
	addr := key.addr.As16()
	hash := uint64(1469598103934665603)
	for _, b := range addr {
		hash ^= uint64(b)
		hash *= 1099511628211
	}
	return int(hash % uint64(count))
}
