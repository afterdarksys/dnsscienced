package reputation

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestLimiterAdaptsRateToReputationAndDecays(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseQPS = 10
	cfg.MinimumQPS = 1
	cfg.Burst = 2
	cfg.MaxEntries = 16
	cfg.MaxScore = 10
	cfg.ProtocolPenalty = 9
	cfg.ComplexityPenalty = 10
	cfg.PolicyPenalty = 1
	cfg.RateLimitPenalty = 1
	cfg.DecayPerSecond = 1
	cfg.ExemptCIDRs = nil
	limiter, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("192.0.2.10")
	now := time.Unix(100, 0)

	limiter.Observe(ip, SignalProtocol, now)
	if !limiter.Allow(ip, now) || !limiter.Allow(ip, now) {
		t.Fatal("initial burst was not admitted")
	}
	if limiter.Allow(ip, now) {
		t.Fatal("query beyond burst was admitted")
	}
	if limiter.Allow(ip, now.Add(100*time.Millisecond)) {
		t.Fatal("poor-reputation client refilled at the base rate")
	}
	if !limiter.Allow(ip, now.Add(10*time.Second)) {
		t.Fatal("decayed client did not recover")
	}
	stats := limiter.Stats()
	if stats.Limited != 2 || stats.Observed < 3 || stats.Tracked != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestLimiterBoundsCacheWithConstantTimeEviction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxEntries = 2
	cfg.ExemptCIDRs = nil
	limiter, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	for _, raw := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		limiter.Observe(net.ParseIP(raw), SignalPolicy, now)
	}
	stats := limiter.Stats()
	if stats.Tracked != 2 || stats.Evicted != 1 {
		t.Fatalf("unexpected bounded-cache stats: %+v", stats)
	}
}

func TestLimiterGroupsIPv6AndHonorsExemptions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseQPS = 1
	cfg.MinimumQPS = 1
	cfg.Burst = 1
	cfg.MaxEntries = 16
	cfg.ExemptCIDRs = []string{"192.0.2.0/24"}
	limiter, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if !limiter.Allow(net.ParseIP("192.0.2.5"), now) ||
		!limiter.Allow(net.ParseIP("192.0.2.5"), now) {
		t.Fatal("exempt client was limited")
	}
	if !limiter.Allow(net.ParseIP("2001:db8::1"), now) {
		t.Fatal("first IPv6 query was limited")
	}
	if limiter.Allow(net.ParseIP("2001:db8::2"), now) {
		t.Fatal("clients in the same IPv6 /64 did not share a bucket")
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinimumQPS = cfg.BaseQPS + 1
	if _, err := New(cfg); err == nil {
		t.Fatal("minimum_qps above base_qps was accepted")
	}
	cfg = DefaultConfig()
	cfg.ExemptCIDRs = []string{"not-a-cidr"}
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid exempt CIDR was accepted")
	}
	cfg = DefaultConfig()
	cfg.Action = "amplify"
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid action was accepted")
	}
}

func TestLimiterConcurrentAccessRemainsBounded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxEntries = 128
	cfg.ExemptCIDRs = nil
	limiter, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	var wg sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for query := 0; query < 1000; query++ {
				ip := net.IPv4(198, 51, byte(worker), byte(query))
				limiter.Observe(ip, SignalPolicy, now)
				limiter.Allow(ip, now)
			}
		}(worker)
	}
	wg.Wait()
	stats := limiter.Stats()
	if stats.Tracked > int64(cfg.MaxEntries) {
		t.Fatalf("tracked %d entries, configured maximum is %d", stats.Tracked, cfg.MaxEntries)
	}
	if stats.Evicted == 0 {
		t.Fatal("concurrent churn did not exercise bounded eviction")
	}
}

func BenchmarkLimiterAllowExistingClient(b *testing.B) {
	cfg := DefaultConfig()
	cfg.BaseQPS = 10_000_000
	cfg.MinimumQPS = 10_000_000
	cfg.Burst = 10_000_000
	cfg.MaxEntries = 1024
	cfg.ExemptCIDRs = nil
	limiter, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	ip := net.ParseIP("192.0.2.10")
	limiter.Allow(ip, time.Now())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow(ip, time.Now())
	}
}
