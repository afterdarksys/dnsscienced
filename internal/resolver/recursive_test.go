package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/cookie"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/miekg/dns"
)

func TestNewRecursive(t *testing.T) {
	cfg := Config{
		CacheConfig: cache.Config{
			ShardCount: 256,
			MaxEntries: 10000,
		},
		Workers:       100,
		QueryTimeout:  5 * time.Second,
		MaxIterations: 20,
		EnableCookies: false,
		EnableRRL:     false,
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	if r.cache == nil {
		t.Error("cache not initialized")
	}
	if r.workerPool == nil {
		t.Error("worker pool not initialized")
	}
	if r.client == nil {
		t.Error("DNS client not initialized")
	}
}

func TestNewRecursive_WithDefaults(t *testing.T) {
	cfg := Config{}
	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	if r.cfg.QueryTimeout != 5*time.Second {
		t.Errorf("QueryTimeout = %v, want 5s", r.cfg.QueryTimeout)
	}
	if r.cfg.MaxIterations != 20 {
		t.Errorf("MaxIterations = %d, want 20", r.cfg.MaxIterations)
	}
	if r.cfg.Workers != 100 {
		t.Errorf("Workers = %d, want 100", r.cfg.Workers)
	}
}

func TestNewRecursive_WithCookies(t *testing.T) {
	cfg := Config{
		EnableCookies: true,
		CookieConfig: cookie.Config{
			Enabled:       true,
			ClusterSecret: []byte("test-secret-key-for-testing-123"),
		},
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	if r.cookies == nil {
		t.Error("cookies not initialized")
	}
}

func TestNewRecursive_WithRRL(t *testing.T) {
	cfg := Config{
		EnableRRL: true,
		RRLConfig: rrl.DefaultConfig(),
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	if r.rrl == nil {
		t.Error("RRL not initialized")
	}
}

func TestResolve_NoQuestion(t *testing.T) {
	cfg := Config{}
	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	msg := new(dns.Msg)
	// No question set

	ctx := context.Background()
	clientIP := net.ParseIP("192.0.2.1")

	_, err = r.Resolve(ctx, msg, clientIP)
	if err == nil {
		t.Error("Resolve() should error with no question")
	}
}

func TestResolve_CacheHit(t *testing.T) {
	cfg := Config{
		CacheConfig: cache.Config{
			ShardCount: 256,
			MaxEntries: 10000,
		},
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	// Create a cached response
	cachedResp := new(dns.Msg)
	cachedResp.SetQuestion("example.com.", dns.TypeA)
	cachedResp.Response = true
	cachedResp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP("93.184.216.34"),
		},
	}

	// Pack and cache it
	packed, err := cachedResp.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	// Calculate cache key same way resolver does
	question := cachedResp.Question[0]
	cacheKey := hashQuery(question.Name, question.Qtype, question.Qclass)

	r.cache.Set(cacheKey, &cache.Entry{
		Data:      packed,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		OrigTTL:   3600,
		QName:     question.Name,
		QType:     question.Qtype,
		QClass:    question.Qclass,
	})

	// Now query it
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.Id = 0x1234

	ctx := context.Background()
	clientIP := net.ParseIP("192.0.2.1")

	resp, err := r.Resolve(ctx, query, clientIP)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if resp.Id != 0x1234 {
		t.Errorf("Response ID = 0x%x, want 0x1234", resp.Id)
	}
	if len(resp.Answer) == 0 {
		t.Error("Expected cached answer")
	}
	if !resp.RecursionAvailable {
		t.Error("RecursionAvailable should be true")
	}
}

func TestResolve_CacheMiss(t *testing.T) {
	// This test would require a working network connection
	// and would actually query DNS servers. For unit tests,
	// we skip this and rely on integration tests.
	t.Skip("Skipping cache miss test - requires network")
}

func TestFindGlue(t *testing.T) {
	cfg := Config{}
	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	msg := new(dns.Msg)
	msg.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "ns1.example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP("192.0.2.1"),
		},
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "ns2.example.com.",
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}

	// Test A record glue
	ip := r.findGlue(msg, "ns1.example.com.")
	if ip != "192.0.2.1" {
		t.Errorf("findGlue() = %s, want 192.0.2.1", ip)
	}

	// Test AAAA record glue
	ip = r.findGlue(msg, "ns2.example.com.")
	if ip != "2001:db8::1" {
		t.Errorf("findGlue() = %s, want 2001:db8::1", ip)
	}

	// Test missing glue
	ip = r.findGlue(msg, "ns3.example.com.")
	if ip != "" {
		t.Errorf("findGlue() = %s, want empty string", ip)
	}
}

func TestGetTTL(t *testing.T) {
	tests := []struct {
		name     string
		msg      *dns.Msg
		expected uint32
	}{
		{
			name: "single answer",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Ttl: 300},
					},
				},
			},
			expected: 300,
		},
		{
			name: "multiple answers - return minimum",
			msg: &dns.Msg{
				Answer: []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Ttl: 300},
					},
					&dns.A{
						Hdr: dns.RR_Header{Ttl: 100},
					},
					&dns.A{
						Hdr: dns.RR_Header{Ttl: 500},
					},
				},
			},
			expected: 100,
		},
		{
			name: "no answers - default",
			msg: &dns.Msg{
				Answer: []dns.RR{},
			},
			expected: 300,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getTTL(tt.msg)
			if got != tt.expected {
				t.Errorf("getTTL() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestGetStats(t *testing.T) {
	cfg := Config{
		EnableRRL: true,
		RRLConfig: rrl.DefaultConfig(),
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	stats := r.GetStats()

	// Should have cache stats (Size field exists)
	_ = stats.Cache.Size

	// Should have worker pool stats
	if stats.Pool.Workers == 0 {
		t.Error("Expected pool stats")
	}

	// Should have RRL stats
	if stats.RRL == nil {
		t.Error("Expected RRL stats")
	}
}

func TestGetStats_NoRRL(t *testing.T) {
	cfg := Config{
		EnableRRL: false,
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	stats := r.GetStats()

	// Should NOT have RRL stats
	if stats.RRL != nil {
		t.Error("Should not have RRL stats when disabled")
	}
}

func TestClose(t *testing.T) {
	cfg := Config{
		EnableRRL: true,
		RRLConfig: rrl.DefaultConfig(),
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}

	// Should not panic
	err = r.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestResolveIterative_MaxIterations(t *testing.T) {
	cfg := Config{
		MaxIterations: 2, // Very low limit
		QueryTimeout:  1 * time.Second,
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	// This would hit max iterations if it tried to resolve
	// (but will likely fail on network first in unit tests)
	ctx := context.Background()
	_, err = r.resolveIterative(ctx, "example.com.", dns.TypeA, dns.ClassINET)

	// Should either timeout or hit max iterations
	// Both are acceptable for this test
	if err == nil {
		t.Error("Expected error for max iterations or timeout")
	}
}

func TestResolve_ContextCancellation(t *testing.T) {
	cfg := Config{
		QueryTimeout: 10 * time.Second,
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		t.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	clientIP := net.ParseIP("192.0.2.1")

	_, err = r.Resolve(ctx, query, clientIP)
	if err == nil {
		t.Error("Expected error from cancelled context")
	}
}

// Helper function that matches the one in recursive.go
func hashQuery(name string, qtype, qclass uint16) uint64 {
	// Simple hash for testing - matches packet.HashQuery
	hash := uint64(0)
	for _, c := range name {
		hash = hash*31 + uint64(c)
	}
	hash = hash*31 + uint64(qtype)
	hash = hash*31 + uint64(qclass)
	return hash
}

// Benchmark recursive resolver (end-to-end)
func BenchmarkResolve_CacheHit(b *testing.B) {
	cfg := Config{
		CacheConfig: cache.Config{
			ShardCount: 256,
			MaxEntries: 10000,
		},
	}

	r, err := NewRecursive(cfg)
	if err != nil {
		b.Fatalf("NewRecursive() error = %v", err)
	}
	defer r.Close()

	// Pre-populate cache
	cachedResp := new(dns.Msg)
	cachedResp.SetQuestion("example.com.", dns.TypeA)
	cachedResp.Response = true
	cachedResp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP("93.184.216.34"),
		},
	}

	packed, _ := cachedResp.Pack()
	question := cachedResp.Question[0]
	cacheKey := hashQuery(question.Name, question.Qtype, question.Qclass)

	r.cache.Set(cacheKey, &cache.Entry{
		Data:      packed,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		OrigTTL:   3600,
		QName:     question.Name,
		QType:     question.Qtype,
		QClass:    question.Qclass,
	})

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	ctx := context.Background()
	clientIP := net.ParseIP("192.0.2.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query.Id = uint16(i)
		_, _ = r.Resolve(ctx, query, clientIP)
	}
}

func BenchmarkFindGlue(b *testing.B) {
	cfg := Config{}
	r, _ := NewRecursive(cfg)
	defer r.Close()

	msg := new(dns.Msg)
	for i := 0; i < 10; i++ {
		msg.Extra = append(msg.Extra, &dns.A{
			Hdr: dns.RR_Header{
				Name:   "ns1.example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP("192.0.2.1"),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.findGlue(msg, "ns1.example.com.")
	}
}

func BenchmarkGetTTL(b *testing.B) {
	msg := &dns.Msg{
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Ttl: 300}},
			&dns.A{Hdr: dns.RR_Header{Ttl: 100}},
			&dns.A{Hdr: dns.RR_Header{Ttl: 500}},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getTTL(msg)
	}
}
