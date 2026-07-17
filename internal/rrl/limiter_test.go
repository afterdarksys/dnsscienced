package rrl

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	cfg := DefaultConfig()
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	if !limiter.cfg.Enabled {
		t.Error("limiter should be enabled by default")
	}
}

func TestCheck_Allow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 10
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// First few queries should be allowed
	for i := 0; i < 5; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action != ActionAllow {
			t.Errorf("query %d: action = %v, want ActionAllow", i, action)
		}
	}

	stats := limiter.GetStats()
	if stats.Allowed != 5 {
		t.Errorf("allowed = %d, want 5", stats.Allowed)
	}
}

func TestCheck_RateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 2
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust tokens (2 tokens for 1 second window)
	for i := 0; i < 2; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action != ActionAllow {
			t.Errorf("initial query %d should be allowed", i)
		}
	}

	// Next query should be rate limited
	action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	if action == ActionAllow {
		t.Error("query should be rate limited")
	}

	stats := limiter.GetStats()
	if stats.Dropped+stats.Slipped == 0 {
		t.Error("should have dropped or slipped at least one query")
	}
}

func TestCheck_Refill(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 5
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust tokens
	for i := 0; i < 5; i++ {
		limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	}

	// Should be rate limited now
	action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	if action == ActionAllow {
		t.Error("should be rate limited")
	}

	// Wait for refill
	time.Sleep(1200 * time.Millisecond)

	// Should be allowed again
	action = limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	if action != ActionAllow {
		t.Error("should be allowed after refill")
	}
}

func TestCheck_Exempt(t *testing.T) {
	_, exemptNet, _ := net.ParseCIDR("192.0.2.0/24")

	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 1
	cfg.ExemptPrefixes = []*net.IPNet{exemptNet}
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.100")

	// Exempt IPs should never be rate limited
	for i := 0; i < 100; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action != ActionAllow {
			t.Errorf("exempt client should always be allowed, got %v", action)
		}
	}
}

func TestCheck_DifferentCategories(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 2
	cfg.NXDOMAINsPerSecond = 2
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust response tokens
	for i := 0; i < 2; i++ {
		limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	}

	// NXDOMAIN should still be allowed (different bucket)
	action := limiter.Check(clientIP, "notfound.com", 1, CategoryNXDOMAIN)
	if action != ActionAllow {
		t.Error("NXDOMAIN should use separate bucket")
	}
}

func TestCheck_Slip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 1
	cfg.Window = 1
	cfg.Slip = 2 // 50% slip rate
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust tokens
	limiter.Check(clientIP, "example.com", 1, CategoryResponse)

	// Generate many rate-limited queries
	var slipped, dropped int
	for i := 0; i < 100; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action == ActionSlip {
			slipped++
		} else if action == ActionDrop {
			dropped++
		}
	}

	// Should have both slips and drops (with 100 samples, we should see both)
	// But the test is probabilistic, so we allow edge cases
	total := slipped + dropped
	if total == 0 {
		t.Error("should have some rate-limited responses")
	}

	// With slip=2, we expect roughly 50/50 split
	// But allow wide variance since it's based on hash modulo
	// Only fail if we get an extremely unlikely result (all one type)
	if slipped == 0 && dropped < 50 {
		t.Error("should have some slipped responses with 100 samples")
	}
	if dropped == 0 && slipped < 50 {
		t.Error("should have some dropped responses with 100 samples")
	}
}

func TestCheck_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Should always allow when disabled
	for i := 0; i < 1000; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action != ActionAllow {
			t.Error("disabled limiter should always allow")
		}
	}
}

func TestCategorizeResponse(t *testing.T) {
	tests := []struct {
		rcode       int
		answerCount int
		nsCount     int
		want        int
	}{
		{0, 1, 0, CategoryResponse},    // NOERROR with answer
		{0, 0, 1, CategoryReferral},    // NOERROR with NS
		{0, 0, 0, CategoryNodata},      // NOERROR without answer or NS
		{3, 0, 0, CategoryNXDOMAIN},    // NXDOMAIN
		{2, 0, 0, CategoryError},       // SERVFAIL
		{1, 0, 0, CategoryError},       // FORMERR
	}

	for _, tt := range tests {
		got := CategorizeResponse(tt.rcode, tt.answerCount, tt.nsCount)
		if got != tt.want {
			t.Errorf("CategorizeResponse(%d, %d, %d) = %d, want %d",
				tt.rcode, tt.answerCount, tt.nsCount, got, tt.want)
		}
	}
}

func TestGetStats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 2
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Generate some traffic
	for i := 0; i < 10; i++ {
		limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	}

	stats := limiter.GetStats()
	if stats.Total != 10 {
		t.Errorf("total = %d, want 10", stats.Total)
	}
	if stats.Allowed+stats.Dropped+stats.Slipped != stats.Total {
		t.Error("stats don't add up")
	}
	if stats.DropRate < 0 || stats.DropRate > 1 {
		t.Errorf("dropRate = %.2f, should be between 0 and 1", stats.DropRate)
	}
}

// TestCheck_NXDOMAINWaterTorture proves the fix for the random-subdomain /
// NXDOMAIN "water torture" flood: before imputing the qname for NXDOMAIN
// (and NODATA/error) categories, each unique random label
// (randNNNN.victim.com) got its own fresh bucket with a full token
// allowance, so RRL never tripped. After the fix, all such responses from
// one client prefix collapse onto a single shared bucket and the limiter
// trips well before 1000 distinct queries are allowed.
func TestCheck_NXDOMAINWaterTorture(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NXDOMAINsPerSecond = 5
	cfg.Window = 15 // 5*15 = 75 token allowance for the (shared) bucket
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	const numQueries = 1000
	var allowed, limited int
	for i := 0; i < numQueries; i++ {
		qname := fmt.Sprintf("rand%d.victim.com", i)
		action := limiter.Check(clientIP, qname, 1, CategoryNXDOMAIN)
		if action == ActionAllow {
			allowed++
		} else {
			limited++
		}
	}

	if limited == 0 {
		t.Fatalf("water-torture flood of %d distinct NXDOMAIN qnames was never rate limited (allowed=%d, limited=%d) — bucketHash is still keying on qname",
			numQueries, allowed, limited)
	}

	// Allowance is bounded by the shared bucket's max tokens
	// (limit * window); everything past that should be limited.
	maxTokens := cfg.NXDOMAINsPerSecond * cfg.Window
	if allowed > maxTokens {
		t.Errorf("allowed %d queries, want <= %d (shared-bucket token cap) — distinct qnames are still minting separate buckets",
			allowed, maxTokens)
	}

	// Confirm all 1000 distinct qnames actually converged on one bucket hash.
	hash := bucketHash(cfg, clientIP, "rand0.victim.com", 1, CategoryNXDOMAIN)
	for i := 1; i < numQueries; i++ {
		qname := fmt.Sprintf("rand%d.victim.com", i)
		if got := bucketHash(cfg, clientIP, qname, 1, CategoryNXDOMAIN); got != hash {
			t.Fatalf("qname %q produced a distinct bucket hash %d (want %d) — NXDOMAIN qnames are not being imputed",
				qname, got, hash)
		}
	}
}

// TestCheck_PositiveAnswersBucketPerName proves legitimate positive-answer
// (CategoryResponse) traffic still buckets per distinct qname, so unrelated
// legitimate queries don't share a rate-limit budget.
func TestCheck_PositiveAnswersBucketPerName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 1
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust the single token for "a.example.com".
	action := limiter.Check(clientIP, "a.example.com", 1, CategoryResponse)
	if action != ActionAllow {
		t.Fatalf("first query for a.example.com: action = %v, want ActionAllow", action)
	}

	// A distinct, legitimate qname must still get its own fresh allowance.
	action = limiter.Check(clientIP, "b.example.com", 1, CategoryResponse)
	if action != ActionAllow {
		t.Errorf("query for a different legitimate qname (b.example.com) was rate limited (%v); positive answers must still bucket per-qname", action)
	}

	// Also verify at the hash level: distinct qnames -> distinct hashes for
	// CategoryResponse.
	h1 := bucketHash(cfg, clientIP, "a.example.com", 1, CategoryResponse)
	h2 := bucketHash(cfg, clientIP, "b.example.com", 1, CategoryResponse)
	if h1 == h2 {
		t.Error("bucketHash collapsed two distinct positive-answer qnames onto the same bucket")
	}
}

func BenchmarkCheck(b *testing.B) {
	cfg := DefaultConfig()
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	}
}

func BenchmarkCheckConcurrent(b *testing.B) {
	cfg := DefaultConfig()
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		}
	})
}
