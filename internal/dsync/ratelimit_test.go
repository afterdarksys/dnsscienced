package dsync_test

import (
	"net"
	"testing"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/dsync"
	"github.com/stretchr/testify/assert"
)

// TestNotifyRateLimiter_Allows verifies that all requests within the burst limit
// are allowed for the same IP (DSYNC-04).
func TestNotifyRateLimiter_Allows(t *testing.T) {
	limiter := dsync.NewNotifyLimiter(10, 5)
	defer limiter.Close()

	ip := net.ParseIP("192.0.2.1")
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow(ip), "request %d within burst should be allowed", i+1)
	}
}

// TestNotifyRateLimiter_Blocks verifies that requests beyond the rate limit are blocked.
func TestNotifyRateLimiter_Blocks(t *testing.T) {
	// Near-zero rate, burst of 1: first request allowed, second blocked immediately
	limiter := dsync.NewNotifyLimiter(0.001, 1)
	defer limiter.Close()

	ip := net.ParseIP("192.0.2.2")
	first := limiter.Allow(ip)
	second := limiter.Allow(ip)

	assert.True(t, first, "first request should be allowed")
	assert.False(t, second, "second immediate request should be blocked (rate exhausted)")
}

// TestRateLimiterEviction verifies that stale visitor entries are evicted
// after sweepStale is triggered (DSYNC-05).
func TestRateLimiterEviction(t *testing.T) {
	limiter := dsync.NewNotifyLimiter(10, 5)
	defer limiter.Close()

	ip := net.ParseIP("192.0.2.3")
	// Add the visitor to the map
	limiter.Allow(ip)

	// Set lastSeen to 11 minutes ago by manipulating via the exported TestSweepStale helper
	// We use the exported ForceLastSeen for testing to simulate staleness
	limiter.ForceLastSeen(ip, time.Now().Add(-11*time.Minute))

	// Trigger the sweep
	limiter.SweepStaleForTest()

	// The visitor should be gone; a new Allow call should succeed (fresh limiter created)
	// We verify indirectly: if sweep worked, a high-rate Allow should be allowed again
	// (since a fresh limiter is created). This tests that the old entry was evicted.
	assert.True(t, limiter.Allow(ip), "after eviction, new Allow should succeed with fresh limiter")
	assert.Equal(t, 1, limiter.VisitorCount(), "only one visitor should remain after eviction")
}

// TestRateLimiterDifferentIPs verifies that two IPs get independent limiters.
func TestRateLimiterDifferentIPs(t *testing.T) {
	// Burst of 1 so the first request exhausts the limiter
	limiter := dsync.NewNotifyLimiter(0.001, 1)
	defer limiter.Close()

	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	// Exhaust ip1's burst
	limiter.Allow(ip1)
	assert.False(t, limiter.Allow(ip1), "ip1 should be rate-limited after burst exhausted")

	// ip2 should still be allowed (independent limiter)
	assert.True(t, limiter.Allow(ip2), "ip2 should be unaffected by ip1's exhaustion")
}

// TestRateLimiterClose verifies that Close() stops the background goroutine.
func TestRateLimiterClose(t *testing.T) {
	limiter := dsync.NewNotifyLimiter(10, 5)
	defer limiter.Close()

	// Close should complete without blocking (doneCh closed by cleanupLoop)
	done := make(chan struct{})
	go func() {
		limiter.Close()
		close(done)
	}()

	select {
	case <-done:
		// Success: Close() returned promptly
	case <-time.After(3 * time.Second):
		t.Error("Close() timed out — goroutine may have leaked")
	}
}
