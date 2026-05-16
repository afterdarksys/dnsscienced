package dsync

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// visitor holds a per-source-IP rate limiter and its last-seen time.
// The lastSeen field is updated on every Allow() call and used by sweepStale()
// to evict inactive entries (T-08-02: prevents unbounded map growth under IP spoofing).
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NotifyLimiter is a per-source-IP token bucket rate limiter for inbound NOTIFY
// messages. It satisfies RFC 9859 §5's MUST rate limit requirement.
//
// A background goroutine sweeps stale entries every 5 minutes, evicting visitors
// last-seen more than 10 minutes ago.
type NotifyLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	r        rate.Limit
	b        int
	stopCh   chan struct{}
	doneCh   chan struct{}
	closeOnce sync.Once
}

// NewNotifyLimiter creates a NotifyLimiter with the given rate (requests per second)
// and burst size. It starts a background goroutine to sweep stale visitor entries.
func NewNotifyLimiter(rps float64, burst int) *NotifyLimiter {
	nl := &NotifyLimiter{
		visitors: make(map[string]*visitor),
		r:        rate.Limit(rps),
		b:        burst,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go nl.cleanupLoop()
	return nl
}

// Allow reports whether the source IP is within the rate limit.
// It creates a new per-IP limiter on first use and updates the lastSeen timestamp.
func (nl *NotifyLimiter) Allow(ip net.IP) bool {
	key := ip.String()

	nl.mu.Lock()
	v, ok := nl.visitors[key]
	if !ok {
		v = &visitor{
			limiter: rate.NewLimiter(nl.r, nl.b),
		}
		nl.visitors[key] = v
	}
	v.lastSeen = time.Now()
	lim := v.limiter
	nl.mu.Unlock()

	return lim.Allow()
}

// sweepStale deletes visitor entries that have not been seen for more than 10 minutes.
func (nl *NotifyLimiter) sweepStale() {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	for key, v := range nl.visitors {
		if time.Since(v.lastSeen) > 10*time.Minute {
			delete(nl.visitors, key)
		}
	}
}

// cleanupLoop runs in a goroutine and calls sweepStale every 5 minutes.
// It exits when stopCh is closed, then closes doneCh to signal completion.
func (nl *NotifyLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			nl.sweepStale()
		case <-nl.stopCh:
			close(nl.doneCh)
			return
		}
	}
}

// Close stops the background cleanup goroutine and waits for it to exit.
// Always call Close() when done with a NotifyLimiter to avoid goroutine leaks.
// Safe to call multiple times; subsequent calls are no-ops.
func (nl *NotifyLimiter) Close() {
	nl.closeOnce.Do(func() {
		close(nl.stopCh)
		<-nl.doneCh
	})
}

// ForceLastSeen sets the lastSeen time for a given IP's visitor entry.
// This is exported for use in tests to simulate stale entries.
func (nl *NotifyLimiter) ForceLastSeen(ip net.IP, t time.Time) {
	key := ip.String()
	nl.mu.Lock()
	defer nl.mu.Unlock()
	if v, ok := nl.visitors[key]; ok {
		v.lastSeen = t
	}
}

// SweepStaleForTest calls sweepStale, exported for test use.
func (nl *NotifyLimiter) SweepStaleForTest() {
	nl.sweepStale()
}

// VisitorCount returns the number of active visitor entries. Exported for tests.
func (nl *NotifyLimiter) VisitorCount() int {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	return len(nl.visitors)
}
