package cache

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestPrefetchCoalescesConcurrentHits(t *testing.T) {
	c := NewShardedCache(Config{
		ShardCount:        1,
		MaxEntries:        10,
		Prefetch:          true,
		PrefetchMinTTLPct: 0.1,
	})
	defer c.Close()

	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	c.SetPrefetchFunc(func(string, uint16, uint16) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
	})

	const key = uint64(42)
	c.Set(key, &Entry{
		ExpiresAt: time.Now().Add(time.Second),
		OrigTTL:   100,
		QName:     "popular.example.",
		QType:     1,
		QClass:    1,
	})

	for range 100 {
		if _, ok := c.Get(key); !ok {
			t.Fatal("expected cache hit")
		}
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("prefetch callback did not start")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("prefetch callbacks = %d, want 1 while refresh is in flight", got)
	}
	close(release)
}

func TestValidationModes(t *testing.T) {
	// 1. Test Pass Mode
	t.Run("Pass Mode", func(t *testing.T) {
		c := NewShardedCache(Config{
			ValidationMode: ValidationModePass,
		})
		defer c.Close()

		entry := &Entry{
			QName:           "invalid.com",
			DNSSECValidated: false,
			ExpiresAt:       time.Now().Add(time.Hour),
		}
		hash := uint64(123)
		c.Set(hash, entry)

		if _, ok := c.Get(hash); !ok {
			t.Error("Pass mode should cache invalid entry")
		}
	})

	// 2. Test Enforced Mode
	t.Run("Enforced Mode", func(t *testing.T) {
		c := NewShardedCache(Config{
			ValidationMode: ValidationModeEnforced,
		})
		defer c.Close()

		// Invalid entry
		entry := &Entry{
			QName:           "invalid.com",
			DNSSECValidated: false,
			ExpiresAt:       time.Now().Add(time.Hour),
		}
		hash := uint64(123)
		c.Set(hash, entry)

		if _, ok := c.Get(hash); ok {
			t.Error("Enforced mode should NOT cache invalid entry")
		}

		// Valid entry
		validEntry := &Entry{
			QName:           "valid.com",
			DNSSECValidated: true,
			ExpiresAt:       time.Now().Add(time.Hour),
		}
		validHash := uint64(456)
		c.Set(validHash, validEntry)

		if _, ok := c.Get(validHash); !ok {
			t.Error("Enforced mode should cache valid entry")
		}
	})

	// 3. Test LogOnly Mode
	t.Run("LogOnly Mode", func(t *testing.T) {
		c := NewShardedCache(Config{
			ValidationMode: ValidationModeLogOnly,
		})
		defer c.Close()

		entry := &Entry{
			QName:           "invalid.com",
			DNSSECValidated: false,
			ExpiresAt:       time.Now().Add(time.Hour),
		}
		hash := uint64(123)
		c.Set(hash, entry)

		if _, ok := c.Get(hash); !ok {
			t.Error("LogOnly mode should cache invalid entry")
		}
	})
}

func BenchmarkSetAtCapacity(b *testing.B) {
	const capacity = 4096
	c := NewShardedCache(Config{ShardCount: 1, MaxEntries: capacity})
	defer c.Close()

	expiresAt := time.Now().Add(time.Hour)
	for i := range capacity {
		c.Set(uint64(i), &Entry{ExpiresAt: expiresAt})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		c.Set(uint64(capacity+i), &Entry{ExpiresAt: expiresAt.Add(time.Duration(i))})
	}
}

func TestSetReplacementAtCapacityDoesNotEvictAnotherKey(t *testing.T) {
	c := NewShardedCache(Config{ShardCount: 1, MaxEntries: 2})
	defer c.Close()

	expiresAt := time.Now().Add(time.Hour)
	c.Set(1, &Entry{Data: []byte("one"), ExpiresAt: expiresAt})
	c.Set(2, &Entry{Data: []byte("two"), ExpiresAt: expiresAt})
	replacement := &Entry{Data: []byte("replacement"), ExpiresAt: expiresAt}
	c.Set(2, replacement)

	if _, ok := c.Get(1); !ok {
		t.Fatal("replacement evicted an unrelated key")
	}
	got, ok := c.Get(2)
	if !ok || got != replacement {
		t.Fatal("replacement was not stored")
	}
	if got := c.GetStats().Evictions; got != 0 {
		t.Fatalf("evictions = %d, want 0", got)
	}
}

func TestSetEvictsEarliestExpiry(t *testing.T) {
	c := NewShardedCache(Config{ShardCount: 1, MaxEntries: 2})
	defer c.Close()

	now := time.Now()
	c.Set(1, &Entry{ExpiresAt: now.Add(2 * time.Hour)})
	c.Set(2, &Entry{ExpiresAt: now.Add(time.Hour)})
	c.Set(3, &Entry{ExpiresAt: now.Add(3 * time.Hour)})

	if _, ok := c.Get(2); ok {
		t.Fatal("earliest-expiring key was not evicted")
	}
	if _, ok := c.Get(1); !ok {
		t.Fatal("later-expiring key was evicted")
	}
	if _, ok := c.Get(3); !ok {
		t.Fatal("new key was not stored")
	}
}

func TestSetEvictsUntilMemoryBoundIsSatisfied(t *testing.T) {
	c := NewShardedCache(Config{
		ShardCount:  1,
		MaxEntries:  10,
		MaxMemoryMB: 1,
	})
	defer c.Close()

	now := time.Now()
	for i := uint64(1); i <= 3; i++ {
		c.Set(i, &Entry{
			Data:      make([]byte, 250*1024),
			ExpiresAt: now.Add(time.Duration(i) * time.Hour),
		})
	}
	c.Set(4, &Entry{
		Data:      make([]byte, 600*1024),
		ExpiresAt: now.Add(4 * time.Hour),
	})

	stats := c.GetStats()
	if stats.MemoryBytes > 1024*1024 {
		t.Fatalf("memory = %d, exceeds 1 MiB shard limit", stats.MemoryBytes)
	}
	if stats.Evictions != 2 {
		t.Fatalf("evictions = %d, want 2", stats.Evictions)
	}
	if stats.Size != 2 {
		t.Fatalf("size = %d, want 2", stats.Size)
	}
}

func TestOversizedReplacementPreservesExistingEntry(t *testing.T) {
	c := NewShardedCache(Config{
		ShardCount:  1,
		MaxEntries:  10,
		MaxMemoryMB: 1,
	})
	defer c.Close()

	existing := &Entry{Data: []byte("small"), ExpiresAt: time.Now().Add(time.Hour)}
	c.Set(1, existing)
	c.Set(1, &Entry{Data: make([]byte, 2*1024*1024), ExpiresAt: time.Now().Add(time.Hour)})

	got, ok := c.Get(1)
	if !ok || got != existing {
		t.Fatal("oversized replacement removed the existing cache entry")
	}
}

func TestPerformCleanupUsesExpiryQueue(t *testing.T) {
	c := NewShardedCache(Config{ShardCount: 1, MaxEntries: 10})
	defer c.Close()

	c.Set(1, &Entry{ExpiresAt: time.Now().Add(-time.Second)})
	c.Set(2, &Entry{ExpiresAt: time.Now().Add(time.Hour)})
	c.performCleanup()

	if _, ok := c.Get(1); ok {
		t.Fatal("expired entry survived cleanup")
	}
	if _, ok := c.Get(2); !ok {
		t.Fatal("live entry was removed during cleanup")
	}
	if got := c.GetStats().Expirations; got != 1 {
		t.Fatalf("expirations = %d, want 1", got)
	}
}

// TestApplyTTLPolicy_ClampsUnboundedTTL guards against cache-poisoning via a
// malicious/misconfigured authoritative server returning an oversized TTL
// (e.g. TTL=4294967295, ~136 years). Without a MaxTTL ceiling, that value
// would sit in cache effectively forever. See resolver.DefaultConfig, which
// now wires CacheConfig.MaxTTL so this ceiling is actually enforced by default.
func TestApplyTTLPolicy_ClampsUnboundedTTL(t *testing.T) {
	const maxTTL = 1 * time.Hour

	c := NewShardedCache(Config{
		MaxTTL: maxTTL,
	})
	defer c.Close()

	// Simulate a response with an absurdly long TTL (~136 years).
	entry := &Entry{
		QName:           "attacker-controlled.example",
		DNSSECValidated: true,
		ExpiresAt:       time.Now().Add(time.Duration(4294967295) * time.Second),
	}
	hash := uint64(789)
	c.Set(hash, entry)

	got, ok := c.Get(hash)
	if !ok {
		t.Fatal("expected entry to be cached")
	}

	remaining := time.Until(got.ExpiresAt)
	if remaining > maxTTL {
		t.Errorf("TTL not clamped: remaining=%s exceeds configured maxTTL=%s", remaining, maxTTL)
	}
	// Sanity: should still be a positive TTL close to the ceiling, not zero/expired.
	if remaining <= 0 {
		t.Errorf("clamped TTL should still be positive, got %s", remaining)
	}
}
