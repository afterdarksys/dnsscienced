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
