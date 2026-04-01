package cache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
)

const (
	// Number of shards - power of 2 for fast modulo via bitmasking
	defaultShardCount = 256

	// Default cache size per shard
	defaultShardSize = 10000

	// Cleanup interval for expired entries
	cleanupInterval = 60 * time.Second
)

// ValidationMode defines the strictness of cache admission via DNSSEC
type ValidationMode string

const (
	// ValidationModePass allows all entries (default)
	ValidationModePass ValidationMode = "pass"
	// ValidationModeLogOnly logs invalid entries but caches them
	ValidationModeLogOnly ValidationMode = "log-only"
	// ValidationModeEnforced only caches DNSSEC-validated entries
	ValidationModeEnforced ValidationMode = "enforced"
)

// Entry represents a cached DNS response
type Entry struct {
	// Wire format response
	Data []byte

	// Expiration tracking
	ExpiresAt time.Time
	OrigTTL   uint32

	// Statistics (atomic for lock-free updates)
	Hits atomic.Uint64

	// DNSSEC validation status
	DNSSECValidated bool
	DNSSECBogus     bool

	// Query metadata
	QName  string
	QType  uint16
	QClass uint16

	// Threat Intelligence Metadata
	ThreatScore  int32
	Categories   []string
	Reputation   string
	FirstSeen    time.Time
	LastSeen     time.Time
	ThreatSource string
}

// IsExpired checks if entry has expired
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStale checks if entry is within serve-stale window
func (e *Entry) IsStale(maxStale time.Duration) bool {
	if !e.IsExpired() {
		return false
	}
	return time.Since(e.ExpiresAt) < maxStale
}

// shard represents a single cache shard with its own lock
type shard struct {
	mu      sync.RWMutex
	entries map[uint64]*Entry // Keyed by hash
	maxSize int
}

// ShardedCache implements a thread-safe, lock-contention-free cache
// using sharding to distribute load across multiple locks
type ShardedCache struct {
	shards []*shard

	// Configuration
	shardCount int
	shardMask  uint64 // For fast modulo: hash & mask

	// Serve stale configuration
	serveStale   bool
	maxStaleTTL  time.Duration
	staleRefresh bool

	// Threat enrichment
	enricher *ThreatScorer

	// Validation Mode
	validationMode ValidationMode

	// Event Broadcaster
	broadcaster *Broadcaster

	// Statistics (atomic for lock-free access)
	hits        atomic.Uint64
	misses      atomic.Uint64
	evictions   atomic.Uint64
	expirations atomic.Uint64

	// Cleanup goroutine management
	stopCleanup chan struct{}
	cleanupDone sync.WaitGroup
}

// Config holds cache configuration
type Config struct {
	// Total cache size (distributed across shards)
	MaxEntries int `yaml:"max_entries"`

	// Number of shards (default 256)
	ShardCount int `yaml:"shard_count"`

	// Serve stale configuration
	ServeStale   bool          `yaml:"serve_stale"`
	MaxStaleTTL  time.Duration `yaml:"max_stale_ttl"`
	StaleRefresh bool          `yaml:"stale_refresh"` // Whether to trigger background refresh

	// DNSSEC Validation Mode
	ValidationMode ValidationMode `yaml:"validation_mode"`

	// Threat Intelligence
	DarkAPIKey string `yaml:"darkapi_key"`
}

// NewShardedCache creates a new sharded cache
func NewShardedCache(cfg Config) *ShardedCache {
	if cfg.ShardCount == 0 {
		cfg.ShardCount = defaultShardCount
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = defaultShardSize * cfg.ShardCount
	}
	if cfg.ValidationMode == "" {
		cfg.ValidationMode = ValidationModePass
	}

	// Ensure shard count is power of 2
	if cfg.ShardCount&(cfg.ShardCount-1) != 0 {
		// Round up to next power of 2
		n := 1
		for n < cfg.ShardCount {
			n <<= 1
		}
		cfg.ShardCount = n
	}

	shardSize := cfg.MaxEntries / cfg.ShardCount

	c := &ShardedCache{
		shards:       make([]*shard, cfg.ShardCount),
		shardCount:   cfg.ShardCount,
		shardMask:    uint64(cfg.ShardCount - 1),
		serveStale:   cfg.ServeStale,
		maxStaleTTL:  cfg.MaxStaleTTL,
		staleRefresh: cfg.StaleRefresh,
		// Deduplication handled

		enricher:       NewThreatScorer(cfg.DarkAPIKey),
		validationMode: cfg.ValidationMode,
		broadcaster:    NewBroadcaster(),
		stopCleanup:    make(chan struct{}),
	}

	// Initialize shards
	for i := 0; i < cfg.ShardCount; i++ {
		c.shards[i] = &shard{
			entries: make(map[uint64]*Entry, shardSize),
			maxSize: shardSize,
		}
	}

	// Start background cleanup goroutine
	c.cleanupDone.Add(1)
	go c.cleanupExpired()

	return c
}

// getShard returns the shard for a given hash
// Uses bitmasking for fast modulo operation
func (c *ShardedCache) getShard(hash uint64) *shard {
	return c.shards[hash&c.shardMask]
}

// Get retrieves an entry from cache
func (c *ShardedCache) Get(hash uint64) (*Entry, bool) {
	shard := c.getShard(hash)

	shard.mu.RLock()
	entry, ok := shard.entries[hash]
	shard.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	// Check expiration
	if entry.IsExpired() {
		if !c.serveStale {
			c.misses.Add(1)
			return nil, false
		}

		// Check if within serve-stale window
		if !entry.IsStale(c.maxStaleTTL) {
			c.misses.Add(1)
			return nil, false
		}

		// Serve stale but increment miss counter
		c.misses.Add(1)
	} else {
		c.hits.Add(1)
	}

	entry.Hits.Add(1)
	return entry, true
}

// Set stores an entry in cache
func (c *ShardedCache) Set(hash uint64, entry *Entry) {
	shard := c.getShard(hash)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Validation Mode Logic
	if !entry.DNSSECValidated {
		switch c.validationMode {
		case ValidationModeEnforced:
			// Drop invalid entries in enforced mode
			return
		case ValidationModeLogOnly:
			// Log but allow (using fmt for MVP)
			fmt.Printf("[CACHE] Validation failure for %s (LogOnly)\n", entry.QName)
		}
	}

	if c.enricher != nil {
		c.enricher.EnrichEntry(entry)
	}

	// Publish Store Event (only if threat found or always? Plan said important events. Let's publish all new stores for now, stream filtering handles the rest)
	if c.broadcaster != nil {
		c.broadcaster.PublishStore(entry)
	}

	// Check if we need to evict
	if len(shard.entries) >= shard.maxSize {
		// Simple LRU: remove oldest entry
		// In production, use a better eviction policy
		c.evictOldest(shard)
	}

	shard.entries[hash] = entry
}

// Delete removes an entry from cache
func (c *ShardedCache) Delete(hash uint64) {
	shard := c.getShard(hash)

	shard.mu.Lock()
	delete(shard.entries, hash)
	shard.mu.Unlock()
}

// evictOldest removes the oldest entry from a shard (must hold lock)
func (c *ShardedCache) evictOldest(s *shard) {
	var oldestHash uint64
	var oldestTime time.Time
	first := true

	for hash, entry := range s.entries {
		if first || entry.ExpiresAt.Before(oldestTime) {
			oldestHash = hash
			oldestTime = entry.ExpiresAt
			first = false
		}
	}

	if !first {
		delete(s.entries, oldestHash)
		c.evictions.Add(1)
		// Publish Evict Event? Maybe.
		// For Streaming Intelligence, we care most about Adds.
		// But let's add it for completeness.
		// NOTE: broadcaster.Publish needs an Entry. We need to retrieve it before deleting.
		// But we don't have the entry here locally easily without re-lookup or keeping reference.
		// Loop implementation kept 'oldestTime', but we didn't keep 'oldestEntry'.
		// Let's optimize: skip evict event for now to save lookup cost, unless we really need it.
		// Actually, let's keep it simple.
	}
}

// Flush clears all entries from cache
func (c *ShardedCache) Flush() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.entries = make(map[uint64]*Entry, shard.maxSize)
		shard.mu.Unlock()
	}
}

// cleanupExpired periodically removes expired entries
func (c *ShardedCache) cleanupExpired() {
	defer c.cleanupDone.Done()

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.performCleanup()
		case <-c.stopCleanup:
			return
		}
	}
}

// performCleanup removes expired entries from all shards
func (c *ShardedCache) performCleanup() {
	for _, shard := range c.shards {
		shard.mu.Lock()

		// Collect expired keys
		var expired []uint64
		for hash, entry := range shard.entries {
			if c.serveStale {
				// Only remove if beyond serve-stale window
				if entry.IsExpired() && !entry.IsStale(c.maxStaleTTL) {
					expired = append(expired, hash)
				}
			} else {
				// Remove all expired
				if entry.IsExpired() {
					expired = append(expired, hash)
				}
			}
		}

		// Delete expired entries
		for _, hash := range expired {
			delete(shard.entries, hash)
			c.expirations.Add(1)
		}

		shard.mu.Unlock()

		// Yield to prevent blocking for too long
		if len(expired) > 0 {
			time.Sleep(time.Millisecond)
		}
	}
}

// Stats returns cache statistics
type Stats struct {
	Hits        uint64
	Misses      uint64
	Evictions   uint64
	Expirations uint64
	Size        int
	HitRate     float64
}

// GetStats returns current cache statistics
func (c *ShardedCache) GetStats() Stats {
	hits := c.hits.Load()
	misses := c.misses.Load()

	var hitRate float64
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	// Count total entries across all shards
	size := 0
	for _, shard := range c.shards {
		shard.mu.RLock()
		size += len(shard.entries)
		shard.mu.RUnlock()
	}

	return Stats{
		Hits:        hits,
		Misses:      misses,
		Evictions:   c.evictions.Load(),
		Expirations: c.expirations.Load(),
		Size:        size,
		HitRate:     hitRate,
	}
}

// Close stops background goroutines
func (c *ShardedCache) Close() {
	close(c.stopCleanup)
	c.cleanupDone.Wait()
}

// ForEach iterates over all cache entries (for debugging/monitoring)
// WARNING: This locks all shards sequentially, use sparingly
func (c *ShardedCache) ForEach(fn func(hash uint64, entry *Entry)) {
	for _, shard := range c.shards {
		shard.mu.RLock()
		for hash, entry := range shard.entries {
			fn(hash, entry)
		}
		shard.mu.RUnlock()
	}
}

// Subscribe returns a channel that receives cache events
func (c *ShardedCache) Subscribe() chan *pb.CacheEvent {
	return c.broadcaster.Subscribe()
}

// Unsubscribe removes a channel from subscription
func (c *ShardedCache) Unsubscribe(ch chan *pb.CacheEvent) {
	c.broadcaster.Unsubscribe(ch)
}
