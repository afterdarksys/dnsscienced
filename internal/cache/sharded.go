package cache

import (
	"fmt"
	"hash/fnv"
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

	// Negative caching (RFC 2308)
	IsNegative bool   // True for NXDOMAIN and NODATA responses
	NegType    string // "NXDOMAIN" or "NODATA"

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

// estimateSize estimates the memory size of this entry in bytes
func (e *Entry) estimateSize() int64 {
	size := int64(0)

	// Wire format data
	size += int64(len(e.Data))

	// Fixed-size fields
	size += 8  // ExpiresAt (time.Time is 3 words on 64-bit)
	size += 4  // OrigTTL
	size += 8  // Hits (atomic.Uint64)
	size += 1  // DNSSECValidated
	size += 1  // DNSSECBogus
	size += 2  // QType
	size += 2  // QClass

	// String fields
	size += int64(len(e.QName))
	size += int64(len(e.Reputation))
	size += int64(len(e.ThreatSource))

	// Slice overhead + content
	size += int64(len(e.Categories) * 16) // approximate string slice overhead
	for _, cat := range e.Categories {
		size += int64(len(cat))
	}

	// Threat metadata
	size += 4  // ThreatScore
	size += 16 // FirstSeen
	size += 16 // LastSeen

	// Map entry overhead (hash key + pointer)
	size += 8 + 8

	return size
}

// shard represents a single cache shard with its own lock
type shard struct {
	mu          sync.RWMutex
	entries     map[uint64]*Entry // Keyed by hash
	maxSize     int
	memoryUsed  atomic.Int64      // Current memory usage in bytes
	maxMemory   int64             // Maximum memory per shard in bytes
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

	// Memory limits (bytes)
	MaxMemoryMB int `yaml:"max_memory_mb"` // Maximum cache memory in MB

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

	// Calculate memory limit per shard
	var maxMemoryPerShard int64
	if cfg.MaxMemoryMB > 0 {
		totalMemory := int64(cfg.MaxMemoryMB) * 1024 * 1024 // Convert MB to bytes
		maxMemoryPerShard = totalMemory / int64(cfg.ShardCount)
	}

	// Initialize shards
	for i := 0; i < cfg.ShardCount; i++ {
		c.shards[i] = &shard{
			entries:   make(map[uint64]*Entry, shardSize),
			maxSize:   shardSize,
			maxMemory: maxMemoryPerShard,
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

	// Calculate entry size
	entrySize := entry.estimateSize()

	// Check if we need to evict based on size or memory
	needsEviction := len(shard.entries) >= shard.maxSize

	// Memory-aware eviction
	if shard.maxMemory > 0 {
		currentMemory := shard.memoryUsed.Load()
		if currentMemory+entrySize > shard.maxMemory {
			needsEviction = true
		}
	}

	if needsEviction {
		c.evictOldest(shard)
	}

	// Remove old entry if replacing
	if oldEntry, exists := shard.entries[hash]; exists {
		oldSize := oldEntry.estimateSize()
		shard.memoryUsed.Add(-oldSize)
	}

	// Add new entry
	shard.entries[hash] = entry
	shard.memoryUsed.Add(entrySize)
}

// Delete removes an entry from cache
func (c *ShardedCache) Delete(hash uint64) {
	shard := c.getShard(hash)

	shard.mu.Lock()
	if entry, exists := shard.entries[hash]; exists {
		entrySize := entry.estimateSize()
		shard.memoryUsed.Add(-entrySize)
		delete(shard.entries, hash)
	}
	shard.mu.Unlock()
}

// evictOldest removes the oldest entry from a shard (must hold lock)
func (c *ShardedCache) evictOldest(s *shard) {
	var oldestHash uint64
	var oldestEntry *Entry
	var oldestTime time.Time
	first := true

	for hash, entry := range s.entries {
		if first || entry.ExpiresAt.Before(oldestTime) {
			oldestHash = hash
			oldestEntry = entry
			oldestTime = entry.ExpiresAt
			first = false
		}
	}

	if !first && oldestEntry != nil {
		// Update memory tracking
		entrySize := oldestEntry.estimateSize()
		s.memoryUsed.Add(-entrySize)

		delete(s.entries, oldestHash)
		c.evictions.Add(1)
	}
}

// Flush clears all entries from cache
func (c *ShardedCache) Flush() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.entries = make(map[uint64]*Entry, shard.maxSize)
		shard.memoryUsed.Store(0)
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

		// Collect expired keys and their entries for memory tracking
		type expiredEntry struct {
			hash uint64
			size int64
		}
		var expired []expiredEntry

		for hash, entry := range shard.entries {
			shouldExpire := false
			if c.serveStale {
				// Only remove if beyond serve-stale window
				if entry.IsExpired() && !entry.IsStale(c.maxStaleTTL) {
					shouldExpire = true
				}
			} else {
				// Remove all expired
				if entry.IsExpired() {
					shouldExpire = true
				}
			}

			if shouldExpire {
				expired = append(expired, expiredEntry{
					hash: hash,
					size: entry.estimateSize(),
				})
			}
		}

		// Delete expired entries and update memory tracking
		for _, exp := range expired {
			delete(shard.entries, exp.hash)
			shard.memoryUsed.Add(-exp.size)
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
	MemoryBytes int64
	MaxMemory   int64
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

	// Count total entries and memory across all shards
	size := 0
	var memoryBytes int64
	var maxMemory int64
	for _, shard := range c.shards {
		shard.mu.RLock()
		size += len(shard.entries)
		memoryBytes += shard.memoryUsed.Load()
		maxMemory += shard.maxMemory
		shard.mu.RUnlock()
	}

	return Stats{
		Hits:        hits,
		Misses:      misses,
		Evictions:   c.evictions.Load(),
		Expirations: c.expirations.Load(),
		Size:        size,
		HitRate:     hitRate,
		MemoryBytes: memoryBytes,
		MaxMemory:   maxMemory,
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

// HashKey generates a cache key hash for a given query
func HashKey(qname string, qtype uint16, qclass uint16) uint64 {
	h := fnv.New64a()
	h.Write([]byte(qname))
	h.Write([]byte{byte(qtype >> 8), byte(qtype)})
	h.Write([]byte{byte(qclass >> 8), byte(qclass)})
	return h.Sum64()
}
