package cache

import (
	"fmt"
	"hash/fnv"
	"math"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"github.com/miekg/dns"
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
	Hits       atomic.Uint64
	refreshing atomic.Bool

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
	size += 8 // ExpiresAt (time.Time is 3 words on 64-bit)
	size += 4 // OrigTTL
	size += 8 // Hits (atomic.Uint64)
	size += 1 // DNSSECValidated
	size += 1 // DNSSECBogus
	size += 2 // QType
	size += 2 // QClass

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
	mu         sync.RWMutex
	entries    map[uint64]*Entry // Keyed by hash
	maxSize    int
	memoryUsed atomic.Int64 // Current memory usage in bytes
	maxMemory  int64        // Maximum memory per shard in bytes
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

	// TTL enforcement (Unbound-inspired)
	minTTL         time.Duration
	maxTTL         time.Duration
	minNegativeTTL time.Duration
	maxNegativeTTL time.Duration
	bogusTTL       time.Duration

	// Prefetch (Unbound-inspired)
	prefetch          bool
	prefetchMinTTLPct float64
	prefetchFn        func(qname string, qtype, qclass uint16)

	// DNS rebinding protection (Unbound private-address)
	rebinding *RebindingGuard

	// Aggressive NSEC caching (RFC 8198)
	nsecCache *NSECCache

	// Unwanted reply poisoning detection (Unbound unwanted-reply-threshold)
	unwantedReplies   atomic.Uint64
	unwantedThreshold uint64

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

	// TTL enforcement (Unbound cache-min-ttl / cache-max-ttl)
	// Clamps TTLs on positive responses before caching. Prevents zero-TTL bypass
	// and over-long TTLs that delay revocation of compromised records.
	MinTTL time.Duration `yaml:"min_ttl"`
	MaxTTL time.Duration `yaml:"max_ttl"`

	// Negative TTL enforcement (Unbound cache-min-negative-ttl / cache-max-negative-ttl)
	// Applied to NXDOMAIN and NODATA responses.
	MinNegativeTTL time.Duration `yaml:"min_negative_ttl"`
	MaxNegativeTTL time.Duration `yaml:"max_negative_ttl"`

	// BogusTTL controls how long DNSSEC-bogus entries are quarantined in cache
	// before re-validation is attempted. Prevents hammering the validator on
	// repeatedly invalid zones (Unbound val-bogus-ttl, default 60s).
	BogusTTL time.Duration `yaml:"bogus_ttl"`

	// Prefetch triggers background refresh when a cache entry has less than
	// PrefetchMinTTLPct of its original TTL remaining. This keeps popular records
	// perpetually fresh and reduces the re-query window that an attacker could race
	// to inject a poisoned response. (Unbound prefetch: yes)
	Prefetch          bool    `yaml:"prefetch"`
	PrefetchMinTTLPct float64 `yaml:"prefetch_min_ttl_pct"` // default 0.1 (10%)

	// RebindingProtection prevents public names from resolving to RFC-1918 / loopback
	// addresses, blocking browser-based DNS rebinding attacks. (Unbound private-address)
	RebindingProtection bool     `yaml:"rebinding_protection"`
	PrivateAddresses    []string `yaml:"private_addresses"` // CIDRs; empty = use defaults
	PrivateDomains      []string `yaml:"private_domains"`   // Exempt from rebinding check

	// AggressiveNSEC enables RFC 8198 synthesis: NXDOMAIN responses for names
	// covered by cached NSEC records, without querying the network. Requires
	// DNSSEC validation to be active. (Unbound aggressive-nsec: yes)
	AggressiveNSEC bool `yaml:"aggressive_nsec"`

	// UnwantedReplyThreshold flushes the entire cache when this many unsolicited
	// (non-matching) replies are counted, indicating an active cache poisoning
	// attempt. 0 disables. (Unbound unwanted-reply-threshold)
	UnwantedReplyThreshold uint64 `yaml:"unwanted_reply_threshold"`
}

// Validate checks operator-controlled cache sizing before allocation. A zero
// value selects the documented default for that field.
func (cfg Config) Validate() error {
	if cfg.ShardCount < 0 || cfg.ShardCount > 65536 {
		return fmt.Errorf("shard_count must be between 0 and 65536")
	}
	if cfg.MaxEntries < 0 {
		return fmt.Errorf("max_entries cannot be negative")
	}
	if cfg.MaxMemoryMB < 0 || int64(cfg.MaxMemoryMB) > math.MaxInt64/(1024*1024) {
		return fmt.Errorf("max_memory_mb is out of range")
	}
	if cfg.PrefetchMinTTLPct < 0 || cfg.PrefetchMinTTLPct > 1 {
		return fmt.Errorf("prefetch_min_ttl_pct must be between 0 and 1")
	}

	shards := cfg.ShardCount
	if shards == 0 {
		shards = defaultShardCount
	}
	effectiveShards := 1
	for effectiveShards < shards {
		effectiveShards <<= 1
	}
	entries := cfg.MaxEntries
	if entries == 0 {
		entries = defaultShardSize * effectiveShards
	}
	if entries < effectiveShards {
		return fmt.Errorf("max_entries (%d) must be at least effective shard_count (%d)", entries, effectiveShards)
	}
	return nil
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

	prefetchRatio := cfg.PrefetchMinTTLPct
	if prefetchRatio == 0 {
		prefetchRatio = 0.1
	}

	bogusTTL := cfg.BogusTTL
	if bogusTTL == 0 {
		bogusTTL = 60 * time.Second // Unbound default
	}

	maxNegTTL := cfg.MaxNegativeTTL
	if maxNegTTL == 0 {
		maxNegTTL = time.Hour // Unbound cache-max-negative-ttl default
	}

	c := &ShardedCache{
		shards:       make([]*shard, cfg.ShardCount),
		shardCount:   cfg.ShardCount,
		shardMask:    uint64(cfg.ShardCount - 1),
		serveStale:   cfg.ServeStale,
		maxStaleTTL:  cfg.MaxStaleTTL,
		staleRefresh: cfg.StaleRefresh,

		minTTL:         cfg.MinTTL,
		maxTTL:         cfg.MaxTTL,
		minNegativeTTL: cfg.MinNegativeTTL,
		maxNegativeTTL: maxNegTTL,
		bogusTTL:       bogusTTL,

		prefetch:          cfg.Prefetch,
		prefetchMinTTLPct: prefetchRatio,

		unwantedThreshold: cfg.UnwantedReplyThreshold,

		enricher:       NewThreatScorer(cfg.DarkAPIKey),
		validationMode: cfg.ValidationMode,
		broadcaster:    NewBroadcaster(),
		stopCleanup:    make(chan struct{}),
	}

	if cfg.RebindingProtection {
		c.rebinding = NewRebindingGuard(cfg.PrivateAddresses, cfg.PrivateDomains)
	}

	if cfg.AggressiveNSEC {
		c.nsecCache = NewNSECCache()
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

		// Prefetch: trigger background refresh when entry is within the last
		// PrefetchMinTTLPct of its original TTL (Unbound prefetch: yes).
		if c.prefetch && c.prefetchFn != nil && entry.OrigTTL > 0 {
			remaining := time.Until(entry.ExpiresAt)
			total := time.Duration(entry.OrigTTL) * time.Second
			if float64(remaining)/float64(total) < c.prefetchMinTTLPct &&
				entry.refreshing.CompareAndSwap(false, true) {
				go func() {
					defer entry.refreshing.Store(false)
					c.prefetchFn(entry.QName, entry.QType, entry.QClass)
				}()
			}
		}
	}

	entry.Hits.Add(1)
	return entry, true
}

// SynthesizeNXDOMAIN attempts to answer a query from cached NSEC records
// without hitting the network (RFC 8198 aggressive NSEC). Returns nil when
// no synthesis is possible. Only available when AggressiveNSEC is enabled.
func (c *ShardedCache) SynthesizeNXDOMAIN(qname string, qtype, qclass uint16, queryID uint16) *dns.Msg {
	if c.nsecCache == nil {
		return nil
	}
	return c.nsecCache.SynthesizeNXDOMAIN(qname, qtype, qclass, queryID)
}

// StoreNSEC stores validated NSEC records from a DNSSEC-confirmed NXDOMAIN
// response for later use in aggressive synthesis (RFC 8198).
func (c *ShardedCache) StoreNSEC(msg *dns.Msg, zone string) {
	if c.nsecCache != nil {
		c.nsecCache.Store(msg, zone)
	}
}

// SetPrefetchFunc registers the callback invoked when an entry needs a background
// refresh. The function is called in a new goroutine and must be safe to call
// concurrently. Set this before the cache receives traffic.
func (c *ShardedCache) SetPrefetchFunc(fn func(qname string, qtype, qclass uint16)) {
	c.prefetchFn = fn
}

// RecordUnwantedReply increments the unsolicited-reply counter. When the count
// reaches UnwantedReplyThreshold the entire cache is flushed to expunge any
// poison that may have been injected (Unbound unwanted-reply-threshold).
func (c *ShardedCache) RecordUnwantedReply() {
	if c.unwantedThreshold == 0 {
		return
	}
	if count := c.unwantedReplies.Add(1); count >= c.unwantedThreshold {
		c.unwantedReplies.Store(0)
		c.Flush()
		fmt.Printf("[CACHE-SECURITY] unwanted-reply threshold (%d) reached — cache flushed to remove potential poison\n",
			c.unwantedThreshold)
	}
}

// IsSafeResponse checks a DNS response against the rebinding guard before caching.
// Returns false when a public name resolves to a private IP (rebinding attack).
// Always returns true when rebinding protection is disabled.
func (c *ShardedCache) IsSafeResponse(msg *dns.Msg, qname string) bool {
	if c.rebinding == nil {
		return true
	}
	return c.rebinding.IsSafe(msg, qname)
}

// applyTTLPolicy clamps an entry's TTL to the configured min/max bounds.
// Bogus entries get a short quarantine TTL to avoid hammering the validator.
func (c *ShardedCache) applyTTLPolicy(entry *Entry) {
	now := time.Now()
	remaining := entry.ExpiresAt.Sub(now)

	if entry.DNSSECBogus && c.bogusTTL > 0 {
		// Quarantine bogus entries with a short TTL regardless of other bounds.
		entry.ExpiresAt = now.Add(c.bogusTTL)
		return
	}

	if entry.IsNegative {
		if c.minNegativeTTL > 0 && remaining < c.minNegativeTTL {
			entry.ExpiresAt = now.Add(c.minNegativeTTL)
		}
		if c.maxNegativeTTL > 0 && remaining > c.maxNegativeTTL {
			entry.ExpiresAt = now.Add(c.maxNegativeTTL)
		}
	} else {
		if c.minTTL > 0 && remaining < c.minTTL {
			entry.ExpiresAt = now.Add(c.minTTL)
		}
		if c.maxTTL > 0 && remaining > c.maxTTL {
			entry.ExpiresAt = now.Add(c.maxTTL)
		}
	}
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

	// Apply TTL enforcement before caching (Unbound cache-min/max-ttl).
	c.applyTTLPolicy(entry)

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
