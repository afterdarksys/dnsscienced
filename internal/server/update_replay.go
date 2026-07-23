package server

import (
	"crypto/sha256"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const defaultUpdateReplayCacheSize = 65_536

var updateReplaysTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "dnsscienced_update_replays_total",
	Help: "Total authenticated RFC 2136 UPDATE duplicates coalesced without reapplying the transaction.",
})

var updateReplaySaturatedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "dnsscienced_update_replay_cache_saturated_total",
	Help: "Total authenticated RFC 2136 UPDATE requests failed closed because the replay cache contained only unexpired entries.",
})

type updateReplayCache struct {
	shards []updateReplayShard
}

type updateReplayShard struct {
	mu       sync.Mutex
	entries  map[[sha256.Size]byte]*updateReplayEntry
	slots    []*updateReplayEntry
	nextSlot int
	capacity int
}

type updateReplayEntry struct {
	digest    [sha256.Size]byte
	expiresAt time.Time
	shard     int
	done      chan struct{}
	rcode     int
	complete  bool
}

func newUpdateReplayCache(capacity int) *updateReplayCache {
	if capacity <= 0 {
		return nil
	}
	shardCount := 64
	if capacity < shardCount {
		shardCount = capacity
	}
	cache := &updateReplayCache{shards: make([]updateReplayShard, shardCount)}
	base := capacity / shardCount
	remainder := capacity % shardCount
	for i := range cache.shards {
		shardCapacity := base
		if i < remainder {
			shardCapacity++
		}
		cache.shards[i] = updateReplayShard{
			entries:  make(map[[sha256.Size]byte]*updateReplayEntry, shardCapacity),
			slots:    make([]*updateReplayEntry, 0, shardCapacity),
			capacity: shardCapacity,
		}
	}
	return cache
}

// beginUpdate reserves a verified request MAC or returns the matching earlier
// request. An empty MAC is used only by direct handler tests; a real dns.Server
// rejects it before the UPDATE handler.
func (c *updateReplayCache) beginUpdate(tsigRR *dns.TSIG, now time.Time) (*updateReplayEntry, bool, bool) {
	if c == nil || tsigRR == nil || tsigRR.MAC == "" {
		return nil, false, false
	}
	digest := sha256.Sum256([]byte(
		strings.ToLower(dns.Fqdn(tsigRR.Hdr.Name)) + "\x00" +
			dns.CanonicalName(tsigRR.Algorithm) + "\x00" +
			strings.ToLower(tsigRR.MAC),
	))
	shardIndex := int(digest[0]) % len(c.shards)
	shard := &c.shards[shardIndex]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if existing := shard.entries[digest]; existing != nil {
		if !now.After(existing.expiresAt) {
			return existing, true, false
		}
		delete(shard.entries, digest)
	}

	entry := &updateReplayEntry{
		digest:    digest,
		expiresAt: time.Unix(int64(tsigRR.TimeSigned), 0).Add(time.Duration(tsigRR.Fudge) * time.Second),
		shard:     shardIndex,
		done:      make(chan struct{}),
	}
	if len(shard.slots) < shard.capacity {
		shard.slots = append(shard.slots, entry)
	} else {
		expiredSlot := -1
		for offset := 0; offset < shard.capacity; offset++ {
			slot := (shard.nextSlot + offset) % shard.capacity
			if now.After(shard.slots[slot].expiresAt) {
				expiredSlot = slot
				break
			}
		}
		if expiredSlot < 0 {
			return nil, false, true
		}
		evicted := shard.slots[expiredSlot]
		if shard.entries[evicted.digest] == evicted {
			delete(shard.entries, evicted.digest)
		}
		shard.slots[expiredSlot] = entry
		shard.nextSlot = (expiredSlot + 1) % shard.capacity
	}
	shard.entries[digest] = entry
	return entry, false, false
}

func (c *updateReplayCache) finishUpdate(entry *updateReplayEntry, rcode int) {
	if c == nil || entry == nil {
		return
	}
	shard := &c.shards[entry.shard]
	shard.mu.Lock()
	if !entry.complete {
		entry.rcode = rcode
		entry.complete = true
		close(entry.done)
	}
	shard.mu.Unlock()
}

func (entry *updateReplayEntry) wait() int {
	<-entry.done
	return entry.rcode
}
