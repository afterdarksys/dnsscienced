package cache

import (
	"testing"
	"time"

	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"github.com/miekg/dns"
)

func TestShardedCachePublishesMissHitStoreEvictAndDelete(t *testing.T) {
	c := NewShardedCache(Config{ShardCount: 1, MaxEntries: 1})
	defer c.Close()
	events := c.Subscribe()
	defer c.Unsubscribe(events)

	if _, ok := c.GetQuestion(1, "missing.example.", dns.TypeA, dns.ClassINET); ok {
		t.Fatal("unexpected cache hit")
	}
	assertCacheEvent(t, events, pb.CacheEvent_EVENT_TYPE_MISS, "missing.example.", "never_cached")

	first := &Entry{
		QName:     "first.example.",
		QType:     dns.TypeA,
		QClass:    dns.ClassINET,
		OrigTTL:   300,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	c.Set(1, first)
	assertCacheEvent(t, events, pb.CacheEvent_EVENT_TYPE_STORE, "first.example.", "new_entry")

	if _, ok := c.GetQuestion(1, first.QName, first.QType, first.QClass); !ok {
		t.Fatal("expected cache hit")
	}
	hit := assertCacheEvent(t, events, pb.CacheEvent_EVENT_TYPE_HIT, "first.example.", "fresh")
	if hit.QueryType != "A" || hit.Entry == nil || hit.Entry.Class != "IN" {
		t.Fatalf("incomplete hit event: %+v", hit)
	}

	second := &Entry{
		QName:     "second.example.",
		QType:     dns.TypeAAAA,
		QClass:    dns.ClassINET,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	c.Set(2, second)
	evict := assertCacheEvent(t, events, pb.CacheEvent_EVENT_TYPE_EVICT, "first.example.", "capacity")
	if evict.EvictionReason != "capacity" {
		t.Fatalf("eviction reason = %q", evict.EvictionReason)
	}
	assertCacheEvent(t, events, pb.CacheEvent_EVENT_TYPE_STORE, "second.example.", "new_entry")

	c.Delete(2)
	assertCacheEvent(t, events, pb.CacheEvent_EVENT_TYPE_DELETE, "second.example.", "explicit")
}

func TestCleanupPublishesExpiredEviction(t *testing.T) {
	c := NewShardedCache(Config{ShardCount: 1, MaxEntries: 1})
	defer c.Close()
	events := c.Subscribe()
	defer c.Unsubscribe(events)

	entry := &Entry{
		QName:     "expired.example.",
		QType:     dns.TypeA,
		QClass:    dns.ClassINET,
		ExpiresAt: time.Now().Add(-time.Second),
	}
	c.Set(1, entry)
	assertCacheEvent(t, events, pb.CacheEvent_EVENT_TYPE_STORE, entry.QName, "new_entry")
	c.performCleanup()
	assertCacheEvent(t, events, pb.CacheEvent_EVENT_TYPE_EVICT, entry.QName, "expired")
}

func BenchmarkGetQuestionWithoutSubscribers(b *testing.B) {
	c := NewShardedCache(Config{ShardCount: 1, MaxEntries: 1})
	defer c.Close()
	entry := &Entry{
		QName:     "hot.example.",
		QType:     dns.TypeA,
		QClass:    dns.ClassINET,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	c.Set(1, entry)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = c.GetQuestion(1, entry.QName, entry.QType, entry.QClass)
	}
}

func assertCacheEvent(
	t *testing.T,
	events <-chan *pb.CacheEvent,
	eventType pb.CacheEvent_EventType,
	name string,
	reason string,
) *pb.CacheEvent {
	t.Helper()
	select {
	case event := <-events:
		if event.Type != eventType || event.Name != name || event.Reason != reason {
			t.Fatalf("event = %+v, want type=%s name=%s reason=%s", event, eventType, name, reason)
		}
		return event
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s event", eventType)
		return nil
	}
}
