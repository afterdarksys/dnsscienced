package cache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Broadcaster manages event subscriptions using a lock-free publication model
// optimized for extremely high throughput (4M+ QPS).
type Broadcaster struct {
	mu          sync.Mutex   // Protects writes to subscribers list
	subscribers atomic.Value // Stores []chan *pb.CacheEvent
}

// NewBroadcaster creates a new event broadcaster
func NewBroadcaster() *Broadcaster {
	b := &Broadcaster{}
	b.subscribers.Store(make([]chan *pb.CacheEvent, 0))
	return b
}

// Subscribe adds a channel to the subscribers list
func (b *Broadcaster) Subscribe() chan *pb.CacheEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Load existing subscribers
	existing := b.subscribers.Load().([]chan *pb.CacheEvent)

	// Create new list properly sized
	newSubs := make([]chan *pb.CacheEvent, len(existing)+1)
	copy(newSubs, existing)

	// Create new channel with larger buffer for high throughput
	ch := make(chan *pb.CacheEvent, 1024)
	newSubs[len(existing)] = ch

	// Atomic store
	b.subscribers.Store(newSubs)
	return ch
}

// Unsubscribe removes a channel from the subscribers list
func (b *Broadcaster) Unsubscribe(ch chan *pb.CacheEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	existing := b.subscribers.Load().([]chan *pb.CacheEvent)
	newSubs := make([]chan *pb.CacheEvent, 0, len(existing))

	found := false
	for _, sub := range existing {
		if sub != ch {
			newSubs = append(newSubs, sub)
		} else {
			found = true
		}
	}

	if found {
		b.subscribers.Store(newSubs)
	}
}

// HasSubscribers lets maintenance paths avoid collecting event payloads when
// nobody is watching.
func (b *Broadcaster) HasSubscribers() bool {
	return len(b.subscribers.Load().([]chan *pb.CacheEvent)) > 0
}

// Publish sends an event to all subscribers non-blocking and LOCK-FREE
func (b *Broadcaster) Publish(eventType pb.CacheEvent_EventType, entry *Entry, reason string) {
	// Fast path: check if any subscribers exist before allocating event
	existing := b.subscribers.Load().([]chan *pb.CacheEvent)
	if len(existing) == 0 {
		return
	}

	// Construct protobuf event
	// Note: Allocation here is necessary, but maybe we can pool events later?
	event := &pb.CacheEvent{
		Type:           eventType,
		Timestamp:      timestamppb.Now(),
		Name:           entry.QName,
		QueryType:      queryTypeName(entry.QType),
		Reason:         reason,
		EvictionReason: evictionReason(eventType, reason),
		Entry:          protobufEntry(entry),
	}

	for _, ch := range existing {
		select {
		case ch <- event:
		default:
			// Buffer full, drop event to protect core performance
		}
	}
}

// PublishStore publishes a store event
func (b *Broadcaster) PublishStore(entry *Entry) {
	b.Publish(pb.CacheEvent_EVENT_TYPE_STORE, entry, "new_entry")
}

func (b *Broadcaster) PublishHit(entry *Entry, stale bool) {
	reason := "fresh"
	if stale {
		reason = "stale"
	}
	b.Publish(pb.CacheEvent_EVENT_TYPE_HIT, entry, reason)
}

func (b *Broadcaster) PublishMiss(qname string, qtype, qclass uint16, reason string) {
	b.Publish(pb.CacheEvent_EVENT_TYPE_MISS, &Entry{
		QName:  qname,
		QType:  qtype,
		QClass: qclass,
	}, reason)
}

func (b *Broadcaster) PublishEvict(entry *Entry, reason string) {
	b.Publish(pb.CacheEvent_EVENT_TYPE_EVICT, entry, reason)
}

func (b *Broadcaster) PublishDelete(entry *Entry, reason string) {
	b.Publish(pb.CacheEvent_EVENT_TYPE_DELETE, entry, reason)
}

func protobufEntry(entry *Entry) *pb.CacheEntry {
	if entry == nil {
		return nil
	}
	remainingTTL := int64(time.Until(entry.ExpiresAt).Seconds())
	if remainingTTL < 0 {
		remainingTTL = 0
	}
	return &pb.CacheEntry{
		Name:         entry.QName,
		Type:         queryTypeName(entry.QType),
		Class:        dns.ClassToString[entry.QClass],
		Ttl:          uint32(remainingTTL),
		OriginalTtl:  entry.OrigTTL,
		ExpiresAt:    timestampOrNil(entry.ExpiresAt),
		ThreatScore:  entry.ThreatScore,
		Categories:   append([]string(nil), entry.Categories...),
		Reputation:   entry.Reputation,
		ThreatSource: entry.ThreatSource,
		FirstSeen:    timestampOrNil(entry.FirstSeen),
		LastSeen:     timestampOrNil(entry.LastSeen),
	}
}

func timestampOrNil(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value)
}

func queryTypeName(qtype uint16) string {
	if name := dns.TypeToString[qtype]; name != "" {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

func evictionReason(eventType pb.CacheEvent_EventType, reason string) string {
	if eventType == pb.CacheEvent_EVENT_TYPE_EVICT {
		return reason
	}
	return ""
}
