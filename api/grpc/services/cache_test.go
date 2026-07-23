package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/api/grpc/mock"
	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/grpc/metadata"
)

func TestCacheEventTypeFilterAcceptsDocumentedShortNames(t *testing.T) {
	filter, err := cacheEventTypeFilter([]string{"hit", "EVENT_TYPE_MISS", "Evict"})
	if err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []pb.CacheEvent_EventType{
		pb.CacheEvent_EVENT_TYPE_HIT,
		pb.CacheEvent_EVENT_TYPE_MISS,
		pb.CacheEvent_EVENT_TYPE_EVICT,
	} {
		if !filter[eventType] {
			t.Fatalf("filter does not contain %s: %v", eventType, filter)
		}
	}
}

func TestCacheEventTypeFilterRejectsUnknownType(t *testing.T) {
	if _, err := cacheEventTypeFilter([]string{"not-real"}); err == nil {
		t.Fatal("unknown cache event type was accepted")
	}
}

func TestMatchesDomainPattern(t *testing.T) {
	for _, test := range []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*.example.com", "api.example.com.", true},
		{"*.example.com", "example.com.", false},
		{"api?.example.com", "api1.example.com.", true},
		{"exact.example", "EXACT.EXAMPLE.", true},
		{"*.example.com", "example.net.", false},
	} {
		if got := matchesDomainPattern(normalizeDomainPattern(test.pattern), test.name); got != test.want {
			t.Errorf("matchesDomainPattern(%q, %q) = %v, want %v", test.pattern, test.name, got, test.want)
		}
	}
}

type watchCacheManager struct {
	mock.CacheMgr
	events chan *pb.CacheEvent
	ready  chan struct{}
	once   sync.Once
}

func (m *watchCacheManager) Subscribe() chan *pb.CacheEvent {
	m.once.Do(func() { close(m.ready) })
	return m.events
}

func (m *watchCacheManager) Unsubscribe(chan *pb.CacheEvent) {}

type watchCacheStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	events chan *pb.CacheEvent
}

func (s *watchCacheStream) Send(event *pb.CacheEvent) error {
	s.events <- event
	s.cancel()
	return nil
}

func (s *watchCacheStream) SetHeader(metadata.MD) error  { return nil }
func (s *watchCacheStream) SendHeader(metadata.MD) error { return nil }
func (s *watchCacheStream) SetTrailer(metadata.MD)       {}
func (s *watchCacheStream) Context() context.Context     { return s.ctx }
func (s *watchCacheStream) SendMsg(any) error            { return nil }
func (s *watchCacheStream) RecvMsg(any) error            { return nil }

func TestWatchCacheAppliesEventAndDomainFilters(t *testing.T) {
	manager := &watchCacheManager{
		events: make(chan *pb.CacheEvent, 3),
		ready:  make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream := &watchCacheStream{
		ctx:    ctx,
		cancel: cancel,
		events: make(chan *pb.CacheEvent, 1),
	}
	service := NewCacheService(manager, nil)
	done := make(chan error, 1)
	go func() {
		done <- service.WatchCache(&pb.WatchCacheRequest{
			Types:         []string{"hit"},
			DomainPattern: "*.example.com",
		}, stream)
	}()
	<-manager.ready
	manager.events <- &pb.CacheEvent{Type: pb.CacheEvent_EVENT_TYPE_MISS, Name: "miss.example.com."}
	manager.events <- &pb.CacheEvent{Type: pb.CacheEvent_EVENT_TYPE_HIT, Name: "other.example.net."}
	manager.events <- &pb.CacheEvent{Type: pb.CacheEvent_EVENT_TYPE_HIT, Name: "api.example.com."}

	select {
	case event := <-stream.events:
		if event.Name != "api.example.com." {
			t.Fatalf("streamed event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("WatchCache did not stream the matching event")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WatchCache returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WatchCache did not stop after context cancellation")
	}
}
