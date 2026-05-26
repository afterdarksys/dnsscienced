package eventbus

import (
	"context"
	"sync"
)

type Topic string

const (
	TopicZone   Topic = "zone"
	TopicCache  Topic = "cache"
	TopicServer Topic = "server"
	TopicDNSSEC Topic = "dnssec"
	TopicQuery  Topic = "query"
)

// QueryEvent is published for every DNS query that completes the pipeline.
type QueryEvent struct {
	Domain       string // queried name (e.g. "example.com.")
	QType        string // query type string (e.g. "A", "AAAA", "MX")
	Verdict      string // "ALLOW", "BLOCK", "NXDOMAIN", "NOERROR", etc.
	Zone         string // matched zone name, empty if none
	ClientPrefix string // client IP prefix (first 3 octets for privacy)
	Protocol     string // "udp" or "tcp"
	LatencyUs    int64  // query processing latency in microseconds
	Timestamp    int64  // Unix nanoseconds
}

type Event struct {
	Topic Topic
	Data  interface{}
}

type Subscriber struct {
	Ch   <-chan Event
	stop context.CancelFunc
}

type Bus struct {
	mu   sync.RWMutex
	subs map[Topic][]chan Event
	buf  int
}

func New(buf int) *Bus {
	return &Bus{subs: make(map[Topic][]chan Event), buf: buf}
}

func (b *Bus) Publish(ctx context.Context, topic Topic, data interface{}) {
	b.mu.RLock()
	chs := b.subs[topic]
	b.mu.RUnlock()
	for _, ch := range chs {
		select {
		case ch <- Event{Topic: topic, Data: data}:
		default:
			// drop if subscriber is slow
		}
	}
}

func (b *Bus) Subscribe(ctx context.Context, topic Topic) *Subscriber {
	ch := make(chan Event, b.buf)
	b.mu.Lock()
	b.subs[topic] = append(b.subs[topic], ch)
	b.mu.Unlock()

	cctx, cancel := context.WithCancel(ctx)
	go func() {
		<-cctx.Done()
		b.mu.Lock()
		subs := b.subs[topic]
		for i, c := range subs {
			if c == ch {
				b.subs[topic] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		b.mu.Unlock()
		close(ch)
	}()
	return &Subscriber{Ch: ch, stop: cancel}
}

func (s *Subscriber) Close() { if s.stop != nil { s.stop() } }
