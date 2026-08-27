package registry

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/cache"
	"github.com/miekg/dns"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type liveTestServer struct {
	NoopSrvAdapter
	cache   *cache.ShardedCache
	handler func(context.Context, *dns.Msg, net.Addr) (*dns.Msg, error)
}

type prefetchTestServer struct {
	*liveTestServer
	prefetch func(context.Context, string, uint16, uint16) error
}

func (s *prefetchTestServer) Prefetch(ctx context.Context, name string, qtype, qclass uint16) error {
	return s.prefetch(ctx, name, qtype, qclass)
}

func (s *liveTestServer) GetShardedCache() *cache.ShardedCache { return s.cache }
func (s *liveTestServer) HandleDNS(ctx context.Context, req *dns.Msg, remote net.Addr) (*dns.Msg, error) {
	return s.handler(ctx, req, remote)
}

func TestLiveDNSResolverQueriesAttachedServer(t *testing.T) {
	var got *dns.Msg
	var gotRemote net.Addr
	srv := &liveTestServer{handler: func(_ context.Context, req *dns.Msg, remote net.Addr) (*dns.Msg, error) {
		got, gotRemote = req.Copy(), remote
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.9")}}
		return resp, nil
	}}

	result, err := newLiveDNSResolver(srv).Resolve(context.Background(), "www.example", "A", "IN", true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.RecursionDesired || !got.CheckingDisabled || got.IsEdns0() == nil || !got.IsEdns0().Do() {
		t.Fatalf("live query flags were not preserved: %#v", got)
	}
	addr, ok := gotRemote.(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() {
		t.Fatalf("admin query source = %#v, want loopback", gotRemote)
	}
	if !result.Authoritative || len(result.Answer) != 1 || result.Answer[0].Data != "192.0.2.9" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestLiveCacheLookupAndSelectiveFlush(t *testing.T) {
	c := cache.NewShardedCache(cache.Config{ShardCount: 1, MaxEntries: 10})
	defer c.Close()
	msg := new(dns.Msg)
	msg.SetQuestion("www.example.", dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.0.2.10")}}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	c.Set(cache.HashKey("www.example.", dns.TypeA, dns.ClassINET), &cache.Entry{
		Data: wire, ExpiresAt: time.Now().Add(120 * time.Second), OrigTTL: 120,
		QName: "www.example.", QType: dns.TypeA, QClass: dns.ClassINET,
	})
	mgr := newLiveCacheMgr(&liveTestServer{cache: c})
	entries, err := mgr.Lookup(context.Background(), "WWW.EXAMPLE", "A")
	if err != nil || len(entries) != 1 || entries[0].TTL == 0 {
		t.Fatalf("Lookup entries=%#v err=%v", entries, err)
	}
	result, err := mgr.Flush(context.Background(), "FLUSH_SCOPE_EXACT", "www.example", "A", false)
	if err != nil || result.Removed != 1 {
		t.Fatalf("Flush result=%#v err=%v", result, err)
	}
	if stats := c.GetStats(); stats.Size != 0 {
		t.Fatalf("cache still has %d entries", stats.Size)
	}
}

func TestUnsupportedAdminOperationsReturnUnimplemented(t *testing.T) {
	srv := &liveTestServer{}
	if _, err := newLiveControlMgr(srv, "test").Reload(context.Background(), []string{"zones"}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("Reload status = %v, want Unimplemented", status.Code(err))
	}
}

func TestLiveCachePrefetchWarmsResolver(t *testing.T) {
	var questions []dns.Question
	var mu sync.Mutex
	srv := &prefetchTestServer{liveTestServer: &liveTestServer{}, prefetch: func(_ context.Context, name string, qtype, qclass uint16) error {
		mu.Lock()
		questions = append(questions, dns.Question{Name: name, Qtype: qtype, Qclass: qclass})
		mu.Unlock()
		return nil
	}}

	outcome, err := newLiveCacheMgr(srv).Prefetch(
		context.Background(),
		[]string{"one.example", "two.example"},
		[]string{"A", "INVALID"},
		2,
	)
	if err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	if outcome.Queued != 2 || len(outcome.Errors) != 2 {
		t.Fatalf("Prefetch outcome = %#v, want 2 queued and 2 validation errors", outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(questions) != 2 {
		t.Fatalf("resolver questions = %v, want 2", questions)
	}
	for _, question := range questions {
		if question.Qtype != dns.TypeA || question.Qclass != dns.ClassINET {
			t.Fatalf("unexpected prefetch question: %#v", question)
		}
	}
}
