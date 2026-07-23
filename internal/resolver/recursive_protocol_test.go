package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/packet"
	"github.com/dnsscience/dnsscienced/internal/worker"
	"github.com/miekg/dns"
)

func startDualProtocolDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	udpConn, err := net.ListenPacket("udp", tcpListener.Addr().String())
	if err != nil {
		_ = tcpListener.Close()
		t.Fatalf("listen UDP: %v", err)
	}

	tcpServer := &dns.Server{Listener: tcpListener, Handler: handler}
	udpServer := &dns.Server{PacketConn: udpConn, Handler: handler}
	go func() { _ = tcpServer.ActivateAndServe() }()
	go func() { _ = udpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return tcpListener.Addr().String()
}

func TestQueryNameserverRetriesTruncatedUDPOverTCP(t *testing.T) {
	var udpQueries atomic.Int32
	var tcpQueries atomic.Int32
	addr := startDualProtocolDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			udpQueries.Add(1)
			resp.Truncated = true
		} else {
			tcpQueries.Add(1)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.80"),
			}}
		}
		_ = w.WriteMsg(resp)
	}))

	r, err := NewRecursive(Config{QueryTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewRecursive: %v", err)
	}
	defer r.Close()

	resp, err := r.queryNameserver(context.Background(), addr, "example.com.", dns.TypeA, dns.ClassINET)
	if err != nil {
		t.Fatalf("queryNameserver: %v", err)
	}
	if resp.Truncated || len(resp.Answer) != 1 {
		t.Fatalf("response truncated=%v answers=%d, want complete TCP answer", resp.Truncated, len(resp.Answer))
	}
	if udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatalf("UDP queries=%d TCP queries=%d, want one of each", udpQueries.Load(), tcpQueries.Load())
	}
}

func TestResolveAgesFreshCacheTTLs(t *testing.T) {
	r, err := NewRecursive(Config{CacheConfig: cache.Config{ShardCount: 1, MaxEntries: 10}})
	if err != nil {
		t.Fatalf("NewRecursive: %v", err)
	}
	defer r.Close()

	cached := new(dns.Msg)
	cached.SetQuestion("example.com.", dns.TypeA)
	cached.Response = true
	cached.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.81"),
	}}
	wire, err := cached.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	q := cached.Question[0]
	r.cache.Set(packet.HashQuery(q.Name, q.Qtype, q.Qclass), &cache.Entry{
		Data: wire, ExpiresAt: time.Now().Add(30 * time.Minute), OrigTTL: 3600,
		QName: q.Name, QType: q.Qtype, QClass: q.Qclass,
	})

	query := new(dns.Msg)
	query.SetQuestion(q.Name, q.Qtype)
	resp, err := r.Resolve(context.Background(), query, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := resp.Answer[0].Header().Ttl
	if got > 1800 || got < 1795 {
		t.Fatalf("aged TTL=%d, want approximately 1800", got)
	}
}

func TestResolveCoalescesConcurrentCacheMisses(t *testing.T) {
	var queries atomic.Int32
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	addr := startDualProtocolDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if queries.Add(1) == 1 {
			close(lookupStarted)
		}
		<-releaseLookup
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("198.51.100.20"),
		}}
		_ = w.WriteMsg(resp)
	}))

	r, err := NewRecursive(Config{QueryTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewRecursive: %v", err)
	}
	defer r.Close()
	r.roots = []string{addr}

	const callers = 32
	start := make(chan struct{})
	results := make(chan *dns.Msg, callers)
	errs := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for i := range callers {
		go func(id int) {
			query := new(dns.Msg)
			query.SetQuestion("burst.example.", dns.TypeA)
			query.Id = uint16(id + 1)
			ready.Done()
			<-start
			resp, resolveErr := r.Resolve(context.Background(), query, nil)
			results <- resp
			errs <- resolveErr
		}(i)
	}
	ready.Wait()
	close(start)

	select {
	case <-lookupStarted:
	case <-time.After(time.Second):
		t.Fatal("upstream lookup did not start")
	}
	time.Sleep(20 * time.Millisecond)
	if got := queries.Load(); got != 1 {
		t.Fatalf("upstream queries while lookup blocked = %d, want 1", got)
	}
	close(releaseLookup)

	seenIDs := make(map[uint16]bool, callers)
	for range callers {
		if resolveErr := <-errs; resolveErr != nil {
			t.Fatalf("Resolve: %v", resolveErr)
		}
		resp := <-results
		seenIDs[resp.Id] = true
	}
	if len(seenIDs) != callers {
		t.Fatalf("response IDs = %v, want %d independent IDs", seenIDs, callers)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("upstream queries = %d, want 1", got)
	}
	if stats := r.GetStats().Pool; stats.Submitted != 1 || stats.Completed != 1 {
		t.Fatalf("worker stats = %+v, want one submitted and completed lookup", stats)
	}
}

func TestResolveRejectsWhenWorkerQueueIsFull(t *testing.T) {
	lookupStarted := make(chan struct{})
	releaseLookups := make(chan struct{})
	addr := startDualProtocolDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		select {
		case <-lookupStarted:
		default:
			close(lookupStarted)
		}
		<-releaseLookups
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("198.51.100.23"),
		}}
		_ = w.WriteMsg(resp)
	}))

	r, err := NewRecursive(Config{
		Workers:         1,
		WorkerQueueSize: 1,
		QueryTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("NewRecursive: %v", err)
	}
	defer r.Close()
	r.roots = []string{addr}

	resolveAsync := func(name string) <-chan error {
		done := make(chan error, 1)
		go func() {
			query := new(dns.Msg)
			query.SetQuestion(name, dns.TypeA)
			_, resolveErr := r.Resolve(context.Background(), query, nil)
			done <- resolveErr
		}()
		return done
	}

	first := resolveAsync("first.example.")
	select {
	case <-lookupStarted:
	case <-time.After(time.Second):
		t.Fatal("first worker did not start")
	}
	second := resolveAsync("second.example.")
	deadline := time.Now().Add(time.Second)
	for r.GetStats().Pool.QueueDepth != 1 {
		if time.Now().After(deadline) {
			t.Fatal("second lookup did not enter worker queue")
		}
		time.Sleep(time.Millisecond)
	}

	thirdQuery := new(dns.Msg)
	thirdQuery.SetQuestion("third.example.", dns.TypeA)
	if _, err := r.Resolve(context.Background(), thirdQuery, nil); !errors.Is(err, worker.ErrQueueFull) {
		t.Fatalf("third Resolve error = %v, want ErrQueueFull", err)
	}
	stats := r.GetStats().Pool
	if stats.BusyWorkers != 1 || stats.QueueDepth != 1 || stats.Rejected != 1 {
		t.Fatalf("saturated worker stats = %+v", stats)
	}

	close(releaseLookups)
	if err := <-first; err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
}

func TestPrefetchRefreshesLiveCacheEntry(t *testing.T) {
	var queries atomic.Int32
	refreshed := make(chan struct{})
	addr := startDualProtocolDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		queries.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("198.51.100.22"),
		}}
		_ = w.WriteMsg(resp)
		select {
		case <-refreshed:
		default:
			close(refreshed)
		}
	}))

	r, err := NewRecursive(Config{
		QueryTimeout: time.Second,
		CacheConfig: cache.Config{
			ShardCount:        1,
			MaxEntries:        10,
			Prefetch:          true,
			PrefetchMinTTLPct: 0.1,
		},
	})
	if err != nil {
		t.Fatalf("NewRecursive: %v", err)
	}
	defer r.Close()
	r.roots = []string{addr}

	old := new(dns.Msg)
	old.SetQuestion("popular.example.", dns.TypeA)
	old.Response = true
	old.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "popular.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 100},
		A:   net.ParseIP("198.51.100.21"),
	}}
	wire, packErr := old.Pack()
	if packErr != nil {
		t.Fatalf("Pack: %v", packErr)
	}
	question := old.Question[0]
	r.cache.Set(packet.HashQuery(question.Name, question.Qtype, question.Qclass), &cache.Entry{
		Data: wire, ExpiresAt: time.Now().Add(time.Second), OrigTTL: 100,
		QName: question.Name, QType: question.Qtype, QClass: question.Qclass,
	})

	query := new(dns.Msg)
	query.SetQuestion(question.Name, question.Qtype)
	first, err := r.Resolve(context.Background(), query, nil)
	if err != nil {
		t.Fatalf("initial Resolve: %v", err)
	}
	if got := first.Answer[0].(*dns.A).A.String(); got != "198.51.100.21" {
		t.Fatalf("initial answer = %s, want cached address", got)
	}

	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not query upstream")
	}

	deadline := time.Now().Add(time.Second)
	for {
		current, resolveErr := r.Resolve(context.Background(), query, nil)
		if resolveErr != nil {
			t.Fatalf("refreshed Resolve: %v", resolveErr)
		}
		if got := current.Answer[0].(*dns.A).A.String(); got == "198.51.100.22" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("live cache entry was not replaced by background refresh")
		}
		time.Sleep(time.Millisecond)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("upstream refresh queries = %d, want 1", got)
	}
}

func TestQNAMEMinimizationContinuesAfterIntermediatePositiveAnswer(t *testing.T) {
	addr := startDualProtocolDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		if q.Name == "www.example." && q.Qtype == dns.TypeMX {
			resp.Answer = []dns.RR{&dns.MX{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Mx:  "mail.example.",
			}}
		} else {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.82"),
			}}
		}
		_ = w.WriteMsg(resp)
	}))

	r, err := NewRecursive(Config{QueryTimeout: time.Second, QNAMEMinimization: true})
	if err != nil {
		t.Fatalf("NewRecursive: %v", err)
	}
	defer r.Close()
	r.roots = []string{addr}

	resp, err := r.resolveIterative(context.Background(), "www.example.", dns.TypeMX, dns.ClassINET)
	if err != nil {
		t.Fatalf("resolveIterative: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != dns.TypeMX {
		t.Fatalf("answer=%v, want final MX rather than intermediate A", resp.Answer)
	}
}

func TestResolveFollowsCNAMEChain(t *testing.T) {
	addr := startDualProtocolDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		switch q.Name {
		case "alias.example.":
			resp.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "target.example.",
			}}
		case "target.example.":
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.83"),
			}}
		}
		_ = w.WriteMsg(resp)
	}))

	r, err := NewRecursive(Config{QueryTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewRecursive: %v", err)
	}
	defer r.Close()
	r.roots = []string{addr}

	query := new(dns.Msg)
	query.SetQuestion("alias.example.", dns.TypeA)
	query.RecursionDesired = true
	resp, err := r.Resolve(context.Background(), query, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Answer) != 2 || resp.Answer[0].Header().Rrtype != dns.TypeCNAME || resp.Answer[1].Header().Rrtype != dns.TypeA {
		t.Fatalf("answer=%v, want CNAME followed by terminal A", resp.Answer)
	}
	if !resp.RecursionDesired || !resp.RecursionAvailable {
		t.Fatalf("response flags RD=%v RA=%v, want both true", resp.RecursionDesired, resp.RecursionAvailable)
	}
}

func TestResolveFollowsDNAMEAndSynthesizesCNAME(t *testing.T) {
	addr := startDualProtocolDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		switch q.Name {
		case "host.example.":
			resp.Answer = []dns.RR{&dns.DNAME{
				Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "example.net.",
			}}
		case "host.example.net.":
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.84"),
			}}
		}
		_ = w.WriteMsg(resp)
	}))

	r, err := NewRecursive(Config{QueryTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewRecursive: %v", err)
	}
	defer r.Close()
	r.roots = []string{addr}

	query := new(dns.Msg)
	query.SetQuestion("host.example.", dns.TypeA)
	query.RecursionDesired = true
	resp, err := r.Resolve(context.Background(), query, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Answer) != 3 || resp.Answer[0].Header().Rrtype != dns.TypeDNAME ||
		resp.Answer[1].Header().Rrtype != dns.TypeCNAME || resp.Answer[2].Header().Rrtype != dns.TypeA {
		t.Fatalf("answer=%v, want DNAME, synthesized CNAME, terminal A", resp.Answer)
	}
}
