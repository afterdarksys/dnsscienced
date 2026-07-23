package resolver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/packet"
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
