package primarynotify

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/tsig"
	"github.com/miekg/dns"
)

type fakeSender struct {
	mu        sync.Mutex
	failures  int
	permanent bool
	calls     []notification
	targets   []string
	networks  []string
	called    chan struct{}
}

func (s *fakeSender) Send(
	_ context.Context,
	network string,
	target string,
	zoneName string,
	_ ZoneConfig,
	soa *dns.SOA,
) error {
	s.mu.Lock()
	s.calls = append(s.calls, notification{zone: zoneName, soa: soa})
	s.targets = append(s.targets, target)
	s.networks = append(s.networks, network)
	fail := s.failures > 0
	if fail {
		s.failures--
	}
	s.mu.Unlock()
	if fail {
		if s.permanent {
			return permanentError{err: errors.New("rejected")}
		}
		return errors.New("temporary failure")
	}
	select {
	case s.called <- struct{}{}:
	default:
	}
	return nil
}

func testSOA(serial uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1.example.",
		Mbox:    "hostmaster.example.",
		Serial:  serial,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
}

func newTestNotifier(t *testing.T, sender sender, attempts int) *Notifier {
	t.Helper()
	n, err := New(Config{
		Workers: 2,
		Zones: map[string]ZoneConfig{
			"example.": {
				Targets:       []string{"192.0.2.1"},
				AllowUnsigned: true,
				Attempts:      attempts,
				RetryBackoff:  time.Millisecond,
				Timeout:       time.Second,
			},
		},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.sender = sender
	return n
}

func TestNotifierCoalescesNewestSOABeforeStart(t *testing.T) {
	fake := &fakeSender{called: make(chan struct{}, 1)}
	n := newTestNotifier(t, fake, 1)
	if err := n.Notify("EXAMPLE.", testSOA(1)); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify("example.", testSOA(2)); err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	select {
	case <-fake.called:
	case <-time.After(time.Second):
		t.Fatal("notification was not delivered")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.calls) != 1 || fake.calls[0].soa.Serial != 2 {
		t.Fatalf("calls=%+v, want one notification with serial 2", fake.calls)
	}
	stats := n.Stats()
	if stats.Enqueued != 1 || stats.Coalesced != 1 || stats.Delivered != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestNotifierRetriesWithBoundedAttempts(t *testing.T) {
	fake := &fakeSender{failures: 2, called: make(chan struct{}, 1)}
	n := newTestNotifier(t, fake, 3)
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if err := n.Notify("example.", testSOA(3)); err != nil {
		t.Fatal(err)
	}

	select {
	case <-fake.called:
	case <-time.After(time.Second):
		t.Fatal("notification did not succeed after retries")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.calls) != 3 {
		t.Fatalf("calls=%d, want 3", len(fake.calls))
	}
	if stats := n.Stats(); stats.Retries != 2 || stats.Delivered != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestNotifierFallsBackToTCPAfterUDPRetries(t *testing.T) {
	fake := &fakeSender{failures: 2, called: make(chan struct{}, 1)}
	n := newTestNotifier(t, fake, 2)
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if err := n.Notify("example.", testSOA(4)); err != nil {
		t.Fatal(err)
	}

	select {
	case <-fake.called:
	case <-time.After(time.Second):
		t.Fatal("TCP fallback did not succeed")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.networks) != 3 ||
		fake.networks[0] != "udp" ||
		fake.networks[1] != "udp" ||
		fake.networks[2] != "tcp" {
		t.Fatalf("networks=%v, want [udp udp tcp]", fake.networks)
	}
	if stats := n.Stats(); stats.Retries != 1 || stats.TCPFallbacks != 1 || stats.Delivered != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestNotifierDoesNotRetryPermanentRejection(t *testing.T) {
	fake := &fakeSender{failures: 10, permanent: true, called: make(chan struct{}, 1)}
	n := newTestNotifier(t, fake, 3)
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if err := n.Notify("example.", testSOA(5)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if n.Stats().Failed == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.calls) != 1 {
		t.Fatalf("calls=%d, want one permanent rejection without retry", len(fake.calls))
	}
	if stats := n.Stats(); stats.Retries != 0 || stats.TCPFallbacks != 0 || stats.Failed != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestNotifierRequiresAuthenticationByDefault(t *testing.T) {
	_, err := New(Config{Zones: map[string]ZoneConfig{
		"example.": {Targets: []string{"192.0.2.1"}},
	}}, nil, nil)
	if err == nil {
		t.Fatal("New accepted unsigned NOTIFY without explicit opt-in")
	}
}

func TestNotifierIgnoresUnconfiguredZone(t *testing.T) {
	fake := &fakeSender{called: make(chan struct{}, 1)}
	n := newTestNotifier(t, fake, 1)
	if err := n.Notify("other.", testSOA(1)); err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	select {
	case <-fake.called:
		t.Fatal("unconfigured zone was notified")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestDNSSenderAuthenticatedRoundTrip(t *testing.T) {
	keyRing, err := tsig.NewKeyRing([]tsig.KeyConfig{{
		Name:      "notify-key.example.",
		Algorithm: "hmac-sha256",
		Secret:    base64.StdEncoding.EncodeToString([]byte("notify-test-secret")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan *dns.Msg, 1)
	server := &dns.Server{
		PacketConn:   packetConn,
		TsigProvider: keyRing,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			received <- request.Copy()
			response := new(dns.Msg)
			response.SetReply(request)
			requestTSIG := request.IsTsig()
			if requestTSIG == nil || w.TsigStatus() != nil {
				response.Rcode = dns.RcodeNotAuth
				_ = w.WriteMsg(response)
				return
			}
			response.SetTsig(
				requestTSIG.Hdr.Name,
				requestTSIG.Algorithm,
				requestTSIG.Fudge,
				time.Now().Unix(),
			)
			_ = w.WriteMsg(response)
		}),
	}
	done := make(chan error, 1)
	go func() {
		done <- server.ActivateAndServe()
	}()
	defer func() {
		_ = server.Shutdown()
		<-done
	}()

	cfg := ZoneConfig{
		TSIGKey:       "notify-key.example.",
		TSIGAlgorithm: dns.HmacSHA256,
		Timeout:       time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := (dnsSender{provider: keyRing}).Send(
		ctx,
		"udp",
		packetConn.LocalAddr().String(),
		"example.",
		cfg,
		testSOA(42),
	); err != nil {
		t.Fatal(err)
	}
	select {
	case request := <-received:
		if request.Opcode != dns.OpcodeNotify ||
			request.IsTsig() == nil ||
			len(request.Answer) != 1 ||
			request.Answer[0].(*dns.SOA).Serial != 42 {
			t.Fatalf("request=%v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive NOTIFY")
	}
}
