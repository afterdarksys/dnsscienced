package server

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// ednsVersionTestResponseWriter captures the full DNS message written to it
// via a deep copy, so that pool.PutMessage's reset (deferred in handleDNS)
// does not clobber the captured Rcode/Extra/Answer sections.
type ednsVersionTestResponseWriter struct {
	msg        *dns.Msg
	written    bool
	remoteAddr net.Addr
}

func newEDNSVersionTestResponseWriter(ip string) *ednsVersionTestResponseWriter {
	return &ednsVersionTestResponseWriter{
		remoteAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 1234},
	}
}

func (w *ednsVersionTestResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (w *ednsVersionTestResponseWriter) RemoteAddr() net.Addr { return w.remoteAddr }
func (w *ednsVersionTestResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m.Copy()
	w.written = true
	return nil
}
func (w *ednsVersionTestResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *ednsVersionTestResponseWriter) Close() error                { return nil }
func (w *ednsVersionTestResponseWriter) TsigStatus() error           { return nil }
func (w *ednsVersionTestResponseWriter) TsigTimersOnly(b bool)       {}
func (w *ednsVersionTestResponseWriter) Hijack()                     {}

// makeEDNSVersionRequest creates a standard A query for name with an EDNS0
// OPT record carrying the given EDNS VERSION.
func makeEDNSVersionRequest(name string, version uint8) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.SetEdns0(4096, false)
	opt := m.IsEdns0()
	opt.SetVersion(version)
	return m
}

// TestHandleDNS_EDNSVersionTooHigh verifies RFC 6891 §6.1.3: a query
// advertising EDNS VERSION >= 1 gets RCODE BADVERS back with an OPT RR
// advertising VERSION 0, and no answer section — instead of being processed
// as a normal query.
func TestHandleDNS_EDNSVersionTooHigh(t *testing.T) {
	cfg := Config{}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newEDNSVersionTestResponseWriter("1.2.3.4")
	r := makeEDNSVersionRequest("example.com.", 1)

	s.handleDNS(w, r)

	if !w.written {
		t.Fatal("handleDNS did not write a response")
	}
	if w.msg.Rcode != dns.RcodeBadVers {
		t.Errorf("Rcode = %d, want %d (BADVERS)", w.msg.Rcode, dns.RcodeBadVers)
	}
	if len(w.msg.Answer) != 0 {
		t.Errorf("Answer section not empty: %v", w.msg.Answer)
	}

	respOpt := w.msg.IsEdns0()
	if respOpt == nil {
		t.Fatal("response has no OPT record")
	}
	if respOpt.Version() != 0 {
		t.Errorf("response OPT version = %d, want 0", respOpt.Version())
	}
}

// TestHandleDNS_EDNSVersionZero_Unaffected verifies that a normal query with
// EDNS VERSION 0 (or no EDNS at all) is not intercepted by the BADVERS check.
func TestHandleDNS_EDNSVersionZero_Unaffected(t *testing.T) {
	cfg := Config{}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newEDNSVersionTestResponseWriter("1.2.3.4")
	r := makeEDNSVersionRequest("example.com.", 0)

	s.handleDNS(w, r)

	if !w.written {
		t.Fatal("handleDNS did not write a response")
	}
	if w.msg.Rcode == dns.RcodeBadVers {
		t.Errorf("Rcode = BADVERS, EDNS version 0 request should not be rejected")
	}
}
