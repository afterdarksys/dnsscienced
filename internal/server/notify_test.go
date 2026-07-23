package server

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// testResponseWriter captures the DNS message written to it.
// It copies the message on WriteMsg so that the pool.PutMessage defer in handleDNS
// does not reset the captured Rcode after the handler returns.
type testResponseWriter struct {
	rcode              int
	written            bool
	recursionAvailable bool
	msg                *dns.Msg
	remoteAddr         net.Addr
}

func newTestResponseWriter(ip string) *testResponseWriter {
	return &testResponseWriter{
		remoteAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 1234},
	}
}

func (t *testResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (t *testResponseWriter) RemoteAddr() net.Addr { return t.remoteAddr }
func (t *testResponseWriter) WriteMsg(m *dns.Msg) error {
	t.rcode = m.Rcode
	t.recursionAvailable = m.RecursionAvailable
	t.msg = m.Copy()
	t.written = true
	return nil
}
func (t *testResponseWriter) Write(b []byte) (int, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(b); err != nil {
		return 0, err
	}
	if err := t.WriteMsg(msg); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (t *testResponseWriter) Close() error          { return nil }
func (t *testResponseWriter) TsigStatus() error     { return nil }
func (t *testResponseWriter) TsigTimersOnly(b bool) {}
func (t *testResponseWriter) Hijack()               {}

// makeNotifyRequest creates a NOTIFY dns.Msg for the given qtype.
func makeNotifyRequest(qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetNotify("example.com.")
	m.Question[0].Qtype = qtype
	return m
}

// makeQueryRequest creates a standard A query dns.Msg.
func makeQueryRequest(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

// TestHandleDNSNotifyOpcode_Enabled verifies that a NOTIFY message sent to a
// DSYNC-enabled server gets a NOERROR response (RFC 9859 / RFC 1996 §3.10).
// The authoritative and recursive paths must NOT be invoked — verified by not
// configuring zones or a recursive resolver.
func TestHandleDNSNotifyOpcode_Enabled(t *testing.T) {
	cfg := Config{
		DSYNC: DSYNCConfig{
			Enabled:         true,
			RateLimitPerMin: 300,
			Burst:           10,
		},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newTestResponseWriter("1.2.3.4")
	r := makeNotifyRequest(dns.TypeCDS)

	s.handleDNS(w, r)

	if !w.written {
		t.Fatal("handleDNS did not write a response")
	}
	if w.rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want %d (NOERROR)", w.rcode, dns.RcodeSuccess)
	}
}

// TestHandleDNSNotifyOpcode_Disabled verifies that a NOTIFY message sent to a
// server with DSYNC.Enabled=false gets a NOTIMPL response immediately.
func TestHandleDNSNotifyOpcode_Disabled(t *testing.T) {
	cfg := Config{
		DSYNC: DSYNCConfig{
			Enabled: false,
		},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newTestResponseWriter("1.2.3.4")
	r := makeNotifyRequest(dns.TypeCDS)

	s.handleDNS(w, r)

	if !w.written {
		t.Fatal("handleDNS did not write a response")
	}
	if w.rcode != dns.RcodeNotImplemented {
		t.Errorf("Rcode = %d, want %d (NOTIMPL)", w.rcode, dns.RcodeNotImplemented)
	}
}

func TestOrdinarySOANotifyIsNotAcceptedAsDSYNC(t *testing.T) {
	cfg := Config{DSYNC: DSYNCConfig{Enabled: true, RateLimitPerMin: 300, Burst: 10}}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	w := newTestResponseWriter("1.2.3.4")
	s.handleDNS(w, makeNotifyRequest(dns.TypeSOA))
	if !w.written || w.rcode != dns.RcodeNotImplemented {
		t.Fatalf("written=%v rcode=%d, want NOTIMPL", w.written, w.rcode)
	}
}

// TestHandleDNSQuery_Unaffected verifies that a normal A query still goes through
// the normal query processing path (opcode branch does not intercept OpcodeQuery=0).
// With no recursive or authoritative configured, the server returns REFUSED.
func TestHandleDNSQuery_Unaffected(t *testing.T) {
	cfg := Config{
		DSYNC: DSYNCConfig{
			Enabled:         true,
			RateLimitPerMin: 300,
			Burst:           10,
		},
		// No EnableRecursive, no EnableAuthoritative
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newTestResponseWriter("1.2.3.4")
	r := makeQueryRequest("example.com.")

	s.handleDNS(w, r)

	if !w.written {
		t.Fatal("handleDNS did not write a response")
	}
	// Normal query path — should NOT get NOTIMPL (that's the NOTIFY disabled response)
	// With no resolver/authoritative, server returns REFUSED
	if w.rcode == dns.RcodeNotImplemented {
		t.Errorf("Normal query got NOTIMPL — opcode branch incorrectly intercepted OpcodeQuery")
	}
}
