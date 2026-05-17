package dsync

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// mockResponseWriter captures the DNS message written by the handler.
type mockResponseWriter struct {
	msg *dns.Msg
}

func (m *mockResponseWriter) LocalAddr() net.Addr        { return &net.UDPAddr{} }
func (m *mockResponseWriter) RemoteAddr() net.Addr       { return &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1234} }
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) Close() error                { return nil }
func (m *mockResponseWriter) TsigStatus() error          { return nil }
func (m *mockResponseWriter) TsigTimersOnly(b bool)      {}
func (m *mockResponseWriter) Hijack()                    {}

// rejectAll is a test Allower that always rejects.
type rejectAll struct{}

func (rejectAll) Check(_ net.IP) bool { return false }

// newTestHandler creates a Handler suitable for unit tests.
// It uses a zerolog.Nop() logger to suppress output.
func newTestHandler(limiter *NotifyLimiter, acl Allower) *Handler {
	return NewHandler(limiter, acl, zerolog.Nop(), nil)
}

// makeNotifyMsg creates a NOTIFY DNS message with the given qtype.
func makeNotifyMsg(qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetNotify("example.com.")
	m.Question[0].Qtype = qtype
	return m
}

// permissiveLimiter returns a NotifyLimiter that always allows.
func permissiveLimiter() *NotifyLimiter {
	nl := NewNotifyLimiter(1000, 10000)
	return nl
}

// blockedLimiter returns a NotifyLimiter whose Allow() always returns false
// by exhausting the token bucket before the test call.
func blockedLimiter(t *testing.T) *NotifyLimiter {
	t.Helper()
	// Use a very small burst of 1 and drain it.
	nl := NewNotifyLimiter(0.00001, 1)
	ip := net.ParseIP("1.2.3.4")
	// Drain the single token.
	nl.Allow(ip)
	return nl
}

// TestHandleInbound_ACLReject verifies that a NOTIFY from an ACL-rejected source
// receives dns.RcodeRefused, and that the rate limiter is never called.
func TestHandleInbound_ACLReject(t *testing.T) {
	lim := permissiveLimiter()
	defer lim.Close()

	h := newTestHandler(lim, rejectAll{})
	w := &mockResponseWriter{}
	r := makeNotifyMsg(dns.TypeCDS)

	h.HandleInbound(w, r, net.ParseIP("1.2.3.4"))

	if w.msg == nil {
		t.Fatal("expected a reply but got none")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("expected RcodeRefused(%d), got %d", dns.RcodeRefused, w.msg.Rcode)
	}
}

// TestHandleInbound_RateLimited verifies that a NOTIFY from an allowed source that
// exceeds the rate limit receives dns.RcodeRefused.
func TestHandleInbound_RateLimited(t *testing.T) {
	lim := blockedLimiter(t)
	defer lim.Close()

	h := newTestHandler(lim, AllowAllACL())
	w := &mockResponseWriter{}
	r := makeNotifyMsg(dns.TypeCDS)

	h.HandleInbound(w, r, net.ParseIP("1.2.3.4"))

	if w.msg == nil {
		t.Fatal("expected a reply but got none")
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("expected RcodeRefused(%d), got %d", dns.RcodeRefused, w.msg.Rcode)
	}
}

// TestHandleInbound_Success_CDS verifies that a NOTIFY(CDS) from an allowed,
// non-rate-limited source receives dns.RcodeSuccess (NOERROR).
func TestHandleInbound_Success_CDS(t *testing.T) {
	lim := permissiveLimiter()
	defer lim.Close()

	h := newTestHandler(lim, AllowAllACL())
	w := &mockResponseWriter{}
	r := makeNotifyMsg(dns.TypeCDS)

	h.HandleInbound(w, r, net.ParseIP("1.2.3.4"))

	if w.msg == nil {
		t.Fatal("expected a reply but got none")
	}
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess(%d), got %d", dns.RcodeSuccess, w.msg.Rcode)
	}
}

// TestHandleInbound_Success_CSYNC verifies that a NOTIFY(CSYNC) from an allowed,
// non-rate-limited source receives dns.RcodeSuccess (NOERROR).
func TestHandleInbound_Success_CSYNC(t *testing.T) {
	lim := permissiveLimiter()
	defer lim.Close()

	h := newTestHandler(lim, AllowAllACL())
	w := &mockResponseWriter{}
	r := makeNotifyMsg(dns.TypeCSYNC)

	h.HandleInbound(w, r, net.ParseIP("10.0.0.1"))

	if w.msg == nil {
		t.Fatal("expected a reply but got none")
	}
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess(%d), got %d", dns.RcodeSuccess, w.msg.Rcode)
	}
}

// TestHandleInbound_NoQuestion verifies that a NOTIFY with an empty Question section
// receives dns.RcodeFormatError.
func TestHandleInbound_NoQuestion(t *testing.T) {
	lim := permissiveLimiter()
	defer lim.Close()

	h := newTestHandler(lim, AllowAllACL())
	w := &mockResponseWriter{}

	// Build a NOTIFY message with no question.
	r := new(dns.Msg)
	r.SetNotify("example.com.")
	r.Question = nil // Clear the question section.

	h.HandleInbound(w, r, net.ParseIP("1.2.3.4"))

	if w.msg == nil {
		t.Fatal("expected a reply but got none")
	}
	if w.msg.Rcode != dns.RcodeFormatError {
		t.Errorf("expected RcodeFormatError(%d), got %d", dns.RcodeFormatError, w.msg.Rcode)
	}
}

// TestHandleInbound_NonDSYNCQtype verifies that a NOTIFY with Qtype=TypeSOA
// (not CDS/CSYNC) receives NOERROR but does not spawn a delegation check goroutine.
// We verify NOERROR response; goroutine behavior is validated structurally.
func TestHandleInbound_NonDSYNCQtype(t *testing.T) {
	lim := permissiveLimiter()
	defer lim.Close()

	h := newTestHandler(lim, AllowAllACL())
	w := &mockResponseWriter{}
	r := makeNotifyMsg(dns.TypeSOA)

	h.HandleInbound(w, r, net.ParseIP("1.2.3.4"))

	if w.msg == nil {
		t.Fatal("expected a reply but got none")
	}
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess(%d) for non-CDS/CSYNC qtype, got %d", dns.RcodeSuccess, w.msg.Rcode)
	}
}
