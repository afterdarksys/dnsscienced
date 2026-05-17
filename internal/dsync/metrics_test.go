package dsync

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// TestMetricsIncrement verifies that HandleInbound increments NotifyInbound counters.
func TestMetricsIncrement(t *testing.T) {
	// Create a private registry to avoid conflicts with other tests that use the
	// default global registry (NewDSYNCMetrics calls prometheus.MustRegister).
	// We use a manually constructed DSYNCMetrics with unregistered counters.
	inbound := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_dsync_notify_inbound_total",
			Help: "test inbound counter",
		},
		[]string{"zone", "result"},
	)

	lim := permissiveLimiter()
	defer lim.Close()

	h := newTestHandler(lim, AllowAllACL())

	m := &DSYNCMetrics{
		NotifyInbound: inbound,
	}
	h.SetMetrics(m)

	// Send a NOTIFY(CDS) from an allowed source — should produce "accepted".
	msg := new(dns.Msg)
	msg.SetNotify("example.com.")
	msg.Question[0].Qtype = dns.TypeCDS

	w := &mockResponseWriter{}
	h.HandleInbound(w, msg, net.ParseIP("192.0.2.1"))

	// Assert NOERROR was returned.
	if w.msg == nil {
		t.Fatal("expected a reply but got none")
	}
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode, "expected NOERROR from HandleInbound")

	// Assert inbound accepted counter incremented to 1.
	val := testutil.ToFloat64(inbound.WithLabelValues("example.com.", "accepted"))
	assert.Equal(t, float64(1), val, "inbound accepted counter should be 1")
}

// TestMetricsIncrement_ACLRefused verifies that HandleInbound increments refused_acl counter.
func TestMetricsIncrement_ACLRefused(t *testing.T) {
	inbound := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_dsync_notify_acl_refused_total",
			Help: "test acl refused counter",
		},
		[]string{"zone", "result"},
	)

	lim := permissiveLimiter()
	defer lim.Close()

	h := newTestHandler(lim, rejectAll{})
	h.SetMetrics(&DSYNCMetrics{NotifyInbound: inbound})

	msg := new(dns.Msg)
	msg.SetNotify("example.com.")
	msg.Question[0].Qtype = dns.TypeCDS

	w := &mockResponseWriter{}
	h.HandleInbound(w, msg, net.ParseIP("192.0.2.1"))

	assert.Equal(t, dns.RcodeRefused, w.msg.Rcode, "expected REFUSED from ACL rejection")

	val := testutil.ToFloat64(inbound.WithLabelValues("example.com.", "refused_acl"))
	assert.Equal(t, float64(1), val, "refused_acl counter should be 1")
}

// TestMetricsIncrement_RateLimitRefused verifies that HandleInbound increments refused_ratelimit counter.
func TestMetricsIncrement_RateLimitRefused(t *testing.T) {
	inbound := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_dsync_notify_ratelimit_refused_total",
			Help: "test ratelimit refused counter",
		},
		[]string{"zone", "result"},
	)

	lim := blockedLimiter(t)
	defer lim.Close()

	h := newTestHandler(lim, AllowAllACL())
	h.SetMetrics(&DSYNCMetrics{NotifyInbound: inbound})

	msg := new(dns.Msg)
	msg.SetNotify("example.com.")
	msg.Question[0].Qtype = dns.TypeCDS

	// Use the same IP that blockedLimiter drained (1.2.3.4).
	w := &mockResponseWriter{}
	h.HandleInbound(w, msg, net.ParseIP("1.2.3.4"))

	assert.Equal(t, dns.RcodeRefused, w.msg.Rcode, "expected REFUSED from rate limit")

	val := testutil.ToFloat64(inbound.WithLabelValues("example.com.", "refused_ratelimit"))
	assert.Equal(t, float64(1), val, "refused_ratelimit counter should be 1")
}
