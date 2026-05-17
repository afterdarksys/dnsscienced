package dsync

import (
	"github.com/prometheus/client_golang/prometheus"
)

// DSYNCMetrics holds Prometheus counters for DSYNC NOTIFY events.
// Follows the same pattern as internal/metrics/metrics.go.
type DSYNCMetrics struct {
	// NotifyInbound counts inbound NOTIFY processing.
	// Labels: zone, result (accepted/refused_acl/refused_ratelimit)
	NotifyInbound *prometheus.CounterVec

	// NotifyOutbound counts outbound NOTIFY sends.
	// Labels: zone, result (sent/failed)
	NotifyOutbound *prometheus.CounterVec

	// Webhook counts webhook delivery attempts.
	// Labels: zone, result (ok/err)
	Webhook *prometheus.CounterVec
}

// NewDSYNCMetrics creates and registers all DSYNC Prometheus counters.
func NewDSYNCMetrics() *DSYNCMetrics {
	m := &DSYNCMetrics{
		NotifyInbound: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_dsync_notify_inbound_total",
				Help: "Total inbound DSYNC NOTIFY messages processed",
			},
			[]string{"zone", "result"},
		),
		NotifyOutbound: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_dsync_notify_outbound_total",
				Help: "Total outbound DSYNC NOTIFY messages sent",
			},
			[]string{"zone", "result"},
		),
		Webhook: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_dsync_webhook_total",
				Help: "Total DSYNC webhook delivery attempts",
			},
			[]string{"zone", "result"},
		),
	}

	prometheus.MustRegister(m.NotifyInbound)
	prometheus.MustRegister(m.NotifyOutbound)
	prometheus.MustRegister(m.Webhook)

	return m
}
