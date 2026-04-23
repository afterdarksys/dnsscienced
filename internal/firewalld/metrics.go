package firewalld

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus counters for the DNS firewall.
type Metrics struct {
	queriesTotal    prometheus.Counter
	queriesAllowed  prometheus.Counter
	queriesBlocked  *prometheus.CounterVec
	junkDetected    *prometheus.CounterVec
	threatScoreHist prometheus.Histogram
	starlarkRuns    *prometheus.CounterVec
}

var (
	metricsOnce sync.Once
	sharedMetrics *Metrics
)

// newMetrics returns the package-level singleton Metrics, registering
// Prometheus collectors exactly once regardless of how many Firewall
// instances are created (important in tests).
func newMetrics() *Metrics {
	metricsOnce.Do(func() {
		sharedMetrics = &Metrics{
			queriesTotal: prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: "dnsscienced",
				Subsystem: "firewalld",
				Name:      "queries_total",
				Help:      "Total DNS queries evaluated by the firewall.",
			}),
			queriesAllowed: prometheus.NewCounter(prometheus.CounterOpts{
				Namespace: "dnsscienced",
				Subsystem: "firewalld",
				Name:      "queries_allowed_total",
				Help:      "DNS queries allowed by the firewall.",
			}),
			queriesBlocked: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "dnsscienced",
				Subsystem: "firewalld",
				Name:      "queries_blocked_total",
				Help:      "DNS queries blocked by the firewall.",
			}, []string{"verdict", "rule"}),
			junkDetected: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "dnsscienced",
				Subsystem: "firewalld",
				Name:      "junk_detected_total",
				Help:      "Junk queries detected by type (dga, data_exfil, random_subdomain).",
			}, []string{"type"}),
			threatScoreHist: prometheus.NewHistogram(prometheus.HistogramOpts{
				Namespace: "dnsscienced",
				Subsystem: "firewalld",
				Name:      "threat_score",
				Help:      "Distribution of computed threat scores (0-100).",
				Buckets:   []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
			}),
			starlarkRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "dnsscienced",
				Subsystem: "firewalld",
				Name:      "starlark_runs_total",
				Help:      "Starlark policy script executions by outcome.",
			}, []string{"script", "outcome"}),
		}
		// Best-effort registration — ignore errors so tests that create
		// multiple registries don't panic.
		_ = prometheus.Register(sharedMetrics.queriesTotal)
		_ = prometheus.Register(sharedMetrics.queriesAllowed)
		_ = prometheus.Register(sharedMetrics.queriesBlocked)
		_ = prometheus.Register(sharedMetrics.junkDetected)
		_ = prometheus.Register(sharedMetrics.threatScoreHist)
		_ = prometheus.Register(sharedMetrics.starlarkRuns)
	})
	return sharedMetrics
}
