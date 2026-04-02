package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for DNSScienced
type Metrics struct {
	// Query counters
	QueriesTotal    *prometheus.CounterVec
	AnswersTotal    *prometheus.CounterVec
	ErrorsTotal     *prometheus.CounterVec
	NXDomainTotal   *prometheus.CounterVec

	// Cache metrics
	CacheHits       prometheus.Counter
	CacheMisses     prometheus.Counter
	CacheSize       prometheus.Gauge
	CacheMemoryBytes prometheus.Gauge

	// RRL metrics
	RRLDropped      *prometheus.CounterVec
	RRLSlipped      *prometheus.CounterVec

	// Query latency
	QueryDuration   *prometheus.HistogramVec

	// Zone metrics
	ZoneCount       prometheus.Gauge
	ZoneLoadDuration *prometheus.HistogramVec

	// Upstream metrics
	UpstreamFailures *prometheus.CounterVec
	UpstreamDuration *prometheus.HistogramVec

	// System metrics
	GoroutineCount  prometheus.Gauge
	GoVersion       *prometheus.GaugeVec

	// Connection metrics
	ActiveConnections *prometheus.GaugeVec
	ConnectionsTotal  *prometheus.CounterVec
}

// New creates a new Metrics instance and registers all metrics
func New() *Metrics {
	m := &Metrics{
		QueriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_queries_total",
				Help: "Total number of DNS queries received",
			},
			[]string{"type", "protocol"}, // type=recursive|authoritative, protocol=udp|tcp
		),

		AnswersTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_answers_total",
				Help: "Total number of DNS answers sent",
			},
			[]string{"rcode"}, // rcode=NOERROR|NXDOMAIN|SERVFAIL|etc
		),

		ErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_errors_total",
				Help: "Total number of DNS errors",
			},
			[]string{"type"}, // type=parse|resolve|zone|etc
		),

		NXDomainTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_nxdomain_total",
				Help: "Total number of NXDOMAIN responses",
			},
			[]string{"zone"},
		),

		CacheHits: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "dnsscienced_cache_hits_total",
				Help: "Total number of cache hits",
			},
		),

		CacheMisses: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "dnsscienced_cache_misses_total",
				Help: "Total number of cache misses",
			},
		),

		CacheSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "dnsscienced_cache_entries",
				Help: "Current number of entries in cache",
			},
		),

		CacheMemoryBytes: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "dnsscienced_cache_memory_bytes",
				Help: "Current memory usage of cache in bytes",
			},
		),

		RRLDropped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_rrl_dropped_total",
				Help: "Total number of queries dropped by RRL",
			},
			[]string{"reason"}, // reason=rate_limit|error|nxdomain
		),

		RRLSlipped: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_rrl_slipped_total",
				Help: "Total number of queries slipped by RRL (TC bit set)",
			},
			[]string{"reason"},
		),

		QueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "dnsscienced_query_duration_seconds",
				Help:    "DNS query latency in seconds",
				Buckets: []float64{.0001, .0005, .001, .005, .01, .05, .1, .5, 1, 5}, // 100µs to 5s
			},
			[]string{"type"}, // type=cached|recursive|authoritative
		),

		ZoneCount: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "dnsscienced_zones_total",
				Help: "Current number of loaded zones",
			},
		),

		ZoneLoadDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "dnsscienced_zone_load_duration_seconds",
				Help:    "Zone loading duration in seconds",
				Buckets: []float64{.001, .01, .1, 1, 10}, // 1ms to 10s
			},
			[]string{"format"}, // format=text|compiled
		),

		UpstreamFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_upstream_failures_total",
				Help: "Total number of upstream resolver failures",
			},
			[]string{"server"},
		),

		UpstreamDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "dnsscienced_upstream_duration_seconds",
				Help:    "Upstream query latency in seconds",
				Buckets: []float64{.001, .01, .05, .1, .5, 1, 5}, // 1ms to 5s
			},
			[]string{"server"},
		),

		GoroutineCount: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "dnsscienced_goroutines",
				Help: "Current number of goroutines",
			},
		),

		GoVersion: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "dnsscienced_build_info",
				Help: "DNSScienced build information",
			},
			[]string{"version", "go_version"},
		),

		ActiveConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "dnsscienced_active_connections",
				Help: "Current number of active connections",
			},
			[]string{"protocol"}, // protocol=udp|tcp
		),

		ConnectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dnsscienced_connections_total",
				Help: "Total number of connections",
			},
			[]string{"protocol"},
		),
	}

	// Register all metrics
	prometheus.MustRegister(m.QueriesTotal)
	prometheus.MustRegister(m.AnswersTotal)
	prometheus.MustRegister(m.ErrorsTotal)
	prometheus.MustRegister(m.NXDomainTotal)
	prometheus.MustRegister(m.CacheHits)
	prometheus.MustRegister(m.CacheMisses)
	prometheus.MustRegister(m.CacheSize)
	prometheus.MustRegister(m.CacheMemoryBytes)
	prometheus.MustRegister(m.RRLDropped)
	prometheus.MustRegister(m.RRLSlipped)
	prometheus.MustRegister(m.QueryDuration)
	prometheus.MustRegister(m.ZoneCount)
	prometheus.MustRegister(m.ZoneLoadDuration)
	prometheus.MustRegister(m.UpstreamFailures)
	prometheus.MustRegister(m.UpstreamDuration)
	prometheus.MustRegister(m.GoroutineCount)
	prometheus.MustRegister(m.GoVersion)
	prometheus.MustRegister(m.ActiveConnections)
	prometheus.MustRegister(m.ConnectionsTotal)

	return m
}

// ServeHTTP starts the Prometheus metrics HTTP server
func ServeHTTP(addr string) error {
	http.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(addr, nil)
}

// RecordQueryDuration records a query duration
func (m *Metrics) RecordQueryDuration(queryType string, duration time.Duration) {
	m.QueryDuration.WithLabelValues(queryType).Observe(duration.Seconds())
}

// RecordCacheHit records a cache hit
func (m *Metrics) RecordCacheHit() {
	m.CacheHits.Inc()
}

// RecordCacheMiss records a cache miss
func (m *Metrics) RecordCacheMiss() {
	m.CacheMisses.Inc()
}

// UpdateCacheSize updates the current cache size
func (m *Metrics) UpdateCacheSize(size int) {
	m.CacheSize.Set(float64(size))
}

// UpdateCacheMemory updates the current cache memory usage
func (m *Metrics) UpdateCacheMemory(bytes int64) {
	m.CacheMemoryBytes.Set(float64(bytes))
}

// CacheHitRate returns the cache hit rate (0.0 to 1.0)
// Note: This is a placeholder - in production you'd query Prometheus directly
// or use the cache.GetStats() method which tracks hits/misses atomically
func (m *Metrics) CacheHitRate() float64 {
	// Placeholder implementation
	// In production: query prometheus or use atomic counters from cache
	return 0.0
}
