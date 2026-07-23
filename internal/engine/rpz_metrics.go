package engine

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var rpzHits = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "dnsscienced",
		Subsystem: "rpz",
		Name:      "hits_total",
		Help:      "Number of RPZ policy matches by zone, action, and source.",
	},
	[]string{"zone", "action", "source"},
)

func recordRPZHit(rule *RPZRule) {
	rpzHits.WithLabelValues(rule.Zone, rule.Action.String(), rule.Source).Inc()
}
