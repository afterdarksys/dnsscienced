package catalog

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	catalogReconcilesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dnsscienced_catalog_reconciles_total",
			Help: "Catalog reconciliation attempts by outcome.",
		},
		[]string{"catalog", "outcome"},
	)
	catalogReconcileActionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dnsscienced_catalog_reconcile_actions_total",
			Help: "Catalog reconciliation actions committed by action type.",
		},
		[]string{"catalog", "action"},
	)
	catalogReconcileDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dnsscienced_catalog_reconcile_duration_seconds",
			Help:    "Catalog reconciliation latency by outcome.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
		},
		[]string{"catalog", "outcome"},
	)
	catalogSerial = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dnsscienced_catalog_serial",
			Help: "Last accepted RFC 1982 serial for a configured catalog.",
		},
		[]string{"catalog"},
	)
	catalogMembers = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dnsscienced_catalog_members",
			Help: "Members in the last accepted catalog snapshot.",
		},
		[]string{"catalog"},
	)
	catalogLastSuccessTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dnsscienced_catalog_last_success_timestamp_seconds",
			Help: "Unix timestamp of the last successful catalog reconciliation.",
		},
		[]string{"catalog"},
	)
	catalogTransfersTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dnsscienced_catalog_transfers_total",
			Help: "Catalog-zone AXFR/IXFR attempts by outcome.",
		},
		[]string{"catalog", "outcome"},
	)
)
