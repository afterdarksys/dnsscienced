package catalog

import (
	"time"

	"github.com/afterdarksys/dnsscienced/internal/logging"
)

const (
	AuditReceipt        = "catalog_receipt"
	AuditTransfer       = "catalog_transfer"
	AuditRejected       = "catalog_rejected"
	AuditReconciliation = "catalog_reconciliation"
)

// AuditEvent is the stable, structured security record emitted for catalog
// control-plane decisions. ActionCounts contains only fixed ActionKind values
// plus "state_reset", so untrusted catalog data cannot create field names.
type AuditEvent struct {
	Time         time.Time
	Kind         string
	Catalog      string
	Serial       uint32
	Members      int
	Outcome      string
	Stage        string
	ActionCounts map[string]int
	Error        string
}

// AuditSink receives catalog security events. Implementations must be safe for
// concurrent transfer callbacks.
type AuditSink interface {
	EmitCatalogAudit(AuditEvent)
}

// LoggingAuditSink writes catalog events to the configured structured system
// logger.
type LoggingAuditSink struct {
	logger *logging.Logger
}

func NewLoggingAuditSink(logger *logging.Logger) *LoggingAuditSink {
	if logger == nil {
		return nil
	}
	return &LoggingAuditSink{logger: logger}
}

func (s *LoggingAuditSink) EmitCatalogAudit(event AuditEvent) {
	if s == nil || s.logger == nil {
		return
	}
	logEvent := s.logger.Info()
	if event.Outcome == "failure" || event.Outcome == "rejected" {
		logEvent = s.logger.Warn()
	}
	logEvent.
		Time("event_time", event.Time).
		Str("event", event.Kind).
		Str("catalog", event.Catalog).
		Uint32("serial", event.Serial).
		Int("members", event.Members).
		Str("outcome", event.Outcome).
		Str("stage", event.Stage).
		Interface("action_counts", event.ActionCounts).
		Str("error", event.Error).
		Msg("catalog audit")
}
