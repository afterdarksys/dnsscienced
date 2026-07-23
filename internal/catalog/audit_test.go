package catalog

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/logging"
)

func TestLoggingAuditSinkWritesStructuredFields(t *testing.T) {
	var output bytes.Buffer
	sink := NewLoggingAuditSink(logging.NewWithWriter(&output))
	sink.EmitCatalogAudit(AuditEvent{
		Time:    time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC),
		Kind:    AuditReconciliation,
		Catalog: "catalog.example.",
		Serial:  42,
		Members: 7,
		Outcome: "committed",
		Stage:   "reconciliation",
		ActionCounts: map[string]int{
			string(ActionRemove): 2,
			"state_reset":        1,
		},
	})

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode audit JSON: %v\n%s", err, output.String())
	}
	if record["message"] != "catalog audit" ||
		record["event"] != AuditReconciliation ||
		record["catalog"] != "catalog.example." ||
		record["outcome"] != "committed" {
		t.Fatalf("audit record = %#v", record)
	}
	actions, ok := record["action_counts"].(map[string]any)
	if !ok || actions[string(ActionRemove)] != float64(2) || actions["state_reset"] != float64(1) {
		t.Fatalf("action_counts = %#v", record["action_counts"])
	}
}

func TestAuditActionCountsIncludesConflictMigrationAndReset(t *testing.T) {
	counts := auditActionCounts([]Action{
		{Kind: ActionConflict},
		{Kind: ActionTransferOwnership},
		{Kind: ActionTransferOwnership, ResetState: true},
		{Kind: ActionRecreate, ResetState: true},
	})
	if counts[string(ActionConflict)] != 1 ||
		counts[string(ActionTransferOwnership)] != 2 ||
		counts[string(ActionRecreate)] != 1 ||
		counts["state_reset"] != 2 {
		t.Fatalf("action counts = %#v", counts)
	}
}
