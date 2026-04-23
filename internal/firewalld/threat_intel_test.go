package firewalld

import (
	"net"
	"testing"
)

// TestThreatIntel_RemoveIPScore verifies that RemoveIPScore deletes the IP
// from the dynamic IP score map under the dynMu write lock.
func TestThreatIntel_RemoveIPScore(t *testing.T) {
	ti := newThreatIntel(ThreatIntelConfig{})

	ip := net.ParseIP("1.2.3.4").String()

	// Inject a score.
	ti.AddIPScore(ip, 75)

	// Verify the score is visible in Score().
	qctx := &QueryContext{ClientIP: net.ParseIP("1.2.3.4")}
	before := ti.Score(qctx)
	if before == 0 {
		t.Fatal("AddIPScore: expected non-zero score, got 0")
	}

	// Remove the score.
	ti.RemoveIPScore(ip)

	// Score should now be 0 (no static entries, no zone scores).
	after := ti.Score(qctx)
	if after != 0 {
		t.Errorf("RemoveIPScore: score after removal = %d, want 0", after)
	}
}
