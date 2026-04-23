package firewalld

import (
	"testing"
	"time"
)

// TestThreatIntelConfig_FeedFields verifies that ThreatIntelConfig has all six
// feed configuration fields and that DefaultConfig() sets the correct defaults.
func TestThreatIntelConfig_FeedFields(t *testing.T) {
	cfg := DefaultConfig()
	ti := cfg.ThreatIntel

	// FeedURL defaults to empty string.
	if ti.FeedURL != "" {
		t.Errorf("FeedURL: got %q, want empty string", ti.FeedURL)
	}

	// PollInterval defaults to 5 minutes.
	if ti.PollInterval != 5*time.Minute {
		t.Errorf("PollInterval: got %v, want 5m", ti.PollInterval)
	}

	// Timeout defaults to 30 seconds.
	if ti.Timeout != 30*time.Second {
		t.Errorf("Timeout: got %v, want 30s", ti.Timeout)
	}

	// TLSSkipVerify defaults to false.
	if ti.TLSSkipVerify {
		t.Errorf("TLSSkipVerify: got true, want false")
	}

	// AuthToken defaults to empty string.
	if ti.AuthToken != "" {
		t.Errorf("AuthToken: got %q, want empty string", ti.AuthToken)
	}

	// Headers defaults to nil.
	if ti.Headers != nil {
		t.Errorf("Headers: got %v, want nil", ti.Headers)
	}
}
