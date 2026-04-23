package firewalld

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFeedConfig verifies ThreatIntelConfig fields are readable and DefaultConfig returns
// correct poll interval and timeout defaults (FEED-01 config coverage).
func TestFeedConfig(t *testing.T) {
	cfg := ThreatIntelConfig{
		FeedURL:      "https://example.com",
		PollInterval: 5 * time.Minute,
		Timeout:      30 * time.Second,
		TLSSkipVerify: false,
		AuthToken:    "secret",
		Headers:      map[string]string{"X-Tenant": "acme"},
	}

	assert.Equal(t, "https://example.com", cfg.FeedURL)
	assert.Equal(t, 5*time.Minute, cfg.PollInterval)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.False(t, cfg.TLSSkipVerify)
	assert.Equal(t, "secret", cfg.AuthToken)
	assert.Equal(t, "acme", cfg.Headers["X-Tenant"])

	defaults := DefaultConfig()
	assert.Equal(t, 5*time.Minute, defaults.ThreatIntel.PollInterval)
	assert.Equal(t, 30*time.Second, defaults.ThreatIntel.Timeout)
}

// TestParseFeed_ValidEntries verifies that parseFeed correctly classifies domains, plain IPs,
// and CIDR entries, and collects warnings for malformed lines (FEED-02 coverage).
func TestParseFeed_ValidEntries(t *testing.T) {
	input := "example.com 75\n1.2.3.0/24 60\n1.2.3.4 80\n# comment\n\nbadline\n"
	entries, warnings := parseFeed(strings.NewReader(input))

	require.Len(t, entries, 3, "expected 3 valid entries")
	require.Len(t, warnings, 1, "expected 1 warning for badline")

	// Find and verify each entry
	var domainEntry, cidrEntry, ipEntry feedEntry
	for _, e := range entries {
		switch e.key {
		case "example.com":
			domainEntry = e
		case "1.2.3.0/24":
			cidrEntry = e
		case "1.2.3.4":
			ipEntry = e
		}
	}

	assert.False(t, domainEntry.isIP, "example.com should be a domain entry")
	assert.Equal(t, "example.com", domainEntry.key)
	assert.Equal(t, 75, domainEntry.score)

	assert.True(t, cidrEntry.isIP, "1.2.3.0/24 should be an IP entry")
	assert.Equal(t, "1.2.3.0/24", cidrEntry.key)
	assert.Equal(t, 60, cidrEntry.score)

	assert.True(t, ipEntry.isIP, "1.2.3.4 should be an IP entry")
	assert.Equal(t, "1.2.3.4", ipEntry.key)
	assert.Equal(t, 80, ipEntry.score)
}

// TestParseFeed_ScoreClamping verifies that scores are clamped to [0, 100] (FEED-02 coverage).
func TestParseFeed_ScoreClamping(t *testing.T) {
	input := "evil.com 150\ngood.com -10\n"
	entries, warnings := parseFeed(strings.NewReader(input))

	require.Len(t, entries, 2)
	assert.Empty(t, warnings)

	var evilScore, goodScore int
	for _, e := range entries {
		switch e.key {
		case "evil.com":
			evilScore = e.score
		case "good.com":
			goodScore = e.score
		}
	}
	assert.Equal(t, 100, evilScore, "score 150 should be clamped to 100")
	assert.Equal(t, 0, goodScore, "score -10 should be clamped to 0")
}

// TestFeedClient_Apply_FullReplace verifies full-replace semantics (D-05, FEED-03):
// entries from the previous cycle that are absent from the new feed are removed.
func TestFeedClient_Apply_FullReplace(t *testing.T) {
	// Mutable response protected by mutex so we can swap between cycles.
	var mu sync.Mutex
	response := "victim.com 80\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body := response
		mu.Unlock()
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	cfg := ThreatIntelConfig{
		FeedURL:      srv.URL,
		PollInterval: time.Hour, // not used in this test
		Timeout:      5 * time.Second,
	}
	engine := newThreatIntel(cfg)
	fc := newFeedClient(cfg, engine)

	// Cycle 1: serve "victim.com 80"
	fc.fetchAndApply()

	engine.dynMu.RLock()
	score, ok := engine.dynDomains["victim.com"]
	engine.dynMu.RUnlock()
	require.True(t, ok, "victim.com should be present after cycle 1")
	assert.Equal(t, 80, score)

	// Swap response — victim.com no longer in feed
	mu.Lock()
	response = "newdomain.com 50\n"
	mu.Unlock()

	// Cycle 2: full-replace should remove victim.com and inject newdomain.com
	fc.fetchAndApply()

	engine.dynMu.RLock()
	_, victimPresent := engine.dynDomains["victim.com"]
	newScore, newOk := engine.dynDomains["newdomain.com"]
	engine.dynMu.RUnlock()

	assert.False(t, victimPresent, "victim.com should be removed after cycle 2 (full-replace)")
	require.True(t, newOk, "newdomain.com should be present after cycle 2")
	assert.Equal(t, 50, newScore)
}

// TestFeedClient_ErrorHandling verifies that a 500 response does not wipe previous scores (D-14, FEED-04).
func TestFeedClient_ErrorHandling(t *testing.T) {
	var mu sync.Mutex
	returnError := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fail := returnError
		mu.Unlock()
		if fail {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "example.com 75\n")
	}))
	defer srv.Close()

	cfg := ThreatIntelConfig{
		FeedURL:      srv.URL,
		PollInterval: time.Hour,
		Timeout:      5 * time.Second,
	}
	engine := newThreatIntel(cfg)
	fc := newFeedClient(cfg, engine)

	// Successful first fetch
	fc.fetchAndApply()

	engine.dynMu.RLock()
	score, ok := engine.dynDomains["example.com"]
	engine.dynMu.RUnlock()
	require.True(t, ok, "example.com should be present after successful fetch")
	assert.Equal(t, 75, score)

	// Now cause the server to return 500
	mu.Lock()
	returnError = true
	mu.Unlock()

	// Failed fetch — previous scores must be retained
	fc.fetchAndApply()

	engine.dynMu.RLock()
	score, ok = engine.dynDomains["example.com"]
	engine.dynMu.RUnlock()
	require.True(t, ok, "example.com must still be present after failed fetch (D-14)")
	assert.Equal(t, 75, score, "score must remain 75 after HTTP 500")
}

// TestFeedClient_Lifecycle verifies that the feed goroutine exits within 500ms of context
// cancellation (D-02, D-09 clean shutdown).
func TestFeedClient_Lifecycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "lifecycle.com 50\n")
	}))
	defer srv.Close()

	cfg := ThreatIntelConfig{
		FeedURL:      srv.URL,
		PollInterval: 10 * time.Millisecond,
		Timeout:      5 * time.Second,
	}
	engine := newThreatIntel(cfg)
	fc := newFeedClient(cfg, engine)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		fc.run(ctx)
	}()

	// Let it tick a few times
	time.Sleep(50 * time.Millisecond)

	// Cancel and verify exit within 500ms
	cancel()
	select {
	case <-done:
		// goroutine exited cleanly
	case <-time.After(500 * time.Millisecond):
		t.Fatal("feed goroutine did not exit within 500ms of context cancellation")
	}
}
