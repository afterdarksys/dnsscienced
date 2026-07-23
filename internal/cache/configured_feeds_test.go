package cache

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfiguredFeedProviderAggregatesScoresCategoriesAndSources(t *testing.T) {
	firstPath := writeThreatFeed(t, "shared.example\nfirst.example\n")
	secondPath := writeThreatFeed(t, "shared.example\nsecond.example\n")
	first := ThreatFeedConfig{
		Name:       "operator",
		File:       firstPath,
		Format:     "domains",
		Score:      60,
		Categories: []string{"suspicious", "shared"},
	}
	second := ThreatFeedConfig{
		Name:       "commercial",
		File:       secondPath,
		Format:     "domains",
		Score:      95,
		Categories: []string{"malware", "shared"},
	}

	provider := NewConfiguredFeedProvider(nil)
	defer provider.Stop()
	if err := provider.refreshSource(first); err != nil {
		t.Fatalf("refresh first: %v", err)
	}
	if err := provider.refreshSource(second); err != nil {
		t.Fatalf("refresh second: %v", err)
	}

	result, err := provider.LookupDomain(context.Background(), "child.shared.example.")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if result.Score != 95 {
		t.Fatalf("score = %d, want 95", result.Score)
	}
	if got := strings.Join(result.Categories, ","); got != "malware,shared,suspicious" {
		t.Fatalf("categories = %q", got)
	}
	if got := strings.Join(result.Sources, ","); got != "commercial,operator" {
		t.Fatalf("sources = %q", got)
	}
}

func TestConfiguredFeedProviderRetainsLastGoodSnapshot(t *testing.T) {
	path := writeThreatFeed(t, "blocked.example\n")
	feed := ThreatFeedConfig{
		Name:   "operator",
		File:   path,
		Format: "domains",
		Score:  90,
	}
	provider := NewConfiguredFeedProvider(nil)
	defer provider.Stop()
	if err := provider.refreshSource(feed); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}

	if err := os.WriteFile(path, []byte("not a valid domain !!!\n"), 0o600); err != nil {
		t.Fatalf("corrupt feed: %v", err)
	}
	if err := provider.refreshSource(feed); err == nil {
		t.Fatal("expected malformed refresh to fail")
	}
	result, err := provider.LookupDomain(context.Background(), "blocked.example")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if result.Score != 90 {
		t.Fatalf("last-good score = %d, want 90", result.Score)
	}
}

func TestParseThreatFeedFormatsAndBounds(t *testing.T) {
	feed := ThreatFeedConfig{
		Name:       "mixed",
		Format:     "auto",
		Score:      80,
		Categories: []string{"operator"},
		MaxEntries: 3,
	}
	snapshot, err := parseThreatFeed(strings.NewReader(`
# comment
0.0.0.0 hosts.example
plain.example
https://url.example/path
`), feed)
	if err != nil {
		t.Fatalf("parseThreatFeed: %v", err)
	}
	if len(snapshot.domains) != 3 || len(snapshot.urls) != 1 {
		t.Fatalf("snapshot sizes = domains:%d urls:%d", len(snapshot.domains), len(snapshot.urls))
	}

	feed.MaxEntries = 1
	if _, err := parseThreatFeed(strings.NewReader("one.example\ntwo.example\n"), feed); err == nil {
		t.Fatal("expected max_entries failure")
	}
	feed.MaxEntries = 3
	feed.MaxBytes = 5
	if _, err := parseThreatFeed(strings.NewReader("long.example\n"), feed); err == nil {
		t.Fatal("expected max_bytes failure")
	}

	feed.MaxBytes = 0
	for _, invalid := range []string{"*.wildcard.example\n", "https://user:pass@example.test/path\n"} {
		if _, err := parseThreatFeed(strings.NewReader(invalid), feed); err == nil {
			t.Fatalf("expected unsafe entry %q to fail", strings.TrimSpace(invalid))
		}
	}
}

func TestValidateThreatFeeds(t *testing.T) {
	path := writeThreatFeed(t, "valid.example\n")
	valid := []ThreatFeedConfig{{
		Name:   "operator",
		File:   path,
		Format: "domains",
		Score:  90,
	}}
	if err := ValidateThreatFeeds(valid); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	tests := []ThreatFeedConfig{
		{Name: "missing-source", Score: 90},
		{Name: "both", File: "feed", URL: "https://example.test/feed", Score: 90},
		{Name: "plain-http", URL: "http://example.test/feed", Score: 90},
		{Name: "bad-score", File: "feed", Score: 101},
		{Name: "bad-format", File: "feed", Score: 90, Format: "csv"},
		{Name: "missing-file", File: filepath.Join(t.TempDir(), "missing"), Score: 90},
	}
	for _, feed := range tests {
		t.Run(feed.Name, func(t *testing.T) {
			if err := ValidateThreatFeeds([]ThreatFeedConfig{feed}); err == nil {
				t.Fatal("expected invalid feed config to fail")
			}
		})
	}
}

func TestThreatScorerUsesConfiguredFeedProvenance(t *testing.T) {
	path := writeThreatFeed(t, "blocked.example\n")
	feed := ThreatFeedConfig{Name: "operator", File: path, Format: "domains", Score: 90}
	scorer := NewThreatScorerWithFeeds("", []ThreatFeedConfig{feed})
	defer scorer.Close()
	entry := &Entry{QName: "blocked.example."}
	scorer.EnrichEntry(entry)
	if entry.ThreatScore != 90 || entry.ThreatSource != "operator" {
		t.Fatalf("entry threat metadata = score:%d source:%q", entry.ThreatScore, entry.ThreatSource)
	}
}

func writeThreatFeed(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "threats.txt")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write threat feed: %v", err)
	}
	return path
}
