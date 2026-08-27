package cache

import (
	"context"
	"testing"

	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
)

func TestEnrichEntry(t *testing.T) {
	scorer := NewThreatScorer("")

	entry := &Entry{QName: "unlisted.example"}
	scorer.EnrichEntry(entry)
	if entry.ThreatScore != 0 || entry.Reputation != "benign" {
		t.Fatalf("unconfigured scorer metadata = score:%d reputation:%q", entry.ThreatScore, entry.Reputation)
	}
	if entry.FirstSeen.IsZero() {
		t.Error("EnrichEntry() FirstSeen should not be zero")
	}
}

func TestEnrich(t *testing.T) {
	scorer := NewThreatScorer("")

	entry := &pb.CacheEntry{
		Name: "unlisted.example",
	}

	scorer.Enrich(context.Background(), entry)

	if entry.ThreatScore != 0 || entry.Reputation != "benign" {
		t.Errorf("Enrich() metadata = score:%d reputation:%q", entry.ThreatScore, entry.Reputation)
	}
}
