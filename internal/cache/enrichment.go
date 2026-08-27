package cache

import (
	"context"
	_ "embed"
	"strings"
	"time"

	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ThreatScorer handles threat intelligence enrichment for cache entries
type ThreatScorer struct {
	provider ThreatProvider
}

// NewThreatScorer creates a new ThreatScorer
func NewThreatScorer(darkAPIKey string) *ThreatScorer {
	return NewThreatScorerWithFeeds(darkAPIKey, nil)
}

// NewThreatScorerWithFeeds creates a scorer backed only by explicitly
// configured remote or operator-local feeds.
func NewThreatScorerWithFeeds(darkAPIKey string, feeds []ThreatFeedConfig) *ThreatScorer {
	var providers []ThreatProvider

	if darkAPIKey != "" {
		providers = append(providers, NewDarkAPIProvider(darkAPIKey))
	}

	if len(feeds) > 0 {
		providers = append(providers, NewConfiguredFeedProvider(feeds))
	}

	var p ThreatProvider
	switch len(providers) {
	case 0:
		// Leave the provider nil so unconfigured deployments do no extra work.
	case 1:
		// Avoid an aggregator goroutine and mutex on the cache insertion hot path.
		p = providers[0]
	default:
		p = NewAggregateProvider(providers...)
	}

	return &ThreatScorer{
		provider: p,
	}
}

// Close stops configured provider refresh workers.
func (ts *ThreatScorer) Close() {
	if closer, ok := ts.provider.(interface{ Stop() }); ok {
		closer.Stop()
	}
}

// CheckURL delegates url-specific lookups to the underlying threat provider.
func (ts *ThreatScorer) CheckURL(ctx context.Context, u string) (int32, []string, error) {
	if ts.provider != nil {
		return ts.provider.CheckURL(ctx, u)
	}
	return 0, nil, nil
}

// Enrich calculates threat metadata for a given domain/IP and updates the CacheEntry
func (ts *ThreatScorer) Enrich(ctx context.Context, entry *pb.CacheEntry) {
	if entry == nil {
		return
	}

	// Default to benign
	entry.ThreatScore = 0
	entry.Reputation = "benign"
	entry.ThreatSource = "dnsscienced-internal"
	entry.FirstSeen = timestamppb.Now()
	entry.LastSeen = timestamppb.Now()

	domain := strings.ToLower(entry.Name)
	domain = strings.TrimSuffix(domain, ".")

	// Use Provider if available
	if ts.provider != nil {
		score, cats, source, err := ts.lookupDomain(ctx, domain)
		if err == nil && score > 0 {
			entry.ThreatScore = score
			entry.Categories = cats
			entry.ThreatSource = source
			if score > 80 {
				entry.Reputation = "malicious"
			} else if score > 50 {
				entry.Reputation = "suspicious"
			}
			return
		}
	}

}

// EnrichEntry calculates threat metadata for the internal cache Entry
func (ts *ThreatScorer) EnrichEntry(entry *Entry) {
	if entry == nil {
		return
	}

	// Default to benign
	entry.ThreatScore = 0
	entry.Reputation = "benign"
	entry.ThreatSource = "dnsscienced-internal"
	entry.FirstSeen = time.Now()
	entry.LastSeen = time.Now()

	domain := strings.ToLower(entry.QName)
	domain = strings.TrimSuffix(domain, ".")

	// Use Provider if available
	// Note: EnrichEntry is often called in hot path (Set), so we rely on fast timeout in provider
	if ts.provider != nil {
		// Use background context with timeout for enrichment?
		// Or assume caller context is not available here.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		score, cats, source, err := ts.lookupDomain(ctx, domain)
		if err == nil && score > 0 {
			entry.ThreatScore = score
			entry.Categories = cats
			entry.ThreatSource = source
			if score > 80 {
				entry.Reputation = "malicious"
			} else if score > 50 {
				entry.Reputation = "suspicious"
			}
			return
		}
	}

}

func (ts *ThreatScorer) lookupDomain(ctx context.Context, domain string) (int32, []string, string, error) {
	if detailed, ok := ts.provider.(detailedThreatProvider); ok {
		result, err := detailed.LookupDomain(ctx, domain)
		return result.Score, result.Categories, strings.Join(result.Sources, ","), err
	}
	score, categories, err := ts.provider.CheckDomain(ctx, domain)
	return score, categories, ts.provider.Name(), err
}
