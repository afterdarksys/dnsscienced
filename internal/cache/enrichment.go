package cache

import (
	"context"
	_ "embed"
	"strings"
	"time"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ThreatScorer handles threat intelligence enrichment for cache entries
type ThreatScorer struct {
	provider ThreatProvider
}

// NewThreatScorer creates a new ThreatScorer
func NewThreatScorer(darkAPIKey string) *ThreatScorer {
	var providers []ThreatProvider

	if darkAPIKey != "" {
		providers = append(providers, NewDarkAPIProvider(darkAPIKey))
	}

	// Add Async Lock-Free OSINT Aggregator
	osintProvider := NewInMemoryFeedProvider(
		"osint-aggregator",
		[]string{
			"https://urlhaus.abuse.ch/downloads/hostfile/", // Industry standard malware domain sinkhole
		},
		6*time.Hour,
	)
	providers = append(providers, osintProvider)

	var p ThreatProvider
	if len(providers) > 0 {
		p = NewAggregateProvider(providers...)
	}

	return &ThreatScorer{
		provider: p,
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
		score, cats, err := ts.provider.CheckDomain(ctx, domain)
		if err == nil && score > 0 {
			entry.ThreatScore = score
			entry.Categories = cats
			entry.ThreatSource = ts.provider.Name()
			if score > 80 {
				entry.Reputation = "malicious"
			} else if score > 50 {
				entry.Reputation = "suspicious"
			}
			return
		}
	}

	// Fallback to mock logic (keep existing behavior for testing/demo)
	if isMalicious(domain) {
		entry.ThreatScore = 100
		entry.Reputation = "malicious"
		entry.Categories = []string{"malware", "phishing"}
	} else if isSuspicious(domain) {
		entry.ThreatScore = 50
		entry.Reputation = "suspicious"
		entry.Categories = []string{"newly_registered"}
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

		score, cats, err := ts.provider.CheckDomain(ctx, domain)
		if err == nil && score > 0 {
			entry.ThreatScore = score
			entry.Categories = cats
			entry.ThreatSource = ts.provider.Name()
			if score > 80 {
				entry.Reputation = "malicious"
			} else if score > 50 {
				entry.Reputation = "suspicious"
			}
			return
		}
	}

	// Fallback to mock logic
	if isMalicious(domain) {
		entry.ThreatScore = 100
		entry.Reputation = "malicious"
		entry.Categories = []string{"malware", "phishing"}
	} else if isSuspicious(domain) {
		entry.ThreatScore = 50
		entry.Reputation = "suspicious"
		entry.Categories = []string{"newly_registered"}
	}
}

// Authorization logic/mock data
// TODO: Replace with real threat feeds
func isMalicious(domain string) bool {
	malicious := []string{
		"example-malware.com",
		"bad-site.org",
		"phishing-attempt.net",
		"test-threat.com",
	}
	for _, m := range malicious {
		if domain == m || strings.HasSuffix(domain, "."+m) {
			return true
		}
	}
	return false
}

func isSuspicious(domain string) bool {
	// Example heuristic: really long random-looking subdomains?
	// For now just explicit list
	suspicious := []string{
		"suspicious-domain.xyz",
		"crypto-miner-test.io",
	}
	for _, s := range suspicious {
		if domain == s || strings.HasSuffix(domain, "."+s) {
			return true
		}
	}
	return false
}
