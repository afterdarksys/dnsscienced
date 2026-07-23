package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ThreatProvider defines the interface for external threat intelligence sources
type ThreatProvider interface {
	CheckDomain(ctx context.Context, domain string) (int32, []string, error)
	CheckURL(ctx context.Context, queryURL string) (int32, []string, error)
	Name() string
}

// ThreatLookup preserves provider provenance for an aggregated decision.
type ThreatLookup struct {
	Score      int32
	Categories []string
	Sources    []string
}

type detailedThreatProvider interface {
	LookupDomain(ctx context.Context, domain string) (ThreatLookup, error)
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// DarkAPIProvider implements ThreatProvider for darkapi.io
type DarkAPIProvider struct {
	apiKey     string
	httpClient *http.Client
}

// NewDarkAPIProvider creates a new DarkAPI provider
func NewDarkAPIProvider(apiKey string) *DarkAPIProvider {
	return &DarkAPIProvider{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 2 * time.Second, // Fast timeout for real-time checks
		},
	}
}

func (p *DarkAPIProvider) Name() string {
	return "darkapi.io"
}

// CheckDomain queries darkapi.io for domain reputation
func (p *DarkAPIProvider) CheckDomain(ctx context.Context, domain string) (int32, []string, error) {
	if p.apiKey == "" {
		return 0, nil, nil
	}

	// Mocking the URL structure as per typical API standards since strict docs aren't provided
	// Assuming GET https://darkapi.io/api/v1/reputation?query=domain
	u := fmt.Sprintf("https://darkapi.io/api/v1/reputation?query=%s", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, nil, nil // Not found = benign usually
	}

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("provider %s failed with status %d", p.Name(), resp.StatusCode)
	}

	var result struct {
		RiskScore  int      `json:"risk_score"` // 0-100
		Categories []string `json:"categories"`
		Verdict    string   `json:"verdict"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, nil, err
	}

	return int32(result.RiskScore), result.Categories, nil
}

// CheckURL queries darkapi.io for URL reputation (not supported yet, returning 0)
func (p *DarkAPIProvider) CheckURL(ctx context.Context, queryURL string) (int32, []string, error) {
	return 0, nil, nil
}

// AggregateProvider combines multiple providers
type AggregateProvider struct {
	providers []ThreatProvider
}

// NewAggregateProvider creates a new aggregator
func NewAggregateProvider(providers ...ThreatProvider) *AggregateProvider {
	return &AggregateProvider{
		providers: providers,
	}
}

// CheckDomain queries all providers and returns the highest score
// Concurrent execution with "fail open" policy
func (ap *AggregateProvider) CheckDomain(ctx context.Context, domain string) (int32, []string, error) {
	result, err := ap.LookupDomain(ctx, domain)
	return result.Score, result.Categories, err
}

// LookupDomain queries all providers, selects the highest score, and preserves
// sorted category/source provenance from every successful positive match.
func (ap *AggregateProvider) LookupDomain(ctx context.Context, domain string) (ThreatLookup, error) {
	var maxScore int32
	var allCategories []string
	var allSources []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ap.providers {
		wg.Add(1)
		go func(p ThreatProvider) {
			defer wg.Done()
			var lookup ThreatLookup
			var err error
			if detailed, ok := p.(detailedThreatProvider); ok {
				lookup, err = detailed.LookupDomain(ctx, domain)
			} else {
				lookup.Score, lookup.Categories, err = p.CheckDomain(ctx, domain)
				if lookup.Score > 0 {
					lookup.Sources = []string{p.Name()}
				}
			}
			if err != nil {
				// Log error but don't fail the aggregation
				// logging.Logger.Warn("Provider failed", zap.String("provider", p.Name()), zap.Error(err))
				return
			}

			mu.Lock()
			if lookup.Score > maxScore {
				maxScore = lookup.Score
			}
			allCategories = append(allCategories, lookup.Categories...)
			allSources = append(allSources, lookup.Sources...)
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	// Dedup categories
	return ThreatLookup{
		Score:      maxScore,
		Categories: sortedUnique(allCategories),
		Sources:    sortedUnique(allSources),
	}, nil
}

// CheckURL queries all providers and returns the highest score for a URL
func (ap *AggregateProvider) CheckURL(ctx context.Context, queryURL string) (int32, []string, error) {
	var maxScore int32
	var allCategories []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ap.providers {
		wg.Add(1)
		go func(p ThreatProvider) {
			defer wg.Done()
			score, cats, err := p.CheckURL(ctx, queryURL)
			if err != nil {
				return
			}

			mu.Lock()
			if score > maxScore {
				maxScore = score
			}
			allCategories = append(allCategories, cats...)
			mu.Unlock()
		}(p)
	}

	wg.Wait()

	uniqueCats := make(map[string]struct{})
	var finalCats []string
	for _, c := range allCategories {
		if _, ok := uniqueCats[c]; !ok {
			uniqueCats[c] = struct{}{}
			finalCats = append(finalCats, c)
		}
	}

	return maxScore, finalCats, nil
}

func (ap *AggregateProvider) Name() string {
	return "aggregate"
}

// Stop halts refresh workers owned by child providers.
func (ap *AggregateProvider) Stop() {
	for _, provider := range ap.providers {
		if stopper, ok := provider.(interface{ Stop() }); ok {
			stopper.Stop()
		}
	}
}

// threatData holds pre-calculated threat metadata for lock-free map reads.
type threatData struct {
	Score      int32
	Categories []string
	Sources    []string
}
