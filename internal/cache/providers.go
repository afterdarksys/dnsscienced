package cache

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ThreatProvider defines the interface for external threat intelligence sources
type ThreatProvider interface {
	CheckDomain(ctx context.Context, domain string) (int32, []string, error)
	CheckURL(ctx context.Context, queryURL string) (int32, []string, error)
	Name() string
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
	var maxScore int32
	var allCategories []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ap.providers {
		wg.Add(1)
		go func(p ThreatProvider) {
			defer wg.Done()
			score, cats, err := p.CheckDomain(ctx, domain)
			if err != nil {
				// Log error but don't fail the aggregation
				// logging.Logger.Warn("Provider failed", zap.String("provider", p.Name()), zap.Error(err))
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

	// Dedup categories
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

// threatData holds pre-calculated threat metadata for lock-free map reads
type threatData struct {
	Score      int32
	Categories []string
}

// InMemoryFeedProvider asynchronously fetches and stores public OSINT feeds for zero-I/O lock-free lookup.
type InMemoryFeedProvider struct {
	feedUrls    []string
	interval    time.Duration
	name        string
	database    atomic.Value // Holds map[string]threatData
	urlDatabase atomic.Value // Holds map[string]threatData
	stopChan    chan struct{}
}

// NewInMemoryFeedProvider constructs the provider and launches the background sync goroutine
func NewInMemoryFeedProvider(name string, urls []string, interval time.Duration) *InMemoryFeedProvider {
	p := &InMemoryFeedProvider{
		feedUrls: urls,
		interval: interval,
		name:     name,
		stopChan: make(chan struct{}),
	}

	// Initialize empty maps to prevent panic on first load
	p.database.Store(make(map[string]threatData))
	p.urlDatabase.Store(make(map[string]threatData))

	go p.syncLoop()
	return p
}

func (p *InMemoryFeedProvider) Name() string {
	return p.name
}

// Stop halts the background sync loop
func (p *InMemoryFeedProvider) Stop() {
	close(p.stopChan)
}

// CheckDomain evaluates the domain in O(1) time fully in-memory via atomic load.
func (p *InMemoryFeedProvider) CheckDomain(ctx context.Context, domain string) (int32, []string, error) {
	db := p.database.Load().(map[string]threatData)
	if data, ok := db[domain]; ok {
		return data.Score, data.Categories, nil
	}
	return 0, nil, nil
}

// CheckURL evaluates the URL in O(1) time fully in-memory via atomic load.
func (p *InMemoryFeedProvider) CheckURL(ctx context.Context, queryURL string) (int32, []string, error) {
	db := p.urlDatabase.Load().(map[string]threatData)
	if data, ok := db[queryURL]; ok {
		return data.Score, data.Categories, nil
	}
	// Fallback to domain checking if specific URL isn't blocked?
	// For pure URL feeds, we leave it exact.
	return 0, nil, nil
}

func (p *InMemoryFeedProvider) syncLoop() {
	// Initial fetch
	p.fetchFeeds()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.fetchFeeds()
		}
	}
}

func (p *InMemoryFeedProvider) fetchFeeds() {
	// Build completely new maps in isolation
	newDB := make(map[string]threatData)
	newURLDB := make(map[string]threatData)
	client := &http.Client{Timeout: 30 * time.Second}

	for _, u := range p.feedUrls {
		resp, err := client.Get(u)
		if err != nil {
			// In production, log error. For now, quietly loop to prevent blocking
			continue
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Handle Hosts-file format (127.0.0.1 domain) or Raw Domain lists
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			var entry string
			if len(fields) >= 2 && (fields[0] == "127.0.0.1" || fields[0] == "0.0.0.0") {
				entry = fields[1]
			} else {
				entry = fields[0]
			}

			if strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://") {
				newURLDB[entry] = threatData{
					Score:      90,
					Categories: []string{"malware", "osint-feed"},
				}
				if parsed, err := url.Parse(entry); err == nil && parsed.Host != "" {
					domain := strings.ToLower(parsed.Host)
					newDB[domain] = threatData{
						Score:      90,
						Categories: []string{"malware", "osint-feed"},
					}
				}
			} else {
				domain := strings.ToLower(entry)
				newDB[domain] = threatData{
					Score:      90, // High certainty for public OSINT feed hits
					Categories: []string{"malware", "osint-feed"},
				}
			}
		}
		resp.Body.Close()
	}

	// Atomic pointer swap: instantaneous switch to the new dataset for all incoming readers
	p.database.Store(newDB)
	p.urlDatabase.Store(newURLDB)
}
