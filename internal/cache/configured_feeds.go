package cache

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultThreatFeedInterval   = 15 * time.Minute
	defaultThreatFeedTimeout    = 15 * time.Second
	defaultThreatFeedMaxBytes   = int64(32 << 20)
	defaultThreatFeedMaxEntries = 1_000_000
	maxThreatFeedLineBytes      = 1 << 20
	maxThreatFeeds              = 128
	maxThreatFeedBytes          = int64(1 << 30)
	maxThreatFeedEntries        = 10_000_000
)

// ThreatFeedConfig describes one operator-controlled threat source. Exactly
// one of URL or File must be set.
type ThreatFeedConfig struct {
	Name              string            `yaml:"name"`
	URL               string            `yaml:"url,omitempty"`
	File              string            `yaml:"file,omitempty"`
	Format            string            `yaml:"format,omitempty"` // domains, hosts, urls, auto
	Score             int32             `yaml:"score"`
	Categories        []string          `yaml:"categories"`
	RefreshInterval   time.Duration     `yaml:"refresh_interval,omitempty"`
	Timeout           time.Duration     `yaml:"timeout,omitempty"`
	MaxBytes          int64             `yaml:"max_bytes,omitempty"`
	MaxEntries        int               `yaml:"max_entries,omitempty"`
	AuthToken         string            `yaml:"auth_token,omitempty"`
	Headers           map[string]string `yaml:"headers,omitempty"`
	AllowInsecureHTTP bool              `yaml:"allow_insecure_http,omitempty"`
}

// ValidateThreatFeeds rejects ambiguous, unbounded, duplicate, or insecure
// source definitions before workers start.
func ValidateThreatFeeds(feeds []ThreatFeedConfig) error {
	if len(feeds) > maxThreatFeeds {
		return fmt.Errorf("threat_feeds exceeds maximum of %d sources", maxThreatFeeds)
	}
	seen := make(map[string]struct{}, len(feeds))
	for i, feed := range feeds {
		name := strings.TrimSpace(feed.Name)
		if name == "" {
			return fmt.Errorf("threat_feeds[%d].name is required", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate threat feed name %q", name)
		}
		seen[key] = struct{}{}
		feedURL := strings.TrimSpace(feed.URL)
		feedFile := strings.TrimSpace(feed.File)
		if (feedURL == "") == (feedFile == "") {
			return fmt.Errorf("threat feed %q requires exactly one of url or file", name)
		}
		if feedURL != "" {
			parsed, err := url.Parse(feedURL)
			if err != nil || parsed.Host == "" || parsed.User != nil {
				return fmt.Errorf("threat feed %q has invalid URL", name)
			}
			if parsed.Scheme != "https" && !(parsed.Scheme == "http" && feed.AllowInsecureHTTP) {
				return fmt.Errorf("threat feed %q URL must use HTTPS (or explicitly allow insecure HTTP)", name)
			}
		} else {
			info, err := os.Stat(feedFile)
			if err != nil {
				return fmt.Errorf("threat feed %q file: %w", name, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("threat feed %q file must be regular", name)
			}
			maxBytes := feed.MaxBytes
			if maxBytes == 0 {
				maxBytes = defaultThreatFeedMaxBytes
			}
			if info.Size() > maxBytes {
				return fmt.Errorf("threat feed %q file exceeds max_bytes %d", name, maxBytes)
			}
		}
		switch strings.ToLower(strings.TrimSpace(feed.Format)) {
		case "", "auto", "domains", "hosts", "urls":
		default:
			return fmt.Errorf("threat feed %q has unsupported format %q", name, feed.Format)
		}
		if feed.Score < 1 || feed.Score > 100 {
			return fmt.Errorf("threat feed %q score must be between 1 and 100", name)
		}
		if feed.RefreshInterval < 0 || feed.Timeout < 0 || feed.MaxBytes < 0 || feed.MaxEntries < 0 {
			return fmt.Errorf("threat feed %q limits and durations cannot be negative", name)
		}
		if feed.RefreshInterval > 0 && feed.RefreshInterval < time.Second {
			return fmt.Errorf("threat feed %q refresh_interval must be at least 1s", name)
		}
		if feed.Timeout > 10*time.Minute {
			return fmt.Errorf("threat feed %q timeout cannot exceed 10m", name)
		}
		if feed.MaxBytes > maxThreatFeedBytes {
			return fmt.Errorf("threat feed %q max_bytes cannot exceed %d", name, maxThreatFeedBytes)
		}
		if feed.MaxEntries > maxThreatFeedEntries {
			return fmt.Errorf("threat feed %q max_entries cannot exceed %d", name, maxThreatFeedEntries)
		}
		if len(feed.Categories) > 64 || len(feed.Headers) > 64 {
			return fmt.Errorf("threat feed %q categories and headers are limited to 64", name)
		}
	}
	return nil
}

type feedSnapshot struct {
	domains map[string]threatData
	urls    map[string]threatData
}

// ConfiguredFeedProvider maintains independent last-good snapshots for each
// source and publishes an immutable merged view for lock-free query lookups.
type ConfiguredFeedProvider struct {
	feeds      []ThreatFeedConfig
	database   atomic.Value // map[string]threatData
	urlDB      atomic.Value // map[string]threatData
	mu         sync.Mutex
	snapshots  map[string]feedSnapshot
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	stopOnce   sync.Once
	httpClient func(ThreatFeedConfig) *http.Client
}

// NewConfiguredFeedProvider starts one bounded refresh worker per configured
// source. Query lookups never perform file or network I/O.
func NewConfiguredFeedProvider(feeds []ThreatFeedConfig) *ConfiguredFeedProvider {
	ctx, cancel := context.WithCancel(context.Background())
	p := &ConfiguredFeedProvider{
		feeds:     append([]ThreatFeedConfig(nil), feeds...),
		snapshots: make(map[string]feedSnapshot, len(feeds)),
		cancel:    cancel,
		httpClient: func(feed ThreatFeedConfig) *http.Client {
			timeout := feed.Timeout
			if timeout == 0 {
				timeout = defaultThreatFeedTimeout
			}
			return &http.Client{
				Timeout: timeout,
				CheckRedirect: func(req *http.Request, _ []*http.Request) error {
					if req.URL.Scheme != "https" &&
						!(req.URL.Scheme == "http" && feed.AllowInsecureHTTP) {
						return fmt.Errorf("threat feed redirect to insecure HTTP is not allowed")
					}
					return nil
				},
			}
		},
	}
	p.database.Store(make(map[string]threatData))
	p.urlDB.Store(make(map[string]threatData))
	for _, feed := range p.feeds {
		feed := feed
		initialRefresh := true
		if feed.File != "" {
			_ = p.refreshSourceContext(ctx, feed)
			initialRefresh = false
			if feed.RefreshInterval == 0 {
				continue
			}
		}
		p.wg.Add(1)
		go p.runSource(ctx, feed, initialRefresh)
	}
	return p
}

func (p *ConfiguredFeedProvider) Name() string {
	return "configured-feeds"
}

func (p *ConfiguredFeedProvider) Stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		p.wg.Wait()
	})
}

func (p *ConfiguredFeedProvider) CheckDomain(ctx context.Context, domain string) (int32, []string, error) {
	result, err := p.LookupDomain(ctx, domain)
	return result.Score, result.Categories, err
}

func (p *ConfiguredFeedProvider) LookupDomain(_ context.Context, domain string) (ThreatLookup, error) {
	db := p.database.Load().(map[string]threatData)
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	for {
		if data, exists := db[name]; exists {
			return ThreatLookup{
				Score:      data.Score,
				Categories: append([]string(nil), data.Categories...),
				Sources:    append([]string(nil), data.Sources...),
			}, nil
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return ThreatLookup{}, nil
		}
		name = name[dot+1:]
	}
}

func (p *ConfiguredFeedProvider) CheckURL(_ context.Context, queryURL string) (int32, []string, error) {
	db := p.urlDB.Load().(map[string]threatData)
	if data, exists := db[queryURL]; exists {
		return data.Score, append([]string(nil), data.Categories...), nil
	}
	parsed, err := url.Parse(queryURL)
	if err != nil || parsed.Hostname() == "" {
		return 0, nil, nil
	}
	result, err := p.LookupDomain(context.Background(), parsed.Hostname())
	return result.Score, result.Categories, err
}

func (p *ConfiguredFeedProvider) runSource(ctx context.Context, feed ThreatFeedConfig, initialRefresh bool) {
	defer p.wg.Done()
	if initialRefresh {
		p.refreshSourceContext(ctx, feed) // Failure retains the prior (initially empty) snapshot.
	}

	interval := feed.RefreshInterval
	if interval == 0 {
		interval = defaultThreatFeedInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refreshSourceContext(ctx, feed)
		}
	}
}

func (p *ConfiguredFeedProvider) refreshSource(feed ThreatFeedConfig) error {
	return p.refreshSourceContext(context.Background(), feed)
}

func (p *ConfiguredFeedProvider) refreshSourceContext(ctx context.Context, feed ThreatFeedConfig) error {
	reader, closeReader, err := p.openSource(ctx, feed)
	if err != nil {
		return err
	}
	defer closeReader()

	snapshot, err := parseThreatFeed(reader, feed)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.snapshots[strings.ToLower(strings.TrimSpace(feed.Name))] = snapshot
	p.rebuildLocked()
	p.mu.Unlock()
	return nil
}

func (p *ConfiguredFeedProvider) openSource(ctx context.Context, feed ThreatFeedConfig) (io.Reader, func(), error) {
	maxBytes := feed.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultThreatFeedMaxBytes
	}
	if feed.File != "" {
		file, err := os.Open(strings.TrimSpace(feed.File))
		if err != nil {
			return nil, func() {}, fmt.Errorf("open threat feed %q: %w", feed.Name, err)
		}
		return io.LimitReader(file, maxBytes+1), func() { _ = file.Close() }, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(feed.URL), nil)
	if err != nil {
		return nil, func() {}, fmt.Errorf("build threat feed %q request: %w", feed.Name, err)
	}
	if feed.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+feed.AuthToken)
	}
	for key, value := range feed.Headers {
		req.Header.Set(key, value)
	}
	resp, err := p.httpClient(feed).Do(req)
	if err != nil {
		return nil, func() {}, fmt.Errorf("fetch threat feed %q: %w", feed.Name, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, func() {}, fmt.Errorf("fetch threat feed %q: HTTP %d", feed.Name, resp.StatusCode)
	}
	return io.LimitReader(resp.Body, maxBytes+1), func() { _ = resp.Body.Close() }, nil
}

func parseThreatFeed(reader io.Reader, feed ThreatFeedConfig) (feedSnapshot, error) {
	maxBytes := feed.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultThreatFeedMaxBytes
	}
	maxEntries := feed.MaxEntries
	if maxEntries == 0 {
		maxEntries = defaultThreatFeedMaxEntries
	}
	format := strings.ToLower(strings.TrimSpace(feed.Format))
	if format == "" {
		format = "auto"
	}
	categories := sortedUnique(feed.Categories)
	if len(categories) == 0 {
		categories = []string{"threat"}
	}
	source := strings.TrimSpace(feed.Name)
	data := threatData{Score: feed.Score, Categories: categories, Sources: []string{source}}
	snapshot := feedSnapshot{
		domains: make(map[string]threatData),
		urls:    make(map[string]threatData),
	}

	counting := &countingReader{reader: reader}
	scanner := bufio.NewScanner(counting)
	scanner.Buffer(make([]byte, 64*1024), maxThreatFeedLineBytes)
	lineNumber := 0
	entryCount := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		entry, isURL, err := parseThreatFeedLine(line, format)
		if err != nil {
			return feedSnapshot{}, fmt.Errorf("threat feed %q line %d: %w", feed.Name, lineNumber, err)
		}
		if entryCount >= maxEntries {
			return feedSnapshot{}, fmt.Errorf("threat feed %q exceeds max_entries %d", feed.Name, maxEntries)
		}
		entryCount++
		if isURL {
			snapshot.urls[entry] = data
			parsed, _ := url.Parse(entry)
			snapshot.domains[strings.ToLower(parsed.Hostname())] = data
		} else {
			snapshot.domains[entry] = data
		}
	}
	if err := scanner.Err(); err != nil {
		return feedSnapshot{}, fmt.Errorf("read threat feed %q: %w", feed.Name, err)
	}
	if counting.count > maxBytes {
		return feedSnapshot{}, fmt.Errorf("threat feed %q exceeds max_bytes %d", feed.Name, maxBytes)
	}
	return snapshot, nil
}

func parseThreatFeedLine(line, format string) (entry string, isURL bool, err error) {
	fields := strings.Fields(line)
	switch format {
	case "hosts":
		if len(fields) < 2 {
			return "", false, fmt.Errorf("invalid hosts entry")
		}
		entry = fields[1]
	case "domains":
		if len(fields) != 1 {
			return "", false, fmt.Errorf("invalid domain entry")
		}
		entry = fields[0]
	case "urls":
		if len(fields) != 1 {
			return "", false, fmt.Errorf("invalid URL entry")
		}
		entry = fields[0]
	case "auto":
		if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1" || fields[0] == "::") {
			entry = fields[1]
		} else if len(fields) == 1 {
			entry = fields[0]
		} else {
			return "", false, fmt.Errorf("ambiguous entry")
		}
	}
	entry = strings.TrimSpace(entry)
	if strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://") {
		parsed, parseErr := url.Parse(entry)
		if parseErr != nil || parsed.Hostname() == "" || parsed.User != nil {
			return "", false, fmt.Errorf("invalid URL %q", entry)
		}
		return entry, true, nil
	}
	if format == "urls" {
		return "", false, fmt.Errorf("expected URL")
	}
	entry = strings.ToLower(strings.TrimSuffix(entry, "."))
	if _, valid := dns.IsDomainName(entry + "."); !valid || entry == "" || strings.Contains(entry, "*") {
		return "", false, fmt.Errorf("invalid domain %q", entry)
	}
	return entry, false, nil
}

func (p *ConfiguredFeedProvider) rebuildLocked() {
	domains := make(map[string]threatData)
	urls := make(map[string]threatData)
	for _, snapshot := range p.snapshots {
		for domain, data := range snapshot.domains {
			domains[domain] = mergeThreatData(domains[domain], data)
		}
		for queryURL, data := range snapshot.urls {
			urls[queryURL] = mergeThreatData(urls[queryURL], data)
		}
	}
	p.database.Store(domains)
	p.urlDB.Store(urls)
}

func mergeThreatData(current, candidate threatData) threatData {
	if candidate.Score > current.Score {
		current.Score = candidate.Score
	}
	current.Categories = sortedUnique(append(current.Categories, candidate.Categories...))
	current.Sources = sortedUnique(append(current.Sources, candidate.Sources...))
	return current
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.count += int64(n)
	return n, err
}
