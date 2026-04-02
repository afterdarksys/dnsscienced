package protective

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// BlocklistEntry represents a blocked domain with metadata
type BlocklistEntry struct {
	Domain    string    // Fully qualified domain name
	Category  string    // Threat category (malware, phishing, c2, etc.)
	Source    string    // Source feed/file
	AddedAt   time.Time // When added to blocklist
	ExpiresAt time.Time // When entry expires (0 = never)
}

// Blocklist manages blocked domains with fast lookups
type Blocklist struct {
	mu sync.RWMutex

	// Domain -> Entry mapping
	entries map[string]*BlocklistEntry

	// Category -> Domains mapping (for category-specific queries)
	categories map[string]map[string]bool

	// Source -> Domains mapping (for feed management)
	sources map[string]map[string]bool

	// Allowlist (domains to never block)
	allowlist map[string]bool

	// Statistics
	totalEntries int64
	lastUpdate   time.Time
}

// NewBlocklist creates a new blocklist
func NewBlocklist() *Blocklist {
	return &Blocklist{
		entries:    make(map[string]*BlocklistEntry),
		categories: make(map[string]map[string]bool),
		sources:    make(map[string]map[string]bool),
		allowlist:  make(map[string]bool),
	}
}

// Add adds a domain to the blocklist
func (b *Blocklist) Add(domain, category, source string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Normalize domain (lowercase, fully qualified)
	domain = normalizeDomain(domain)

	// Check allowlist
	if b.allowlist[domain] {
		return
	}

	// Add entry
	entry := &BlocklistEntry{
		Domain:   domain,
		Category: category,
		Source:   source,
		AddedAt:  time.Now(),
	}
	b.entries[domain] = entry

	// Update category index
	if b.categories[category] == nil {
		b.categories[category] = make(map[string]bool)
	}
	b.categories[category][domain] = true

	// Update source index
	if b.sources[source] == nil {
		b.sources[source] = make(map[string]bool)
	}
	b.sources[source][domain] = true

	b.totalEntries++
	b.lastUpdate = time.Now()
}

// Remove removes a domain from the blocklist
func (b *Blocklist) Remove(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	domain = normalizeDomain(domain)

	entry, exists := b.entries[domain]
	if !exists {
		return
	}

	// Remove from category index
	if b.categories[entry.Category] != nil {
		delete(b.categories[entry.Category], domain)
	}

	// Remove from source index
	if b.sources[entry.Source] != nil {
		delete(b.sources[entry.Source], domain)
	}

	// Remove entry
	delete(b.entries, domain)
	b.totalEntries--
	b.lastUpdate = time.Now()
}

// IsBlocked checks if a domain is blocked
func (b *Blocklist) IsBlocked(domain string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	domain = normalizeDomain(domain)

	// Check exact match
	if _, exists := b.entries[domain]; exists {
		return true
	}

	// Check parent domains (for subdomain blocking)
	labels := dns.SplitDomainName(domain)
	for i := 1; i < len(labels); i++ {
		parent := dns.Fqdn(strings.Join(labels[i:], "."))
		if _, exists := b.entries[parent]; exists {
			return true
		}
	}

	return false
}

// GetEntry returns the blocklist entry for a domain
func (b *Blocklist) GetEntry(domain string) (*BlocklistEntry, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	domain = normalizeDomain(domain)

	// Check exact match
	if entry, exists := b.entries[domain]; exists {
		return entry, true
	}

	// Check parent domains
	labels := dns.SplitDomainName(domain)
	for i := 1; i < len(labels); i++ {
		parent := dns.Fqdn(strings.Join(labels[i:], "."))
		if entry, exists := b.entries[parent]; exists {
			return entry, true
		}
	}

	return nil, false
}

// AddToAllowlist adds a domain to the allowlist
func (b *Blocklist) AddToAllowlist(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	domain = normalizeDomain(domain)
	b.allowlist[domain] = true

	// Remove from blocklist if present
	if entry, exists := b.entries[domain]; exists {
		delete(b.entries, domain)
		if b.categories[entry.Category] != nil {
			delete(b.categories[entry.Category], domain)
		}
		if b.sources[entry.Source] != nil {
			delete(b.sources[entry.Source], domain)
		}
		b.totalEntries--
	}
}

// LoadFromFile loads domains from a file
func (b *Blocklist) LoadFromFile(filename, category, source string, format string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	return b.LoadFromReader(file, category, source, format)
}

// LoadFromReader loads domains from a reader
func (b *Blocklist) LoadFromReader(r io.Reader, category, source, format string) error {
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Parse based on format
		var domain string
		switch format {
		case "domains":
			// Simple list of domains (one per line)
			domain = line

		case "hosts":
			// hosts file format: "0.0.0.0 example.com" or "127.0.0.1 example.com"
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				domain = fields[1]
			}

		case "rpz":
			// Response Policy Zone format: "example.com CNAME ."
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				domain = fields[0]
			}

		case "json":
			// JSON format (simplified - full implementation would use json.Unmarshal)
			// For now, just extract domain from common patterns
			domain = extractDomainFromJSON(line)

		default:
			return fmt.Errorf("unsupported format: %s", format)
		}

		if domain != "" {
			b.Add(domain, category, source)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	return nil
}

// LoadFromURL loads domains from a URL
func (b *Blocklist) LoadFromURL(url, category, source, format string, apiKey string, headers map[string]string) error {
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Add API key if provided
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return b.LoadFromReader(resp.Body, category, source, format)
}

// ClearSource removes all entries from a specific source
func (b *Blocklist) ClearSource(source string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	domains := b.sources[source]
	if domains == nil {
		return
	}

	for domain := range domains {
		entry := b.entries[domain]
		if entry == nil {
			continue
		}

		// Remove from category index
		if b.categories[entry.Category] != nil {
			delete(b.categories[entry.Category], domain)
		}

		// Remove entry
		delete(b.entries, domain)
		b.totalEntries--
	}

	// Clear source index
	delete(b.sources, source)
	b.lastUpdate = time.Now()
}

// Stats returns blocklist statistics
type Stats struct {
	TotalEntries int64
	Categories   map[string]int
	Sources      map[string]int
	AllowlistSize int
	LastUpdate   time.Time
}

// GetStats returns blocklist statistics
func (b *Blocklist) GetStats() Stats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	stats := Stats{
		TotalEntries:  b.totalEntries,
		Categories:    make(map[string]int),
		Sources:       make(map[string]int),
		AllowlistSize: len(b.allowlist),
		LastUpdate:    b.lastUpdate,
	}

	for category, domains := range b.categories {
		stats.Categories[category] = len(domains)
	}

	for source, domains := range b.sources {
		stats.Sources[source] = len(domains)
	}

	return stats
}

// Helper functions

func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	domain = dns.Fqdn(domain)
	return domain
}

func extractDomainFromJSON(line string) string {
	// Simplified JSON extraction
	// Full implementation would use json.Unmarshal
	// Common patterns: {"domain": "example.com"} or {"name": "example.com"}

	line = strings.TrimSpace(line)
	if !strings.Contains(line, "domain") && !strings.Contains(line, "name") {
		return ""
	}

	// Extract value after "domain" or "name" key
	for _, key := range []string{"domain", "name"} {
		idx := strings.Index(line, `"`+key+`"`)
		if idx == -1 {
			continue
		}

		// Find the value
		remaining := line[idx+len(key)+2:]
		valueStart := strings.Index(remaining, `"`)
		if valueStart == -1 {
			continue
		}
		remaining = remaining[valueStart+1:]
		valueEnd := strings.Index(remaining, `"`)
		if valueEnd == -1 {
			continue
		}

		return remaining[:valueEnd]
	}

	return ""
}
