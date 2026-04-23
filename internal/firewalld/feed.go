package firewalld

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// feedEntry represents one parsed line from the threat feed.
type feedEntry struct {
	key   string // normalized: lower-cased domain or ip.String()
	score int    // clamped [0, 100]
	isIP  bool   // true for IP/CIDR targets, false for domains
}

// FeedClient polls a remote threat-intel feed URL and injects scores into a ThreatIntel engine.
// It implements full-replace semantics (D-05): entries from the previous successful cycle are
// removed before applying entries from the new cycle. A failed fetch leaves previous scores intact (D-14).
//
// prevDomains and prevIPs are only accessed from within the single run() goroutine — no mutex needed.
type FeedClient struct {
	cfg    ThreatIntelConfig
	engine *ThreatIntel
	logger zerolog.Logger
	client *http.Client

	// prevDomains and prevIPs track entries injected in the last successful cycle.
	// Used for full-replace: all previous entries are removed before applying new ones.
	// Only accessed from run() goroutine — no external readers, no mutex required.
	prevDomains map[string]bool
	prevIPs     map[string]bool
}

// newFeedClient constructs a FeedClient with a configured HTTP client.
func newFeedClient(cfg ThreatIntelConfig, engine *ThreatIntel) *FeedClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify}, //nolint:gosec
	}
	return &FeedClient{
		cfg:    cfg,
		engine: engine,
		logger: log.With().Str("component", "feed_client").Logger(),
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		prevDomains: make(map[string]bool),
		prevIPs:     make(map[string]bool),
	}
}

// StartFeed launches the background feed poller if FeedURL is configured (D-09).
// It returns immediately; the goroutine exits when ctx is cancelled.
// wg must be the server's WaitGroup so Stop() waits for the goroutine to exit.
func (fw *Firewall) StartFeed(ctx context.Context, wg interface{ Add(int); Done() }) {
	if fw.cfg.ThreatIntel.FeedURL == "" {
		return // D-09: no poller when feed_url is empty or unset
	}
	fc := newFeedClient(fw.cfg.ThreatIntel, fw.intel)

	// D-12: log auth presence/absence, never the token value.
	authDesc := "none"
	if fc.cfg.AuthToken != "" {
		authDesc = "bearer (set)"
	}
	fc.logger.Info().
		Str("url", fc.cfg.FeedURL).
		Str("auth", authDesc).
		Dur("interval", fc.cfg.PollInterval).
		Msg("feed poller starting")

	wg.Add(1)
	go func() {
		defer wg.Done()
		fc.run(ctx)
	}()
}

// run is the main polling loop. It fetches immediately on start, then on every tick.
// Exits when ctx is cancelled.
func (fc *FeedClient) run(ctx context.Context) {
	fc.fetchAndApply()

	ticker := time.NewTicker(fc.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fc.fetchAndApply()
		}
	}
}

// fetchAndApply fetches the feed URL, parses entries, and applies full-replace semantics.
// On HTTP or parse error: logs the error and returns without modifying previous scores (D-14).
// On success: removes previous-cycle entries first, then injects new entries.
func (fc *FeedClient) fetchAndApply() {
	start := time.Now()

	body, err := fc.fetch()
	if err != nil {
		// D-14: keep previous scores intact on failure.
		fc.logger.Error().Err(err).Msg("feed fetch failed, retaining previous scores")
		return
	}
	defer body.Close()

	entries, warnings := parseFeed(body)

	// Log WARN for each malformed line (D-04).
	for _, w := range warnings {
		fc.logger.Warn().Str("detail", w).Msg("feed: malformed line skipped")
	}

	// Full-replace: remove previous cycle's entries ONLY after a successful fetch (D-05 + D-14).
	fc.apply(entries)

	elapsed := time.Since(start)
	fc.logger.Info().
		Int("entries", len(entries)).
		Int("warnings", len(warnings)).
		Dur("elapsed", elapsed).
		Msg("feed fetch complete")
}

// fetch performs the HTTP GET request. Returns the response body on 2xx, error otherwise.
// Sets Bearer auth header and custom headers per config (D-10, D-11). Follows redirects (D-13).
func (fc *FeedClient) fetch() (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, fc.cfg.FeedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("feed: build request: %w", err)
	}

	// D-11: Bearer token when set.
	if fc.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+fc.cfg.AuthToken)
	}

	// D-10: additional custom headers.
	for k, v := range fc.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := fc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed: HTTP request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("feed: HTTP %d from %s", resp.StatusCode, fc.cfg.FeedURL)
	}
	return resp.Body, nil
}

// parseFeed reads newline-delimited feed entries from r.
// Format per line: "<target> <score>" where target is domain or IP/CIDR (D-01).
// Lines starting with "#" and blank lines are silently skipped (D-02).
// Type detection: net.ParseCIDR → net.ParseIP → domain (D-03).
// Malformed lines (missing score, non-numeric score) are collected as warnings (D-04).
// Scores are clamped to [0, 100].
func parseFeed(r io.Reader) ([]feedEntry, []string) {
	var entries []feedEntry
	var warnings []string

	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// D-02: skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			warnings = append(warnings, fmt.Sprintf("line %d: missing score field: %q", lineNum, line))
			continue
		}

		target := fields[0]
		score, err := strconv.Atoi(fields[1])
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: non-numeric score %q: %q", lineNum, fields[1], line))
			continue
		}

		// Clamp score to [0, 100].
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}

		// D-03: type detection by parsing.
		entry := feedEntry{score: score}
		if _, _, err := net.ParseCIDR(target); err == nil {
			// CIDR notation — treated as IP range key.
			entry.isIP = true
			entry.key = target // store as-is; AddIPScore accepts CIDR strings
		} else if ip := net.ParseIP(target); ip != nil {
			// Plain IP address — normalize via ip.String() to avoid representation mismatches.
			entry.isIP = true
			entry.key = ip.String()
		} else {
			// Treat as domain name — lower-case for consistency with ThreatIntel storage.
			entry.isIP = false
			entry.key = strings.ToLower(target)
		}

		entries = append(entries, entry)
	}
	return entries, warnings
}

// apply removes all previous-cycle entries then injects entries from the new cycle.
// This implements full-replace semantics (D-05, D-06).
func (fc *FeedClient) apply(entries []feedEntry) {
	// Step 1: remove all entries from the previous successful cycle.
	for domain := range fc.prevDomains {
		fc.engine.RemoveDomainScore(domain)
	}
	for ip := range fc.prevIPs {
		fc.engine.RemoveIPScore(ip)
	}

	// Step 2: inject new entries and track them for the next cycle.
	newDomains := make(map[string]bool, len(entries))
	newIPs := make(map[string]bool, len(entries))

	for _, e := range entries {
		if e.isIP {
			fc.engine.AddIPScore(e.key, e.score)
			newIPs[e.key] = true
			fc.logger.Debug().Str("target", e.key).Int("score", e.score).Msg("feed entry applied (IP)")
		} else {
			fc.engine.AddDomainScore(e.key, e.score)
			newDomains[e.key] = true
			fc.logger.Debug().Str("target", e.key).Int("score", e.score).Msg("feed entry applied (domain)")
		}
	}

	fc.prevDomains = newDomains
	fc.prevIPs = newIPs
}
