package protective

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/dnsscience/dnsscienced/internal/ede"
	"github.com/dnsscience/dnsscienced/internal/experimental"
	"github.com/miekg/dns"
)

// Engine implements Protective DNS (draft-liu-dnsop-protective-dns)
type Engine struct {
	config    experimental.ProtectiveDNSConfig
	blocklist *Blocklist
	stats     *Statistics
	mu        sync.RWMutex

	// Feed updater
	feedUpdater *FeedUpdater
}

// Statistics tracks protective DNS metrics
type Statistics struct {
	mu sync.RWMutex

	QueriesTotal     int64
	QueriesBlocked   int64
	QueriesAllowed   int64
	BlockedByCategory map[string]int64
	LastUpdate       time.Time
}

// NewEngine creates a new Protective DNS engine
func NewEngine(config experimental.ProtectiveDNSConfig) (*Engine, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("protective DNS not enabled")
	}

	e := &Engine{
		config:    config,
		blocklist: NewBlocklist(),
		stats: &Statistics{
			BlockedByCategory: make(map[string]int64),
		},
	}

	// Load local blocklists
	if err := e.loadLocalBlocklists(); err != nil {
		return nil, fmt.Errorf("load blocklists: %w", err)
	}

	// Load allowlists
	if err := e.loadAllowlists(); err != nil {
		return nil, fmt.Errorf("load allowlists: %w", err)
	}

	// Start feed updater if auto-update enabled
	if config.AutoUpdate {
		e.feedUpdater = NewFeedUpdater(e, config)
		go e.feedUpdater.Run()
	}

	return e, nil
}

// CheckQuery checks if a query should be blocked
func (e *Engine) CheckQuery(qname string, clientIP net.IP) (*BlockResult, error) {
	e.stats.mu.Lock()
	e.stats.QueriesTotal++
	e.stats.mu.Unlock()

	// Normalize domain
	qname = normalizeDomain(qname)

	// Check exemptions
	if e.isExempt(qname, clientIP) {
		e.stats.mu.Lock()
		e.stats.QueriesAllowed++
		e.stats.mu.Unlock()
		return &BlockResult{Blocked: false}, nil
	}

	// Check blocklist
	entry, blocked := e.blocklist.GetEntry(qname)
	if !blocked {
		e.stats.mu.Lock()
		e.stats.QueriesAllowed++
		e.stats.mu.Unlock()
		return &BlockResult{Blocked: false}, nil
	}

	// Domain is blocked
	e.stats.mu.Lock()
	e.stats.QueriesBlocked++
	e.stats.BlockedByCategory[entry.Category]++
	e.stats.mu.Unlock()

	// Log block if enabled
	if e.config.LogBlocks {
		e.logBlock(qname, entry.Category, clientIP)
	}

	return &BlockResult{
		Blocked:  true,
		Domain:   qname,
		Category: entry.Category,
		Source:   entry.Source,
		Reason:   fmt.Sprintf("Blocked: %s", entry.Category),
	}, nil
}

// BlockResult represents the result of a protective DNS check
type BlockResult struct {
	Blocked  bool   // Whether the domain is blocked
	Domain   string // The blocked domain
	Category string // Threat category
	Source   string // Blocklist source
	Reason   string // Block reason
}

// RewriteResponse rewrites a DNS response according to the configured strategy
func (e *Engine) RewriteResponse(msg *dns.Msg, result *BlockResult) *dns.Msg {
	if !result.Blocked {
		return msg // Not blocked, return original
	}

	// Create response based on strategy
	response := new(dns.Msg)
	response.SetReply(msg)

	switch e.config.Strategy {
	case "redirect":
		e.rewriteRedirect(response, msg, result)
	case "localhost":
		e.rewriteLocalhost(response, msg, result)
	case "cname":
		e.rewriteCNAME(response, msg, result)
	case "empty":
		e.rewriteEmpty(response, msg, result)
	case "nxdomain":
		e.rewriteNXDOMAIN(response, msg, result)
	case "servfail":
		e.rewriteSERVFAIL(response, msg, result)
	default:
		// Default to NXDOMAIN
		e.rewriteNXDOMAIN(response, msg, result)
	}

	// Add Extended DNS Error if enabled
	if e.config.EnableEDE {
		e.addEDE(response, result)
	}

	// Set custom TTL if specified
	if e.config.CustomTTL > 0 {
		for _, rr := range response.Answer {
			rr.Header().Ttl = e.config.CustomTTL
		}
	}

	return response
}

// Strategy 1: Redirect to safe IP
func (e *Engine) rewriteRedirect(response, query *dns.Msg, result *BlockResult) {
	if len(query.Question) == 0 {
		return
	}

	q := query.Question[0]

	switch q.Qtype {
	case dns.TypeA:
		if e.config.RedirectIPv4 != "" {
			ip := net.ParseIP(e.config.RedirectIPv4)
			if ip != nil {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    e.config.CustomTTL,
					},
					A: ip,
				}
				response.Answer = append(response.Answer, rr)
			}
		}

	case dns.TypeAAAA:
		if e.config.RedirectIPv6 != "" {
			ip := net.ParseIP(e.config.RedirectIPv6)
			if ip != nil {
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    e.config.CustomTTL,
					},
					AAAA: ip,
				}
				response.Answer = append(response.Answer, rr)
			}
		}
	}
}

// Strategy 2: Return localhost (127.0.0.1 / ::1)
func (e *Engine) rewriteLocalhost(response, query *dns.Msg, result *BlockResult) {
	if len(query.Question) == 0 {
		return
	}

	q := query.Question[0]

	switch q.Qtype {
	case dns.TypeA:
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    e.config.CustomTTL,
			},
			A: net.IPv4(127, 0, 0, 1),
		}
		response.Answer = append(response.Answer, rr)

	case dns.TypeAAAA:
		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    e.config.CustomTTL,
			},
			AAAA: net.IPv6loopback,
		}
		response.Answer = append(response.Answer, rr)
	}
}

// Strategy 3: CNAME to landing page
func (e *Engine) rewriteCNAME(response, query *dns.Msg, result *BlockResult) {
	if len(query.Question) == 0 {
		return
	}

	q := query.Question[0]

	if e.config.CNAMETarget != "" {
		rr := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    e.config.CustomTTL,
			},
			Target: dns.Fqdn(e.config.CNAMETarget),
		}
		response.Answer = append(response.Answer, rr)
	}
}

// Strategy 4: Empty answer section
func (e *Engine) rewriteEmpty(response, query *dns.Msg, result *BlockResult) {
	// Response has been created with SetReply, which sets appropriate header flags
	// Answer section is already empty
	response.Rcode = dns.RcodeSuccess
}

// Strategy 5: NXDOMAIN
func (e *Engine) rewriteNXDOMAIN(response, query *dns.Msg, result *BlockResult) {
	response.Rcode = dns.RcodeNameError
	response.Authoritative = true
}

// Strategy 6: SERVFAIL
func (e *Engine) rewriteSERVFAIL(response, query *dns.Msg, result *BlockResult) {
	response.Rcode = dns.RcodeServerFailure
}

// addEDE adds Extended DNS Error to response
func (e *Engine) addEDE(response *dns.Msg, result *BlockResult) {
	// Create EDE based on category
	var edeObj *ede.EDE

	if e.config.EDEExtraText != "" {
		// Use custom EDE text
		edeObj = ede.NewEDE(e.config.EDEInfoCode, e.config.EDEExtraText)
	} else {
		// Use category-specific EDE
		edeObj = ede.NewBlockedEDE(result.Category)
	}

	edeObj.AddToMessage(response)
}

// isExempt checks if a domain or client is exempt from blocking
func (e *Engine) isExempt(domain string, clientIP net.IP) bool {
	// Check domain exemptions
	for _, exemptDomain := range e.config.ExemptDomains {
		if dns.IsSubDomain(dns.Fqdn(exemptDomain), domain) {
			return true
		}
	}

	// Check client exemptions
	if clientIP != nil {
		for _, cidr := range e.config.ExemptClients {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ipnet.Contains(clientIP) {
				return true
			}
		}
	}

	return false
}

// loadLocalBlocklists loads blocklists from local files
func (e *Engine) loadLocalBlocklists() error {
	for _, file := range e.config.BlocklistFiles {
		// Infer category from filename if not specified
		category := "unknown"
		for _, cat := range e.config.Categories {
			if contains(file, cat) {
				category = cat
				break
			}
		}

		// Infer format from extension
		format := "domains"
		if contains(file, "hosts") {
			format = "hosts"
		} else if contains(file, "rpz") {
			format = "rpz"
		}

		if err := e.blocklist.LoadFromFile(file, category, file, format); err != nil {
			return fmt.Errorf("load %s: %w", file, err)
		}
	}

	return nil
}

// loadAllowlists loads allowlists
func (e *Engine) loadAllowlists() error {
	// Load from files
	for _, file := range e.config.AllowlistFiles {
		if err := e.loadAllowlistFile(file); err != nil {
			return fmt.Errorf("load allowlist %s: %w", file, err)
		}
	}

	// Add explicit domains
	for _, domain := range e.config.AllowlistDomains {
		e.blocklist.AddToAllowlist(domain)
	}

	return nil
}

// loadAllowlistFile loads domains from an allowlist file
func (e *Engine) loadAllowlistFile(filename string) error {
	// Similar to blocklist loading but adds to allowlist
	// Implementation would be similar to LoadFromFile
	return nil
}

// logBlock logs a blocked query
func (e *Engine) logBlock(domain, category string, clientIP net.IP) {
	// Simple logging - production version would use proper logger
	if e.config.LogFormat == "json" {
		log.Printf(`{"timestamp":"%s","domain":"%s","category":"%s","client":"%s","action":"blocked"}`,
			time.Now().Format(time.RFC3339), domain, category, clientIP.String())
	} else {
		log.Printf("BLOCKED %s (category: %s, client: %s)", domain, category, clientIP.String())
	}
}

// GetStats returns protective DNS statistics
func (e *Engine) GetStats() Statistics {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	// Create a copy
	stats := Statistics{
		QueriesTotal:      e.stats.QueriesTotal,
		QueriesBlocked:    e.stats.QueriesBlocked,
		QueriesAllowed:    e.stats.QueriesAllowed,
		BlockedByCategory: make(map[string]int64),
		LastUpdate:        e.stats.LastUpdate,
	}

	for k, v := range e.stats.BlockedByCategory {
		stats.BlockedByCategory[k] = v
	}

	return stats
}

// GetBlocklistStats returns blocklist statistics
func (e *Engine) GetBlocklistStats() Stats {
	return e.blocklist.GetStats()
}

// ReloadBlocklists reloads all blocklists
func (e *Engine) ReloadBlocklists() error {
	return e.loadLocalBlocklists()
}

// Shutdown stops the protective DNS engine
func (e *Engine) Shutdown() {
	if e.feedUpdater != nil {
		e.feedUpdater.Stop()
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr))
}
