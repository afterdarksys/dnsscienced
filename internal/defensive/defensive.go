package defensive

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Manager coordinates all defensive DNS features
type Manager struct {
	cfg Config

	// Blackhole/ACL
	blackhole *BlackholeManager

	// Query Logger
	queryLogger *QueryLogger

	// RRset ordering
	rrsetOrder *RRsetOrderer

	// Statistics
	stats Stats
}

// Stats holds defensive feature statistics
type Stats struct {
	BlackholedQueries   atomic.Uint64
	CompressedResponses atomic.Uint64
	TruncatedResponses  atomic.Uint64
	CookieRejections    atomic.Uint64
	LoggedQueries       atomic.Uint64
}

// New creates a new defensive DNS manager
func New(cfg Config) (*Manager, error) {
	m := &Manager{
		cfg: cfg,
	}

	// Initialize blackhole manager
	if cfg.Blackhole.Enabled {
		var err error
		m.blackhole, err = NewBlackholeManager(cfg.Blackhole)
		if err != nil {
			return nil, fmt.Errorf("init blackhole: %w", err)
		}
		log.Printf("[Defensive] Blackhole ACL enabled: %d CIDRs, action=%s", len(cfg.Blackhole.CIDRs), cfg.Blackhole.Action)
	}

	// Initialize query logger
	if cfg.QueryLogging.Enabled {
		var err error
		m.queryLogger, err = NewQueryLogger(cfg.QueryLogging)
		if err != nil {
			return nil, fmt.Errorf("init query logger: %w", err)
		}
		log.Printf("[Defensive] Query logging enabled: file=%s, categories=%v", cfg.QueryLogging.LogFile, cfg.QueryLogging.Categories)
	}

	// Initialize RRset orderer
	m.rrsetOrder = NewRRsetOrderer(cfg.RRsetOrder)
	if cfg.RRsetOrder.Method != "" && cfg.RRsetOrder.Method != "none" {
		log.Printf("[Defensive] RRset ordering enabled: method=%s", cfg.RRsetOrder.Method)
	}

	return m, nil
}

// CheckBlackhole checks if a client IP should be blackholed
// Returns true if query should be dropped or refused
func (m *Manager) CheckBlackhole(clientIP net.IP) (block bool, action string) {
	if m.blackhole == nil {
		return false, ""
	}

	if m.blackhole.IsBlocked(clientIP) {
		m.stats.BlackholedQueries.Add(1)
		return true, m.cfg.Blackhole.Action
	}

	return false, ""
}

// ValidateCookie validates DNS cookies according to policy
// Returns true if cookie is valid or cookies not enforced
func (m *Manager) ValidateCookie(hasServerCookie bool, isValid bool) bool {
	// If not requiring cookies, always allow
	if !m.cfg.Cookies.RequireServerCookie {
		return true
	}

	// If we have a server cookie, validate it
	if hasServerCookie {
		if m.cfg.Cookies.StrictValidation && !isValid {
			m.stats.CookieRejections.Add(1)
			return false
		}
		return isValid
	}

	// No server cookie - allow first query (client will get cookie in response)
	return true
}

// ApplyEDNSControls applies EDNS UDP size controls to response
func (m *Manager) ApplyEDNSControls(msg *dns.Msg, request *dns.Msg) {
	if !m.cfg.EDNS.Enabled {
		return
	}

	// Get or create EDNS0 OPT record
	opt := msg.IsEdns0()
	if opt == nil && request.IsEdns0() != nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  uint16(m.cfg.EDNS.UDPSize),
			},
		}
		msg.Extra = append(msg.Extra, opt)
	}

	if opt != nil {
		// Set advertised UDP size
		if m.cfg.EDNS.UDPSize > 0 {
			opt.Hdr.Class = uint16(m.cfg.EDNS.UDPSize)
		}

		// Check if response would exceed max UDP size
		packed, err := msg.Pack()
		if err == nil && m.cfg.EDNS.MaxUDPSize > 0 {
			if len(packed) > m.cfg.EDNS.MaxUDPSize {
				// Truncate response - force TCP retry
				msg.Truncated = true
				msg.Answer = nil
				msg.Ns = nil
				// Keep Extra for EDNS
				m.stats.TruncatedResponses.Add(1)
			}
		}
	}
}

// ApplyCompression applies compression controls to message
func (m *Manager) ApplyCompression(msg *dns.Msg) {
	if m.cfg.Compression.Enabled {
		msg.Compress = true
		// NoCaseCompress would require miekg/dns support
		// For now, standard compression is used
		m.stats.CompressedResponses.Add(1)
	} else {
		msg.Compress = false
	}
}

// OrderRRset applies RRset ordering to answer section
func (m *Manager) OrderRRset(records []dns.RR) []dns.RR {
	if m.rrsetOrder == nil {
		return records
	}
	return m.rrsetOrder.Order(records)
}

// LogQuery logs a query if logging is enabled
func (m *Manager) LogQuery(category string, clientIP net.IP, qname string, qtype uint16, rcode int) {
	if m.queryLogger == nil {
		return
	}

	m.queryLogger.Log(category, clientIP, qname, qtype, rcode)
	m.stats.LoggedQueries.Add(1)
}

// GetStats returns defensive feature statistics
func (m *Manager) GetStats() Stats {
	return Stats{
		BlackholedQueries:   atomic.Uint64{},
		CompressedResponses: atomic.Uint64{},
		TruncatedResponses:  atomic.Uint64{},
		CookieRejections:    atomic.Uint64{},
		LoggedQueries:       atomic.Uint64{},
	}
}

// Close cleans up resources
func (m *Manager) Close() error {
	if m.queryLogger != nil {
		return m.queryLogger.Close()
	}
	return nil
}

// BlackholeManager handles IP blacklisting/ACLs
type BlackholeManager struct {
	cfg     BlackholeConfig
	cidrs   []*net.IPNet
	mu      sync.RWMutex
	blocked atomic.Uint64
}

// NewBlackholeManager creates a new blackhole manager
func NewBlackholeManager(cfg BlackholeConfig) (*BlackholeManager, error) {
	b := &BlackholeManager{
		cfg: cfg,
	}

	// Parse CIDRs
	for _, cidr := range cfg.CIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
		b.cidrs = append(b.cidrs, ipnet)
	}

	return b, nil
}

// IsBlocked checks if an IP is blackholed
func (b *BlackholeManager) IsBlocked(ip net.IP) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, cidr := range b.cidrs {
		if cidr.Contains(ip) {
			b.blocked.Add(1)
			return true
		}
	}

	return false
}

// QueryLogger handles query logging with filtering
type QueryLogger struct {
	cfg            QueryLoggingConfig
	file           *os.File
	mu             sync.Mutex
	includeNets    []*net.IPNet
	excludeNets    []*net.IPNet
	categoryMap    map[string]bool
	queries        atomic.Uint64
	filteredOut    atomic.Uint64
}

// NewQueryLogger creates a new query logger
func NewQueryLogger(cfg QueryLoggingConfig) (*QueryLogger, error) {
	q := &QueryLogger{
		cfg:         cfg,
		categoryMap: make(map[string]bool),
	}

	// Parse categories
	for _, cat := range cfg.Categories {
		q.categoryMap[cat] = true
	}

	// Parse include CIDRs
	for _, cidr := range cfg.IncludeClients {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid include CIDR %s: %w", cidr, err)
		}
		q.includeNets = append(q.includeNets, ipnet)
	}

	// Parse exclude CIDRs
	for _, cidr := range cfg.ExcludeClients {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude CIDR %s: %w", cidr, err)
		}
		q.excludeNets = append(q.excludeNets, ipnet)
	}

	// Open log file
	var err error
	q.file, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	// Write header
	q.file.WriteString(fmt.Sprintf("# Query log started at %s\n", time.Now().Format(time.RFC3339)))
	q.file.WriteString("# Format: timestamp | category | client_ip | qname | qtype | rcode\n")

	return q, nil
}

// Log logs a query if it matches filters
func (q *QueryLogger) Log(category string, clientIP net.IP, qname string, qtype uint16, rcode int) {
	// Check if category is enabled
	if len(q.categoryMap) > 0 && !q.categoryMap[category] {
		q.filteredOut.Add(1)
		return
	}

	// Check include filter (if set, IP must match)
	if len(q.includeNets) > 0 {
		matched := false
		for _, net := range q.includeNets {
			if net.Contains(clientIP) {
				matched = true
				break
			}
		}
		if !matched {
			q.filteredOut.Add(1)
			return
		}
	}

	// Check exclude filter
	for _, net := range q.excludeNets {
		if net.Contains(clientIP) {
			q.filteredOut.Add(1)
			return
		}
	}

	// Log the query
	q.mu.Lock()
	defer q.mu.Unlock()

	timestamp := time.Now().Format(time.RFC3339)
	qtypeStr := dns.TypeToString[qtype]
	rcodeStr := dns.RcodeToString[rcode]

	logLine := fmt.Sprintf("%s | %s | %s | %s | %s | %s\n",
		timestamp, category, clientIP.String(), qname, qtypeStr, rcodeStr)

	q.file.WriteString(logLine)
	q.queries.Add(1)
}

// Close closes the log file
func (q *QueryLogger) Close() error {
	if q.file != nil {
		q.file.WriteString(fmt.Sprintf("# Query log closed at %s\n", time.Now().Format(time.RFC3339)))
		q.file.WriteString(fmt.Sprintf("# Total queries logged: %d, filtered out: %d\n", q.queries.Load(), q.filteredOut.Load()))
		return q.file.Close()
	}
	return nil
}

// RRsetOrderer handles record ordering in responses
type RRsetOrderer struct {
	cfg    RRsetOrderConfig
	rng    *rand.Rand
	mu     sync.Mutex
	cyclic map[string]int // Track cyclic position per name
}

// NewRRsetOrderer creates a new RRset orderer
func NewRRsetOrderer(cfg RRsetOrderConfig) *RRsetOrderer {
	r := &RRsetOrderer{
		cfg:    cfg,
		cyclic: make(map[string]int),
	}

	// Initialize random source
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	r.rng = rand.New(rand.NewSource(seed))

	return r
}

// Order applies the configured ordering method to records
func (r *RRsetOrderer) Order(records []dns.RR) []dns.RR {
	if len(records) <= 1 {
		return records
	}

	switch r.cfg.Method {
	case "random":
		return r.randomOrder(records)
	case "cyclic":
		return r.cyclicOrder(records)
	case "fixed", "none", "":
		return records
	default:
		return records
	}
}

// randomOrder shuffles records randomly
func (r *RRsetOrderer) randomOrder(records []dns.RR) []dns.RR {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a copy to avoid modifying original
	result := make([]dns.RR, len(records))
	copy(result, records)

	// Fisher-Yates shuffle
	r.rng.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})

	return result
}

// cyclicOrder rotates records for round-robin behavior
func (r *RRsetOrderer) cyclicOrder(records []dns.RR) []dns.RR {
	if len(records) == 0 {
		return records
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Use the first record's name as the key
	name := records[0].Header().Name

	// Get current position
	pos := r.cyclic[name]

	// Rotate records
	result := make([]dns.RR, len(records))
	for i := 0; i < len(records); i++ {
		result[i] = records[(pos+i)%len(records)]
	}

	// Update position for next time
	r.cyclic[name] = (pos + 1) % len(records)

	return result
}
