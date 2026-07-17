package rrl

import (
	"hash/fnv"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Response Rate Limiting (RRL) prevents DNS amplification attacks
// by limiting response rates to clients making suspicious queries.
//
// Algorithm: Token bucket per (client-IP, query-type, response-type) tuple
// Based on BIND 9's implementation and ISC recommendations

const (
	// Default limits per ISC recommendations
	DefaultResponsesPerSecond = 5
	DefaultErrorsPerSecond    = 5
	DefaultNXDOMAINsPerSecond = 5
	DefaultWindow             = 15 // seconds
	DefaultSlip               = 2  // 1 in N responses get TC bit

	// Response categories for rate limiting
	CategoryResponse = iota
	CategoryError
	CategoryNXDOMAIN
	CategoryReferral
	CategoryNodata
	CategoryAll
)

// Config holds RRL configuration
type Config struct {
	// Per-category limits (queries per second)
	ResponsesPerSecond int `yaml:"responses_per_second"`
	ErrorsPerSecond    int `yaml:"errors_per_second"`
	NXDOMAINsPerSecond int `yaml:"nxdomains_per_second"`
	ReferralsPerSecond int `yaml:"referrals_per_second"`
	NodataPerSecond    int `yaml:"nodata_per_second"`
	AllPerSecond       int `yaml:"all_per_second"` // Global limit across all categories

	// Window for rate calculation (seconds)
	Window int `yaml:"window"`

	// Slip: 1 in N limited responses get TC bit instead of drop
	// slip=0: drop all, slip=1: TC all, slip=2: TC 50%
	Slip int `yaml:"slip"`

	// Exempt prefixes (no rate limiting)
	ExemptPrefixes []*net.IPNet `yaml:"-"` // Handled separately or needs custom unmarshaler

	// Exempt CIDRs for YAML unmarshaling
	ExemptCIDRs []string `yaml:"exempt_cidrs"`

	// IPv4 and IPv6 prefix lengths for bucketing
	IPv4PrefixLen int `yaml:"ipv4_prefix_len"` // Default: 24
	IPv6PrefixLen int `yaml:"ipv6_prefix_len"` // Default: 56

	// Enable/disable
	Enabled bool `yaml:"enabled"`
}

// DefaultConfig returns recommended RRL configuration
func DefaultConfig() Config {
	return Config{
		ResponsesPerSecond: DefaultResponsesPerSecond,
		ErrorsPerSecond:    DefaultErrorsPerSecond,
		NXDOMAINsPerSecond: DefaultNXDOMAINsPerSecond,
		ReferralsPerSecond: 5,
		NodataPerSecond:    5,
		AllPerSecond:       100,
		Window:             DefaultWindow,
		Slip:               DefaultSlip,
		IPv4PrefixLen:      24,
		IPv6PrefixLen:      56,
		Enabled:            true,
	}
}

// Action represents what to do with a query
type Action int

const (
	ActionAllow Action = iota // Allow response
	ActionDrop                // Drop response (silent)
	ActionSlip                // Respond with TC bit
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDrop:
		return "drop"
	case ActionSlip:
		return "slip"
	default:
		return "unknown"
	}
}

// bucket tracks rate for a specific (client, qname, qtype) tuple
type bucket struct {
	tokens    int32
	lastCheck int64 // Unix timestamp
}

// Limiter implements Response Rate Limiting
type Limiter struct {
	cfg   Config
	cfgMu sync.RWMutex // protects cfg

	// Buckets: map[hash]*bucket
	// Hash = fnv(client-prefix || qname || qtype || category)
	buckets sync.Map

	// Statistics
	allowed atomic.Uint64
	dropped atomic.Uint64
	slipped atomic.Uint64

	// Cleanup
	stopCleanup chan struct{}
	cleanupDone sync.WaitGroup
}

// NewLimiter creates a new RRL limiter
func NewLimiter(cfg Config) *Limiter {
	if cfg.Window == 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Slip == 0 {
		cfg.Slip = DefaultSlip
	}

	l := &Limiter{
		cfg:         cfg,
		stopCleanup: make(chan struct{}),
	}

	// Start background cleanup
	l.cleanupDone.Add(1)
	go l.cleanup()

	return l
}

// Check checks if a response should be rate limited
func (l *Limiter) Check(clientIP net.IP, qname string, qtype uint16, category int) Action {
	// Snapshot cfg under RLock so concurrent UpdateConfig calls don't race
	l.cfgMu.RLock()
	cfg := l.cfg // value copy
	l.cfgMu.RUnlock()

	if !cfg.Enabled {
		l.allowed.Add(1)
		return ActionAllow
	}

	// Check if client is exempt
	if isExempt(cfg, clientIP) {
		l.allowed.Add(1)
		return ActionAllow
	}

	// Get rate limit for this category
	limit := getLimitForCategory(cfg, category)
	if limit == 0 {
		l.allowed.Add(1)
		return ActionAllow // No limit for this category
	}

	// Calculate bucket hash
	hash := bucketHash(cfg, clientIP, qname, qtype, category)

	// Get or create bucket
	now := time.Now().Unix()
	bucketInterface, _ := l.buckets.LoadOrStore(hash, &bucket{
		tokens:    int32(limit * cfg.Window),
		lastCheck: now,
	})
	b := bucketInterface.(*bucket)

	// Refill tokens based on elapsed time (token bucket algorithm)
	lastCheck := atomic.LoadInt64(&b.lastCheck)
	elapsed := now - lastCheck

	if elapsed > 0 {
		// Refill tokens: (elapsed seconds) * (tokens per second)
		refill := int32(elapsed * int64(limit))
		maxTokens := int32(limit * cfg.Window)

		// Add tokens, capped at max
		currentTokens := atomic.LoadInt32(&b.tokens)
		newTokens := currentTokens + refill
		if newTokens > maxTokens {
			newTokens = maxTokens
		}

		atomic.StoreInt32(&b.tokens, newTokens)
		atomic.StoreInt64(&b.lastCheck, now)
	}

	// Try to consume a token
	tokens := atomic.AddInt32(&b.tokens, -1)

	if tokens >= 0 {
		// Token available - allow
		l.allowed.Add(1)
		return ActionAllow
	}

	// No tokens - rate limited!
	// Restore the token we tried to consume
	atomic.AddInt32(&b.tokens, 1)

	// Apply slip: 1 in N get TC bit, rest are dropped
	if cfg.Slip > 0 && (hash%uint64(cfg.Slip)) == 0 {
		l.slipped.Add(1)
		return ActionSlip
	}

	l.dropped.Add(1)
	return ActionDrop
}

// isExempt checks if client IP is in exempt list (uses Config snapshot from caller)
func isExempt(cfg Config, ip net.IP) bool {
	for _, prefix := range cfg.ExemptPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// getLimitForCategory returns rate limit for a category (uses Config snapshot from caller)
func getLimitForCategory(cfg Config, category int) int {
	switch category {
	case CategoryResponse:
		return cfg.ResponsesPerSecond
	case CategoryError:
		return cfg.ErrorsPerSecond
	case CategoryNXDOMAIN:
		return cfg.NXDOMAINsPerSecond
	case CategoryReferral:
		return cfg.ReferralsPerSecond
	case CategoryNodata:
		return cfg.NodataPerSecond
	case CategoryAll:
		return cfg.AllPerSecond
	default:
		return cfg.AllPerSecond
	}
}

// imputedQname is the constant sentinel substituted for the real query name
// when bucketing categories whose qname is attacker-controlled (see
// imputeQname). Mirrors BIND RRL's "imputed name" behavior.
var imputedQname = []byte(".")

// imputeQname reports whether bucketHash should substitute imputedQname for
// the real qname instead of hashing the attacker-supplied name directly.
//
// NXDOMAIN, NODATA, and error responses are exactly the categories a
// random-subdomain / NXDOMAIN "water torture" flood abuses: the attacker
// queries a fresh, unique, garbage label (rand1.victim.com, rand2.victim.com,
// ...) for every packet. If the qname were part of the bucket key, each
// unique label would LoadOrStore a brand-new bucket with a full token
// allowance, so RRL would never trip against exactly the attack it exists to
// stop — and the bucket map would grow unbounded (memory-exhaustion DoS).
// Imputing a constant name collapses all such responses toward one victim
// (per client-prefix/qtype/category) onto a single shared bucket.
//
// Positive answers (CategoryResponse) and referrals (CategoryReferral) keep
// the real qname: those names are not attacker-chosen garbage, and legitimate
// distinct queries should not share a rate-limit bucket.
func imputeQname(category int) bool {
	switch category {
	case CategoryNXDOMAIN, CategoryNodata, CategoryError:
		return true
	default:
		return false
	}
}

// bucketHash creates a hash for bucket identification
// Hash includes: client prefix + qname (imputed for attacker-controlled
// categories, see imputeQname) + qtype + category
func bucketHash(cfg Config, ip net.IP, qname string, qtype uint16, category int) uint64 {
	h := fnv.New64a()

	// Write client prefix (not full IP for privacy/efficiency)
	prefix := getPrefix(cfg, ip)
	h.Write(prefix)

	// Write query name — imputed to a constant sentinel for NXDOMAIN/NODATA/
	// error categories so random-subdomain floods can't mint a fresh bucket
	// (and fresh allowance) per unique attacker-chosen label.
	if imputeQname(category) {
		h.Write(imputedQname)
	} else {
		h.Write([]byte(qname))
	}

	// Write query type and category
	var buf [4]byte
	buf[0] = byte(qtype >> 8)
	buf[1] = byte(qtype)
	buf[2] = byte(category >> 8)
	buf[3] = byte(category)
	h.Write(buf[:])

	return h.Sum64()
}

// getPrefix returns the prefix of an IP for bucketing (uses Config snapshot from caller)
func getPrefix(cfg Config, ip net.IP) []byte {
	ip = ip.To4()
	if ip != nil {
		// IPv4: use /24 prefix (default)
		prefixLen := cfg.IPv4PrefixLen
		if prefixLen == 0 {
			prefixLen = 24
		}
		mask := net.CIDRMask(prefixLen, 32)
		return ip.Mask(mask)
	}

	// IPv6: use /56 prefix (default)
	ip = ip.To16()
	prefixLen := cfg.IPv6PrefixLen
	if prefixLen == 0 {
		prefixLen = 56
	}
	mask := net.CIDRMask(prefixLen, 128)
	return ip.Mask(mask)
}

// cleanup periodically removes expired buckets
func (l *Limiter) cleanup() {
	defer l.cleanupDone.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.performCleanup()
		case <-l.stopCleanup:
			return
		}
	}
}

// performCleanup removes old buckets
func (l *Limiter) performCleanup() {
	l.cfgMu.RLock()
	window := l.cfg.Window
	l.cfgMu.RUnlock()

	now := time.Now().Unix()
	cutoff := now - int64(window*2) // Keep buckets for 2x window

	l.buckets.Range(func(key, value interface{}) bool {
		b := value.(*bucket)
		lastCheck := atomic.LoadInt64(&b.lastCheck)

		if lastCheck < cutoff {
			l.buckets.Delete(key)
		}

		return true
	})
}

// Close stops background goroutines
func (l *Limiter) Close() {
	close(l.stopCleanup)
	l.cleanupDone.Wait()
}

// Stats returns RRL statistics
type Stats struct {
	Allowed  uint64
	Dropped  uint64
	Slipped  uint64
	Total    uint64
	DropRate float64
}

// GetStats returns current RRL statistics
func (l *Limiter) GetStats() Stats {
	allowed := l.allowed.Load()
	dropped := l.dropped.Load()
	slipped := l.slipped.Load()
	total := allowed + dropped + slipped

	var dropRate float64
	if total > 0 {
		dropRate = float64(dropped) / float64(total)
	}

	return Stats{
		Allowed:  allowed,
		Dropped:  dropped,
		Slipped:  slipped,
		Total:    total,
		DropRate: dropRate,
	}
}

// GetConfig returns a copy of the current rate-limit configuration.
func (l *Limiter) GetConfig() Config {
	l.cfgMu.RLock()
	defer l.cfgMu.RUnlock()
	return l.cfg
}

// UpdateConfig atomically replaces the rate-limit configuration.
// In-flight bucket tokens are not reset; new limits apply to subsequent checks.
func (l *Limiter) UpdateConfig(cfg Config) {
	l.cfgMu.Lock()
	defer l.cfgMu.Unlock()
	l.cfg = cfg
}

// CategorizeResponse determines the RRL category for a response
func CategorizeResponse(rcode int, answerCount, nsCount int) int {
	switch rcode {
	case 0: // NOERROR
		if answerCount > 0 {
			return CategoryResponse
		}
		if nsCount > 0 {
			return CategoryReferral
		}
		return CategoryNodata

	case 3: // NXDOMAIN
		return CategoryNXDOMAIN

	default: // SERVFAIL, FORMERR, etc.
		return CategoryError
	}
}
