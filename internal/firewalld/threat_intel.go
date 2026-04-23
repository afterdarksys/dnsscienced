package firewalld

import (
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// ThreatIntel computes a composite threat score (0-100) for a query.
//
// Score sources (additive, clamped to 100):
//
//   - IP reputation: static mapping of client CIDR → score delta.
//   - Zone score: per-zone baseline from config.
//   - Customer trust bonus: subtracted for known-good accounts.
//
// The caller blocks queries whose score meets or exceeds
// ThreatIntelConfig.BlockThreshold.
type ThreatIntel struct {
	cfg ThreatIntelConfig

	// ipNets holds parsed CIDR → score entries for IP reputation checks.
	// Built once at construction; replaced atomically on Reload.
	mu     sync.RWMutex
	ipNets []ipScore

	// dynamic lets other components inject scores at runtime (e.g. from live
	// dnsscience feed).  Keyed by lower-cased domain suffix.
	dynMu      sync.RWMutex
	dynDomains map[string]int
	dynIPs     map[string]int // string form of net.IP
}

type ipScore struct {
	net   *net.IPNet
	score int
}

func newThreatIntel(cfg ThreatIntelConfig) *ThreatIntel {
	ti := &ThreatIntel{
		cfg:        cfg,
		dynDomains: make(map[string]int),
		dynIPs:     make(map[string]int),
	}
	ti.compileIPScores()
	return ti
}

func (ti *ThreatIntel) compileIPScores() {
	nets := make([]ipScore, 0, len(ti.cfg.StaticIPScores))
	for cidr, score := range ti.cfg.StaticIPScores {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Also try plain IP.
			ip := net.ParseIP(cidr)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		nets = append(nets, ipScore{net: ipnet, score: score})
	}
	ti.mu.Lock()
	ti.ipNets = nets
	ti.mu.Unlock()
}

// Score computes a threat score for qctx (0-100, higher = more suspicious).
func (ti *ThreatIntel) Score(qctx *QueryContext) int {
	score := 0

	// IP reputation.
	score += ti.ipScore(qctx.ClientIP)

	// Dynamic IP score (from live feed).
	ti.dynMu.RLock()
	if s, ok := ti.dynIPs[qctx.ClientIP.String()]; ok {
		score += s
	}
	ti.dynMu.RUnlock()

	// Zone / domain score: walk labels looking for a configured zone match.
	score += ti.zoneScore(qctx.Name)

	// Dynamic domain score.
	ti.dynMu.RLock()
	bare := strings.TrimSuffix(qctx.Name, ".")
	labels := dns.SplitDomainName(bare)
	for i := range labels {
		suffix := strings.ToLower(strings.Join(labels[i:], "."))
		if s, ok := ti.dynDomains[suffix]; ok {
			score += s
			break
		}
	}
	ti.dynMu.RUnlock()

	// Customer trust bonus reduces score.
	if qctx.CustomerID != "" {
		if meta, ok := ti.cfg.CustomerMeta[qctx.CustomerID]; ok {
			score -= meta.TrustBonus
		}
	}

	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// ipScore returns the reputation score for clientIP.
func (ti *ThreatIntel) ipScore(clientIP net.IP) int {
	if clientIP == nil {
		return 0
	}
	ti.mu.RLock()
	defer ti.mu.RUnlock()
	for _, entry := range ti.ipNets {
		if entry.net.Contains(clientIP) {
			return entry.score
		}
	}
	return 0
}

// zoneScore returns the configured baseline score for the zone containing name.
func (ti *ThreatIntel) zoneScore(name string) int {
	bare := strings.TrimSuffix(strings.ToLower(name), ".")
	labels := dns.SplitDomainName(bare)
	// Walk from most specific to least specific zone.
	for i := range labels {
		zone := strings.Join(labels[i:], ".")
		if s, ok := ti.cfg.ZoneScores[zone]; ok {
			return s
		}
	}
	return 0
}

// AddDomainScore injects a domain score at runtime (called from live feed).
// domain should be a bare label string without trailing dot.
func (ti *ThreatIntel) AddDomainScore(domain string, score int) {
	ti.dynMu.Lock()
	ti.dynDomains[strings.ToLower(domain)] = score
	ti.dynMu.Unlock()
}

// AddIPScore injects an IP score at runtime.
func (ti *ThreatIntel) AddIPScore(ip string, score int) {
	ti.dynMu.Lock()
	ti.dynIPs[ip] = score
	ti.dynMu.Unlock()
}

// RemoveDomainScore removes a previously-injected domain score.
func (ti *ThreatIntel) RemoveDomainScore(domain string) {
	ti.dynMu.Lock()
	delete(ti.dynDomains, strings.ToLower(domain))
	ti.dynMu.Unlock()
}
