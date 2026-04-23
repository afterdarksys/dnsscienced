package cache

import (
	"time"

	"github.com/miekg/dns"
)

// CreateNegativeCacheEntry creates a cache entry for negative responses
// per RFC 2308 (negative caching of DNS queries)
func CreateNegativeCacheEntry(msg *dns.Msg, wireData []byte) (*Entry, bool) {
	if len(msg.Question) == 0 {
		return nil, false
	}

	q := msg.Question[0]
	isNegative := false
	negType := ""

	// RFC 2308: Cache NXDOMAIN and NODATA responses
	if msg.Rcode == dns.RcodeNameError {
		// NXDOMAIN response
		isNegative = true
		negType = "NXDOMAIN"
	} else if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 {
		// NODATA response (NOERROR with no answers)
		isNegative = true
		negType = "NODATA"
	}

	if !isNegative {
		return nil, false
	}

	// Extract negative cache TTL from SOA record in authority section
	// RFC 2308 Section 5: Use SOA minimum field
	negativeTTL := uint32(300) // Default 5 minutes if no SOA

	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			// Use SOA minimum field (MINIMUM in RFC 1035, now negative cache TTL)
			negativeTTL = soa.Minttl
			// Also consider SOA TTL itself per RFC 2308
			if soa.Header().Ttl < negativeTTL {
				negativeTTL = soa.Header().Ttl
			}
			break
		}
	}

	// Apply hard floor/ceiling before per-cache config overrides.
	// These are conservative absolute bounds; ShardedCache.applyTTLPolicy()
	// further enforces the operator-configured min/max negative TTL on top.
	if negativeTTL < 10 {
		negativeTTL = 10 // Absolute floor — prevent zero-TTL cache bypass
	}
	if negativeTTL > 10800 {
		negativeTTL = 10800 // Absolute ceiling — 3 hours
	}

	entry := &Entry{
		Data:       wireData,
		ExpiresAt:  time.Now().Add(time.Duration(negativeTTL) * time.Second),
		OrigTTL:    negativeTTL,
		QName:      q.Name,
		QType:      q.Qtype,
		QClass:     q.Qclass,
		IsNegative: true,
		NegType:    negType,
	}

	return entry, true
}

// GetNegativeCacheTTL extracts the negative cache TTL from a DNS message
// Returns 0 if no SOA record is found
func GetNegativeCacheTTL(msg *dns.Msg) uint32 {
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			ttl := soa.Minttl
			if soa.Header().Ttl < ttl {
				ttl = soa.Header().Ttl
			}
			return ttl
		}
	}
	return 0
}
