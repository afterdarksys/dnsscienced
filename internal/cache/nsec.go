package cache

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// NSECCache stores validated NSEC/NSEC3 records for aggressive negative synthesis.
//
// Implements RFC 8198 "Aggressive Use of DNSSEC-Validated Cache":
// When a DNSSEC-validated NXDOMAIN arrives with an NSEC proof covering a range of
// names, subsequent queries for names within that range can be answered locally
// without querying the authoritative server. This reduces query volume significantly
// for zones under random-subdomain DDoS (e.g., NXNSAttack variants).
//
// Requirements: the zone must be DNSSEC-signed and the resolver must have validation
// enabled (ValidationModeLogOnly or ValidationModeEnforced). Unsigned NSEC records
// are never used for synthesis.
type NSECCache struct {
	mu      sync.RWMutex
	records []*nsecRecord // kept in canonical order by Owner for binary search
}

// nsecRecord is one validated NSEC record stored for synthesis.
type nsecRecord struct {
	Owner     string    // lowercase FQDN of the NSEC owner
	Next      string    // lowercase FQDN of the next name
	TypeMap   []uint16  // types present at Owner
	ExpiresAt time.Time
	Zone      string // the zone this record covers
}

// NewNSECCache creates an empty NSEC cache.
func NewNSECCache() *NSECCache {
	return &NSECCache{}
}

// Store adds validated NSEC records extracted from a DNSSEC-validated NXDOMAIN
// or NODATA response. Only call this when the response has been validated secure.
func (c *NSECCache) Store(msg *dns.Msg, zone string) {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, rr := range msg.Ns {
		nsec, ok := rr.(*dns.NSEC)
		if !ok {
			continue
		}

		owner := strings.ToLower(dns.Fqdn(nsec.Hdr.Name))
		next := strings.ToLower(dns.Fqdn(nsec.NextDomain))

		rec := &nsecRecord{
			Owner:     owner,
			Next:      next,
			TypeMap:   nsec.TypeBitMap,
			ExpiresAt: now.Add(time.Duration(nsec.Hdr.Ttl) * time.Second),
			Zone:      strings.ToLower(dns.Fqdn(zone)),
		}

		// Replace any existing record for the same owner.
		replaced := false
		for i, existing := range c.records {
			if existing.Owner == owner {
				c.records[i] = rec
				replaced = true
				break
			}
		}
		if !replaced {
			c.records = append(c.records, rec)
		}
	}
}

// SynthesizeNXDOMAIN checks whether qname is provably non-existent based on
// cached NSEC records. If so, it returns a synthesized NXDOMAIN response
// that can be returned to the client without hitting the network.
// Returns nil if no synthesis is possible.
func (c *NSECCache) SynthesizeNXDOMAIN(qname string, qtype uint16, qclass uint16, queryID uint16) *dns.Msg {
	qname = strings.ToLower(dns.Fqdn(qname))

	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()

	for _, rec := range c.records {
		if rec.ExpiresAt.Before(now) {
			continue
		}

		// Check if qname falls strictly between Owner and Next in canonical order.
		// NSEC record "A NSEC B" proves non-existence of all names X where A < X < B.
		if canonicalLess(rec.Owner, qname) && canonicalLess(qname, rec.Next) {
			return buildSyntheticNXDOMAIN(qname, qtype, qclass, queryID, rec)
		}

		// Handle zone apex wrap-around: the last NSEC in a zone has Next = zone apex,
		// meaning it covers names after Owner through end of zone.
		// "Z NSEC apex" covers names alphabetically greater than Z.
		if canonicalLess(rec.Owner, qname) && canonicalLess(rec.Next, rec.Owner) {
			// This is the last NSEC (wraps around); name is after the last entry.
			return buildSyntheticNXDOMAIN(qname, qtype, qclass, queryID, rec)
		}
	}

	return nil
}

// Flush removes all expired NSEC records.
func (c *NSECCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	valid := c.records[:0]
	for _, rec := range c.records {
		if rec.ExpiresAt.After(now) {
			valid = append(valid, rec)
		}
	}
	c.records = valid
}

// buildSyntheticNXDOMAIN constructs an NXDOMAIN response from a cached NSEC record.
func buildSyntheticNXDOMAIN(qname string, qtype, qclass uint16, queryID uint16, rec *nsecRecord) *dns.Msg {
	m := new(dns.Msg)
	m.Id = queryID
	m.Response = true
	m.Opcode = dns.OpcodeQuery
	m.Authoritative = false // synthesized, not from authority
	m.RecursionAvailable = true
	m.Rcode = dns.RcodeNameError

	m.Question = []dns.Question{{
		Name:   qname,
		Qtype:  qtype,
		Qclass: qclass,
	}}

	// Include the NSEC record in the authority section so clients can validate
	// the synthetic denial (RFC 8198 §4).
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   rec.Owner,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    uint32(time.Until(rec.ExpiresAt).Seconds()),
		},
		NextDomain: rec.Next,
		TypeBitMap: rec.TypeMap,
	}
	m.Ns = []dns.RR{nsec}

	return m
}

// canonicalLess implements RFC 4034 §6.1 canonical DNS name ordering.
// Names are compared label-by-label from right (TLD) to left (most specific),
// with case-insensitive octet comparison within each label.
func canonicalLess(a, b string) bool {
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	b = strings.ToLower(strings.TrimSuffix(b, "."))

	aLabels := strings.Split(a, ".")
	bLabels := strings.Split(b, ".")

	// Reverse so index 0 is the TLD
	reverseLabels(aLabels)
	reverseLabels(bLabels)

	for i := 0; i < len(aLabels) && i < len(bLabels); i++ {
		if aLabels[i] < bLabels[i] {
			return true
		}
		if aLabels[i] > bLabels[i] {
			return false
		}
	}

	// If all common labels match, shorter name comes first
	return len(aLabels) < len(bLabels)
}

func reverseLabels(labels []string) {
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
}
