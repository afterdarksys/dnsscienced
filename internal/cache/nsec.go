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
	mu           sync.RWMutex
	records      []*nsecRecord  // NSEC records (canonical ordering)
	nsec3records []*nsec3Record // NSEC3 records (hashed, RFC 5155)
}

// nsecRecord is one validated NSEC record stored for synthesis.
type nsecRecord struct {
	Owner     string    // lowercase FQDN of the NSEC owner
	Next      string    // lowercase FQDN of the next name
	TypeMap   []uint16  // types present at Owner
	ExpiresAt time.Time
	Zone      string // the zone this record covers
}

// nsec3Record is one validated NSEC3 record stored for RFC 8198 aggressive synthesis.
type nsec3Record struct {
	OwnerHash  string    // base32-encoded hashed owner name (uppercase, no zone suffix)
	NextHash   string    // base32-encoded hashed next owner name (uppercase)
	Zone       string    // lowercase FQDN of the zone this NSEC3 covers
	Hash       uint8     // hash algorithm; only dns.SHA1 (1) is stored
	Iterations uint16
	Salt       string    // hex-encoded as stored in *dns.NSEC3.Salt
	Flags      uint8
	TypeMap    []uint16
	ExpiresAt  time.Time
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

	// Also store NSEC3 records (RFC 5155) for NSEC3-signed zones (D-04, D-06).
	for _, rr := range msg.Ns {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		// Skip non-SHA1 algorithms — miekg/dns only implements SHA-1 (Pitfall 4).
		if nsec3.Hash != dns.SHA1 {
			continue
		}
		// Skip opt-out NSEC3 records (bit 0 of Flags).
		if nsec3.Flags&0x01 != 0 {
			continue
		}
		// NSEC3 owner format: "<hash>.<zone>" — split at second label boundary.
		owner := strings.ToUpper(nsec3.Hdr.Name)
		labelIdx := dns.Split(owner)
		if len(labelIdx) < 2 {
			continue
		}
		ownerHash := owner[:labelIdx[1]-1]
		ownerZone := strings.ToLower(dns.Fqdn(owner[labelIdx[1]:]))

		rec3 := &nsec3Record{
			OwnerHash:  ownerHash,
			NextHash:   strings.ToUpper(nsec3.NextDomain),
			Zone:       ownerZone,
			Hash:       nsec3.Hash,
			Iterations: nsec3.Iterations,
			Salt:       nsec3.Salt,
			Flags:      nsec3.Flags,
			TypeMap:    nsec3.TypeBitMap,
			ExpiresAt:  now.Add(time.Duration(nsec3.Hdr.Ttl) * time.Second),
		}
		replaced := false
		for i, existing := range c.nsec3records {
			if existing.OwnerHash == ownerHash && existing.Zone == ownerZone {
				c.nsec3records[i] = rec3
				replaced = true
				break
			}
		}
		if !replaced {
			c.nsec3records = append(c.nsec3records, rec3)
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

		// Guard: qname must be a subdomain of the NSEC record's zone.
		// Without this check, a wrap-around NSEC from example.com could incorrectly
		// synthesize NXDOMAIN for names in example.net or other unrelated zones.
		if !dns.IsSubDomain(rec.Zone, qname) {
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

	return c.synthesizeFromNSEC3(qname, qtype, qclass, queryID)
}

// synthesizeFromNSEC3 attempts NSEC3-based NXDOMAIN synthesis (RFC 8198 + RFC 5155).
func (c *NSECCache) synthesizeFromNSEC3(qname string, qtype, qclass, queryID uint16) *dns.Msg {
	qname = strings.ToLower(dns.Fqdn(qname))
	now := time.Now()

	// mu.RLock is already held by the caller (SynthesizeNXDOMAIN).
	for _, rec := range c.nsec3records {
		if rec.ExpiresAt.Before(now) {
			continue
		}
		if !dns.IsSubDomain(rec.Zone, qname) {
			continue
		}
		// Reconstruct minimal *dns.NSEC3 for the Cover() method.
		n3 := &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: rec.OwnerHash + "." + rec.Zone},
			Hash:       rec.Hash,
			Flags:      rec.Flags,
			Iterations: rec.Iterations,
			Salt:       rec.Salt,
			NextDomain: rec.NextHash,
			TypeBitMap: rec.TypeMap,
		}
		if n3.Cover(qname) {
			return buildSyntheticNXDOMAIN_NSEC3(qname, qtype, qclass, queryID, rec, n3)
		}
	}
	return nil
}

func buildSyntheticNXDOMAIN_NSEC3(qname string, qtype, qclass, queryID uint16, rec *nsec3Record, n3 *dns.NSEC3) *dns.Msg {
	m := new(dns.Msg)
	m.Id = queryID
	m.Response = true
	m.Opcode = dns.OpcodeQuery
	m.Authoritative = false
	m.RecursionAvailable = true
	m.Rcode = dns.RcodeNameError

	m.Question = []dns.Question{{
		Name:   qname,
		Qtype:  qtype,
		Qclass: qclass,
	}}

	nsec3RR := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   n3.Hdr.Name,
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    uint32(time.Until(rec.ExpiresAt).Seconds()),
		},
		Hash:       rec.Hash,
		Flags:      rec.Flags,
		Iterations: rec.Iterations,
		Salt:       rec.Salt,
		NextDomain: rec.NextHash,
		TypeBitMap: rec.TypeMap,
	}
	m.Ns = []dns.RR{nsec3RR}
	return m
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

	valid3 := c.nsec3records[:0]
	for _, rec := range c.nsec3records {
		if rec.ExpiresAt.After(now) {
			valid3 = append(valid3, rec)
		}
	}
	c.nsec3records = valid3
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
