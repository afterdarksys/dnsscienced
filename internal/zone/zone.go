package zone

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Zone represents a DNS zone with all its records
type Zone struct {
	// Zone metadata
	Name   string
	Origin string // Fully qualified zone name (e.g., "example.com.")
	Class  uint16 // Usually dns.ClassINET

	// SOA record
	SOA *dns.SOA

	// Records organized by owner name
	// Map: owner name -> record type -> []RR
	Records map[string]map[uint16][]dns.RR

	// DNSSEC configuration
	DNSSEC *DNSSECConfig

	// Security configuration
	Security *SecurityConfig
}

// DNSSECConfig holds DNSSEC settings for a zone
type DNSSECConfig struct {
	Enabled   bool
	Algorithm uint8 // DNSSEC algorithm (e.g., ECDSAP256SHA256)

	// Key lifetimes
	KSKLifetime time.Duration
	ZSKLifetime time.Duration

	// NSEC3 settings
	NSEC3Enabled    bool
	NSEC3Iterations uint16
	NSEC3SaltLength uint8
}

// SecurityConfig holds per-zone security settings
type SecurityConfig struct {
	// 0x20 encoding (case randomization for cache poisoning resistance)
	Enable0x20 *bool // nil = use global setting, true/false = override

	// Response scrubbing (bailiwick checking)
	EnableScrubbing *bool // nil = use global setting

	// DNSSEC validation (for responses from this zone)
	ValidateDNSSEC *bool // nil = use global setting

	// QNAME minimization
	EnableQNAMEMin *bool // nil = use global setting
}

// Config holds zone file parser configuration
type Config struct {
	// Default TTL if not specified
	DefaultTTL uint32

	// Strict mode - fail on any error
	Strict bool

	// Allow includes (for BIND $INCLUDE directive)
	AllowIncludes bool

	// Base directory for relative includes
	BaseDir string
}

// DefaultConfig returns default zone parser configuration
func DefaultConfig() Config {
	return Config{
		DefaultTTL:    3600,
		Strict:        true,
		AllowIncludes: false,
		BaseDir:       ".",
	}
}

// New creates a new empty zone
func New(name string) *Zone {
	// WR-05: guard against empty name to prevent index-out-of-range panic.
	if name == "" {
		panic("zone.New: empty zone name")
	}
	// Ensure name is fully qualified
	if name[len(name)-1] != '.' {
		name += "."
	}

	return &Zone{
		Name:    name,
		Origin:  name,
		Class:   dns.ClassINET,
		Records: make(map[string]map[uint16][]dns.RR),
	}
}

// AddRecord adds a resource record to the zone
func (z *Zone) AddRecord(rr dns.RR) error {
	if rr == nil {
		return fmt.Errorf("cannot add nil record")
	}

	// Get owner name and normalize to lowercase for case-insensitive lookups (RFC 1035 §2.3.3)
	owner := strings.ToLower(rr.Header().Name)
	rr.Header().Name = owner

	// Ensure owner is in zone
	if !dns.IsSubDomain(z.Origin, owner) {
		return fmt.Errorf("record %s not in zone %s", owner, z.Origin)
	}

	// Get record type
	rrtype := rr.Header().Rrtype

	// Initialize maps if needed
	if z.Records[owner] == nil {
		z.Records[owner] = make(map[uint16][]dns.RR)
	}

	// Add record
	z.Records[owner][rrtype] = append(z.Records[owner][rrtype], rr)

	// If this is an SOA record, store it separately
	if rrtype == dns.TypeSOA {
		z.SOA = rr.(*dns.SOA)
	}

	return nil
}

// DeleteRecord removes an exact-match resource record from the zone.
//
// The match is performed by comparing string representations of dns.RR (rr.String()).
// Owner name is normalized to lowercase before lookup (mirrors AddRecord).
// Returns nil if the record is not found (RFC 2136 §3.4.2.5 no-op semantics).
// Returns an error only if rr is nil.
func (z *Zone) DeleteRecord(rr dns.RR) error {
	if rr == nil {
		return fmt.Errorf("cannot delete nil record")
	}

	// Normalize owner to lowercase (mirrors AddRecord)
	owner := strings.ToLower(rr.Header().Name)
	if owner == "" || owner[len(owner)-1] != '.' {
		owner += "."
	}

	rrtype := rr.Header().Rrtype

	typeMap, ok := z.Records[owner]
	if !ok {
		return nil // no-op: owner not in zone
	}

	existing, ok := typeMap[rrtype]
	if !ok {
		return nil // no-op: rrtype not at owner
	}

	// Build a normalized copy of the RR for rdata comparison.
	// RFC 2136 §3.4.2.3: delete-specific-RR matches on owner+type+rdata only;
	// class and TTL in the delete request are ignored. The stored records have
	// lowercase owners, ClassINET, and their original TTL. We normalize class
	// and TTL to the stored values so that rdata-only comparison works correctly.
	normalized := dns.Copy(rr)
	normalized.Header().Name = owner
	if len(existing) > 0 {
		normalized.Header().Class = existing[0].Header().Class
		normalized.Header().Ttl = existing[0].Header().Ttl
	}
	target := normalized.String()
	found := -1
	for i, e := range existing {
		if e.String() == target {
			found = i
			break
		}
	}
	if found == -1 {
		return nil // no-op: record not found
	}

	// Splice out the matched record
	updated := append(existing[:found], existing[found+1:]...)
	if len(updated) == 0 {
		delete(typeMap, rrtype)
		if len(typeMap) == 0 {
			delete(z.Records, owner)
		}
	} else {
		typeMap[rrtype] = updated
	}

	// WR-02: keep z.SOA consistent with Records. If the SOA RR was removed,
	// clear the fast-path field to prevent stale dual-storage divergence.
	// (The UPDATE guard in update.go rejects SOA deletes before reaching here;
	// this guard defends against direct DeleteRecord calls from other callers.)
	if rrtype == dns.TypeSOA {
		z.SOA = nil
	}

	return nil
}

// DeleteRRSet removes all records of a given type at a given owner name.
//
// Owner name is normalized to lowercase before lookup.
// Returns nil if the rrset is not found (no-op per RFC 2136 §3.4.2.5).
func (z *Zone) DeleteRRSet(owner string, rrtype uint16) error {
	// Normalize owner
	owner = strings.ToLower(owner)
	if owner == "" || owner[len(owner)-1] != '.' {
		owner += "."
	}

	typeMap, ok := z.Records[owner]
	if !ok {
		return nil // no-op: owner not in zone
	}

	delete(typeMap, rrtype)
	if len(typeMap) == 0 {
		delete(z.Records, owner)
	}

	return nil
}

// DeleteName removes all rrsets at a given owner name.
//
// Owner name is normalized to lowercase before lookup.
// Returns nil if the owner is not found (no-op per RFC 2136 §3.4.2.5).
func (z *Zone) DeleteName(owner string) error {
	// Normalize owner
	owner = strings.ToLower(owner)
	if owner == "" || owner[len(owner)-1] != '.' {
		owner += "."
	}

	delete(z.Records, owner)
	return nil
}

// GetRecords returns all records for a given owner name and type
func (z *Zone) GetRecords(owner string, rrtype uint16) []dns.RR {
	// WR-06: guard against empty owner to prevent index-out-of-range panic.
	if len(owner) == 0 {
		return nil
	}
	// Ensure owner is fully qualified
	if owner[len(owner)-1] != '.' {
		owner += "."
	}

	// DNS names are case-insensitive per RFC 1035 §2.3.3.
	// Normalize to lowercase so queries with 0x20 case randomization
	// (used by Google's resolver and others) resolve correctly.
	owner = strings.ToLower(owner)

	// An exact owner suppresses wildcard synthesis even when the requested type
	// is absent (RFC 4592). Empty non-terminals also count as existing names.
	if z.nameExists(owner) {
		return z.recordsAt(owner, rrtype)
	}

	// Wildcard expansion may use only the wildcard immediately below the
	// closest encloser. Searching progressively higher wildcards crosses DNS
	// tree nodes and produces answers forbidden by RFC 4592.
	labels := dns.SplitDomainName(owner)
	for i := 1; i < len(labels); i++ {
		encloser := dns.Fqdn(joinLabels(labels[i:]))
		if !z.nameExists(encloser) {
			continue
		}
		wildcard := "*." + encloser
		records := z.recordsAt(wildcard, rrtype)
		result := make([]dns.RR, len(records))
		for j, rr := range records {
			clone := dns.Copy(rr)
			clone.Header().Name = owner
			result[j] = clone
		}
		return result
	}

	return nil
}

// HasName returns true when an exact owner or empty non-terminal exists.
// Wildcard synthesis does not make the queried owner exist in the zone tree.
func (z *Zone) HasName(owner string) bool {
	// WR-06: guard against empty owner to prevent index-out-of-range panic.
	if len(owner) == 0 {
		return false
	}
	if owner[len(owner)-1] != '.' {
		owner += "."
	}
	// DNS names are case-insensitive per RFC 1035 §2.3.3.
	owner = strings.ToLower(owner)
	return z.nameExists(owner)
}

// ExactRecords returns records at an exact owner without wildcard expansion.
func (z *Zone) ExactRecords(owner string, rrtype uint16) []dns.RR {
	owner = strings.ToLower(dns.Fqdn(owner))
	return z.recordsAt(owner, rrtype)
}

// FindDelegation returns the closest zone cut at or above qname, excluding the
// zone apex. The returned NS RRset belongs in a referral authority section.
func (z *Zone) FindDelegation(qname string) (string, []dns.RR) {
	qname = strings.ToLower(dns.Fqdn(qname))
	labels := dns.SplitDomainName(qname)
	for i := 0; i < len(labels); i++ {
		candidate := dns.Fqdn(joinLabels(labels[i:]))
		if strings.EqualFold(candidate, z.Origin) {
			break
		}
		if records := z.recordsAt(candidate, dns.TypeNS); len(records) > 0 {
			return candidate, records
		}
	}
	return "", nil
}

func (z *Zone) recordsAt(owner string, rrtype uint16) []dns.RR {
	typeMap, ok := z.Records[owner]
	if !ok {
		return nil
	}
	if rrtype != dns.TypeANY {
		return typeMap[rrtype]
	}
	var records []dns.RR
	for _, rrset := range typeMap {
		records = append(records, rrset...)
	}
	return records
}

func (z *Zone) nameExists(owner string) bool {
	if _, ok := z.Records[owner]; ok {
		return true
	}
	for recordOwner := range z.Records {
		if !strings.EqualFold(recordOwner, owner) && dns.IsSubDomain(owner, recordOwner) {
			return true
		}
	}
	return false
}

// GetAllRecords returns all records in the zone
func (z *Zone) GetAllRecords() []dns.RR {
	var result []dns.RR

	for _, typeMap := range z.Records {
		for _, records := range typeMap {
			result = append(result, records...)
		}
	}

	return result
}

// GetNameservers returns NS records for the zone
func (z *Zone) GetNameservers() []*dns.NS {
	records := z.GetRecords(z.Origin, dns.TypeNS)
	ns := make([]*dns.NS, 0, len(records))

	for _, rr := range records {
		if n, ok := rr.(*dns.NS); ok {
			ns = append(ns, n)
		}
	}

	return ns
}

// Validate performs basic zone validation
func (z *Zone) Validate() error {
	// Must have SOA record
	if z.SOA == nil {
		return fmt.Errorf("zone %s missing SOA record", z.Origin)
	}

	// SOA must be at zone apex
	if z.SOA.Header().Name != z.Origin {
		return fmt.Errorf("SOA record name %s does not match origin %s", z.SOA.Header().Name, z.Origin)
	}

	// Must have at least one NS record
	ns := z.GetNameservers()
	if len(ns) == 0 {
		return fmt.Errorf("zone %s has no nameservers", z.Origin)
	}

	// Validate NS records have glue if in-zone
	for _, n := range ns {
		target := n.Ns
		if dns.IsSubDomain(z.Origin, target) {
			// Need glue (A or AAAA record)
			hasGlue := false
			if len(z.GetRecords(target, dns.TypeA)) > 0 {
				hasGlue = true
			}
			if len(z.GetRecords(target, dns.TypeAAAA)) > 0 {
				hasGlue = true
			}
			if !hasGlue {
				return fmt.Errorf("nameserver %s in zone but missing glue records", target)
			}
		}
	}

	// Validate CNAME records don't coexist with other types
	for owner, typeMap := range z.Records {
		if cnames, hasCNAME := typeMap[dns.TypeCNAME]; hasCNAME {
			if len(typeMap) > 1 {
				return fmt.Errorf("CNAME record at %s coexists with other records", owner)
			}
			if len(cnames) > 1 {
				return fmt.Errorf("multiple CNAME records at %s", owner)
			}
		}
	}

	// Validate MX records point to valid targets
	for owner, typeMap := range z.Records {
		if mxRecords, ok := typeMap[dns.TypeMX]; ok {
			for _, rr := range mxRecords {
				mx := rr.(*dns.MX)
				if mx.Mx == "." {
					// Null MX is valid (RFC 7505)
					continue
				}
				// MX target should not be a CNAME (RFC 2181)
				if len(z.GetRecords(mx.Mx, dns.TypeCNAME)) > 0 {
					return fmt.Errorf("MX record at %s points to CNAME %s", owner, mx.Mx)
				}
			}
		}
	}

	return nil
}

// IncrementSerial increments the zone serial number
func (z *Zone) IncrementSerial() error {
	if z.SOA == nil {
		return fmt.Errorf("no SOA record to increment")
	}

	// Parse current serial as YYYYMMDDNN format
	currentSerial := z.SOA.Serial
	today := time.Now().Format("20060102")
	todaySerial := uint32(0)
	fmt.Sscanf(today+"00", "%d", &todaySerial)

	if currentSerial < todaySerial {
		// Jump to today's first serial
		z.SOA.Serial = todaySerial
	} else if currentSerial >= todaySerial && currentSerial < todaySerial+99 {
		// Increment within today
		z.SOA.Serial++
	} else {
		// Fallback: just increment.
		// CR-05: guard against uint32 overflow — a serial of 0 would cause secondaries
		// to consider the zone older than any non-zero serial (RFC 1982), halting replication.
		if z.SOA.Serial == math.MaxUint32 {
			return fmt.Errorf("zone %s: SOA serial at MaxUint32, cannot increment", z.Origin)
		}
		z.SOA.Serial++
	}

	return nil
}

// Clone creates a deep copy of the zone
func (z *Zone) Clone() *Zone {
	clone := &Zone{
		Name:    z.Name,
		Origin:  z.Origin,
		Class:   z.Class,
		Records: make(map[string]map[uint16][]dns.RR),
	}

	if z.SOA != nil {
		clone.SOA = dns.Copy(z.SOA).(*dns.SOA)
	}

	for owner, typeMap := range z.Records {
		clone.Records[owner] = make(map[uint16][]dns.RR)
		for rrtype, records := range typeMap {
			clone.Records[owner][rrtype] = make([]dns.RR, len(records))
			for i, rr := range records {
				clone.Records[owner][rrtype][i] = dns.Copy(rr)
			}
		}
	}

	if z.DNSSEC != nil {
		dnssecCopy := *z.DNSSEC
		clone.DNSSEC = &dnssecCopy
	}

	return clone
}

// Helper: join DNS labels back into a domain name
func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return "."
	}
	result := ""
	for _, label := range labels {
		result += label + "."
	}
	return result
}

// Helper: fully qualify a name relative to zone origin
func (z *Zone) fullyQualify(name string) string {
	if name == "" || name == "@" {
		return z.Origin
	}
	if name[len(name)-1] == '.' {
		return name // Already fully qualified
	}
	return name + "." + z.Origin
}

// Helper: parse IP address (supports IPv4 and IPv6)
func parseIP(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", s)
	}
	return ip, nil
}

// GetTypeMap returns the type→[]RR map for the given owner name, or nil if absent.
// Used by the UPDATE handler for CNAME coexistence checks (D-04).
// Owner name is normalized to lowercase before lookup.
func (z *Zone) GetTypeMap(owner string) map[uint16][]dns.RR {
	owner = strings.ToLower(owner)
	if owner != "" && owner[len(owner)-1] != '.' {
		owner += "."
	}
	return z.Records[owner]
}

// Stats returns zone statistics
type Stats struct {
	Name       string
	RecordSets int // Number of unique (owner, type) pairs
	Records    int // Total number of records
	Owners     int // Number of unique owner names
}

// GetStats returns zone statistics
func (z *Zone) GetStats() Stats {
	recordSets := 0
	records := 0

	for _, typeMap := range z.Records {
		for _, rrs := range typeMap {
			recordSets++
			records += len(rrs)
		}
	}

	return Stats{
		Name:       z.Name,
		RecordSets: recordSets,
		Records:    records,
		Owners:     len(z.Records),
	}
}
