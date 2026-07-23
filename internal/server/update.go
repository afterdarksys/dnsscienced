package server

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

// prereqType classifies an RFC 2136 prerequisite record (section 2.4).
type prereqType int

const (
	prereqNameInUse        prereqType = iota // ClassANY, TypeANY → name must exist; fail: NXDOMAIN (3)
	prereqNameNotInUse                       // ClassNONE, TypeANY → name must not exist; fail: YXDomain (6)
	prereqRRSetExists                        // ClassANY, specific type → rrset must exist; fail: NXRrset (8)
	prereqRRSetNotExists                     // ClassNONE, specific type → rrset must not exist; fail: YXRrset (7)
	prereqRRSetExistsValue                   // zone class, specific type, rdata → rrset values must match; fail: NXRrset (8)
	prereqFormatError                        // malformed prerequisite → FormatError
)

// classifyPrereq classifies a prerequisite RR per RFC 2136 §2.4.
func classifyPrereq(rr dns.RR, zoneClass uint16) prereqType {
	hdr := rr.Header()
	switch {
	case hdr.Class == dns.ClassANY && hdr.Rrtype == dns.TypeANY:
		// Name-in-use: any RR at this name
		return prereqNameInUse
	case hdr.Class == dns.ClassNONE && hdr.Rrtype == dns.TypeANY:
		// Name-not-in-use: name must be absent
		return prereqNameNotInUse
	case hdr.Class == dns.ClassANY && hdr.Rrtype != dns.TypeANY:
		// RRset-exists (type-specific, no rdata)
		return prereqRRSetExists
	case hdr.Class == dns.ClassNONE && hdr.Rrtype != dns.TypeANY:
		// RRset-not-exists (type-specific)
		return prereqRRSetNotExists
	case hdr.Class == zoneClass:
		// RRset-exists-value: specific rdata must match
		return prereqRRSetExistsValue
	default:
		return prereqFormatError
	}
}

// evaluatePrereqs evaluates all prerequisite RRs against the live zone.
// Returns (0, true) if all prerequisites pass, or (failRcode, false) on the first failure.
// Per RFC 2136 §3.2, all prerequisites are evaluated; the first failure wins.
func evaluatePrereqs(prereqs []dns.RR, z *zone.Zone) (rcode int, ok bool) {
	valueGroups := make(map[string][]dns.RR)
	for _, rr := range prereqs {
		if rr.Header().Ttl != 0 {
			return dns.RcodeFormatError, false
		}
		pt := classifyPrereq(rr, z.Class)
		owner := strings.ToLower(rr.Header().Name)
		rrtype := rr.Header().Rrtype
		if rr.Header().Class == dns.ClassANY || rr.Header().Class == dns.ClassNONE {
			if _, emptyRData := rr.(*dns.ANY); !emptyRData {
				return dns.RcodeFormatError, false
			}
		}

		switch pt {
		case prereqNameInUse:
			// Name must exist in zone
			if !z.HasName(owner) {
				return dns.RcodeNameError, false // NXDOMAIN (3)
			}

		case prereqNameNotInUse:
			// Name must NOT exist in zone
			if z.HasName(owner) {
				return dns.RcodeYXDomain, false // YXDomain (6)
			}

		case prereqRRSetExists:
			// RRset of given type must exist
			if len(z.ExactRecords(owner, rrtype)) == 0 {
				return dns.RcodeNXRrset, false // NXRrset (8)
			}

		case prereqRRSetNotExists:
			// RRset of given type must NOT exist
			if len(z.ExactRecords(owner, rrtype)) > 0 {
				return dns.RcodeYXRrset, false // YXRrset (7)
			}

		case prereqRRSetExistsValue:
			key := owner + "\x00" + strconv.Itoa(int(rrtype))
			valueGroups[key] = append(valueGroups[key], rr)

		case prereqFormatError:
			return dns.RcodeFormatError, false
		}
	}

	for key, requested := range valueGroups {
		separator := strings.LastIndexByte(key, 0)
		owner := key[:separator]
		rrtype64, _ := strconv.ParseUint(key[separator+1:], 10, 16)
		existing := z.ExactRecords(owner, uint16(rrtype64))
		if !sameRRSetValues(requested, existing, z.Class) {
			return dns.RcodeNXRrset, false
		}
	}

	return 0, true
}

func sameRRSetValues(left, right []dns.RR, zoneClass uint16) bool {
	leftSet := make(map[string]struct{}, len(left))
	rightSet := make(map[string]struct{}, len(right))
	for _, rr := range left {
		leftSet[normalizedRRValue(rr, zoneClass)] = struct{}{}
	}
	for _, rr := range right {
		rightSet[normalizedRRValue(rr, zoneClass)] = struct{}{}
	}
	if len(leftSet) != len(rightSet) {
		return false
	}
	for value := range leftSet {
		if _, ok := rightSet[value]; !ok {
			return false
		}
	}
	return true
}

func normalizedRRValue(rr dns.RR, zoneClass uint16) string {
	copyRR := dns.Copy(rr)
	copyRR.Header().Name = strings.ToLower(dns.Fqdn(copyRR.Header().Name))
	copyRR.Header().Class = zoneClass
	copyRR.Header().Ttl = 0
	return copyRR.String()
}

func containsRRValue(records []dns.RR, candidate dns.RR, zoneClass uint16) bool {
	want := normalizedRRValue(candidate, zoneClass)
	for _, rr := range records {
		if normalizedRRValue(rr, zoneClass) == want {
			return true
		}
	}
	return false
}

// handleUpdate handles RFC 2136 Dynamic DNS Update requests.
//
// Guard chain (each failure returns immediately with the specified rcode):
//  1. TSIG presence (D-16): absent TSIG → NOTAUTH (rcode 9)
//  2. TSIG validity (D-16): bad/replayed TSIG → NOTAUTH
//  3. Empty Zone section guard → FORMERR
//  4. Zone lookup: unknown zone → REFUSED
//  5. ACL check (D-15, D-17): nil ACL (no allow_update) or IP not allowed → REFUSED
//  6. Lock zone.updateMu
//  7. Evaluate prerequisites (r.Answer) against live zone
//  8. Clone live zone
//  9. Apply Update section (r.Ns) to clone
//
// 10. clone.Validate() → SERVFAIL on failure
// 11. clone.IncrementSerial()
// 12. Atomic swap: s.cfg.Zones[zoneName] = clone
// 13. Unlock zone.updateMu
// 14. Reply NOERROR
func (s *Server) handleUpdate(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
	// Local helper to send an error rcode without the pooled message path.
	sendRcode := func(rcode int) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = rcode
		if reqTSIG := r.IsTsig(); reqTSIG != nil {
			m.SetTsig(reqTSIG.Hdr.Name, reqTSIG.Algorithm, reqTSIG.Fudge, time.Now().Unix())
		}
		w.WriteMsg(m) //nolint:errcheck
	}

	// 1. TSIG presence check (D-16): no TSIG record at all → NOTAUTH.
	// This MUST come before the validity check — an absent TSIG yields
	// TsigStatus() == nil, which would incorrectly allow unsigned requests.
	if r.IsTsig() == nil {
		sendRcode(dns.RcodeNotAuth)
		return
	}

	// 2. TSIG validity check (D-16): bad key, bad sig, replay attack.
	if w.TsigStatus() != nil {
		sendRcode(dns.RcodeNotAuth)
		return
	}

	// 3. Empty Zone section guard.
	if len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeSOA ||
		(r.Question[0].Qclass == dns.ClassANY || r.Question[0].Qclass == dns.ClassNONE) {
		sendRcode(dns.RcodeFormatError)
		return
	}

	// 4. Zone lookup. In UPDATE messages, Question[0].Name = zone FQDN (TypeSOA class).
	// CR-02: canonicalize to lowercase before map key lookup (RFC 4343 case-insensitivity).
	zoneName := strings.ToLower(r.Question[0].Name)
	// CR-01: RLock protects concurrent read of cfg.Zones map.
	s.zonesMu.RLock()
	z, ok := s.cfg.Zones[zoneName]
	s.zonesMu.RUnlock()
	if !ok {
		sendRcode(dns.RcodeRefused)
		return
	}
	if r.Question[0].Qclass != z.Class {
		sendRcode(dns.RcodeFormatError)
		return
	}

	// 5. ACL check (D-15, D-17):
	//    nil ACL = no allow_update configured = deny all (secure-by-default).
	//    non-nil ACL = source IP must be in the allowlist.
	acl := s.zoneUpdateACLs[zoneName]
	if acl == nil || !acl.Check(clientIP) {
		sendRcode(dns.RcodeRefused)
		return
	}

	// 6. Lock zone.updateMu to serialize concurrent UPDATE requests (D-06, T-13-08).
	// Hold through prereq evaluation, clone, apply, swap.
	z.Lock()
	defer z.Unlock()

	// 7. Evaluate prerequisites (r.Answer = PREREQUISITE section per RFC 2136 §2).
	// Evaluated against the LIVE zone (before cloning) so that concurrent updates
	// are correctly serialized.  Any failure → return error rcode; zero updates applied (D-03).
	if rcode, ok := evaluatePrereqs(r.Answer, z); !ok {
		sendRcode(rcode)
		return
	}

	// 8. Clone the live zone. All mutations are applied to the clone only.
	// The live zone remains readable and consistent until the atomic swap (D-05, T-13-07).
	clone := z.Clone()

	// 9. Apply Update section (r.Ns = UPDATE section per RFC 2136 §2).
	for _, rr := range r.Ns {
		hdr := rr.Header()
		owner := strings.ToLower(hdr.Name)
		rrtype := hdr.Rrtype

		switch hdr.Class {
		case z.Class:
			// Add record (zone class = INET = 1).
			// D-10: SOA records in the add (zone class) path are silently ignored.
			// Serial auto-increments below; callers must not manage serial via UPDATE.
			if rrtype == dns.TypeSOA {
				continue
			}
			// D-04: CNAME coexistence check — adding a CNAME when other types exist,
			// or adding other types when a CNAME exists, is a protocol violation.
			// WR-03: check runs against clone (the mid-mutation state), not the live zone.
			// RFC 2136 §3.4.2 requires update directives to be applied in order; earlier
			// directives in this message are already reflected in clone, so this check
			// correctly sees the state as it will be after each sequential operation.
			if rrtype == dns.TypeCNAME {
				// If owner already has non-CNAME records, reject.
				for existType := range clone.GetTypeMap(owner) {
					if existType != dns.TypeCNAME {
						sendRcode(dns.RcodeRefused)
						return
					}
				}
			} else {
				// If owner already has a CNAME, reject adding non-CNAME.
				if len(clone.GetRecords(owner, dns.TypeCNAME)) > 0 {
					sendRcode(dns.RcodeRefused)
					return
				}
			}
			if containsRRValue(clone.ExactRecords(owner, rrtype), rr, z.Class) {
				continue
			}
			if err := clone.AddRecord(rr); err != nil {
				sendRcode(dns.RcodeServerFailure)
				return
			}

		case dns.ClassANY:
			if rrtype == dns.TypeANY {
				// Delete all rrsets at name.
				// D-04: deleting all at apex would remove SOA/NS — REFUSED.
				if strings.EqualFold(owner, strings.ToLower(clone.Origin)) {
					sendRcode(dns.RcodeRefused)
					return
				}
				if err := clone.DeleteName(owner); err != nil {
					sendRcode(dns.RcodeServerFailure)
					return
				}
			} else {
				// Delete rrset (all records of this type at owner).
				// D-04: deleting SOA is never allowed.
				if rrtype == dns.TypeSOA {
					sendRcode(dns.RcodeRefused)
					return
				}
				// D-04: deleting all NS at apex would leave zone without nameservers — REFUSED.
				if rrtype == dns.TypeNS && strings.EqualFold(owner, strings.ToLower(clone.Origin)) {
					// CR-03: check the LIVE zone (z) for the floor count, not the mid-mutation
					// clone. Earlier update directives in this message may have added NS records
					// to clone, inflating the count and bypassing this guard incorrectly.
					liveNS := z.GetRecords(owner, dns.TypeNS)
					if len(liveNS) <= 1 {
						sendRcode(dns.RcodeRefused)
						return
					}
				}
				if err := clone.DeleteRRSet(owner, rrtype); err != nil {
					sendRcode(dns.RcodeServerFailure)
					return
				}
			}

		case dns.ClassNONE:
			// Delete specific RR.
			// D-04: deleting the SOA record directly is not allowed.
			if rrtype == dns.TypeSOA {
				sendRcode(dns.RcodeRefused)
				return
			}
			// WR-01: NS floor guard for ClassNONE (delete-specific-RR) path.
			// Parallel to the ClassANY NS guard above — deleting a specific NS at the
			// apex one-by-one must not be allowed to remove the last nameserver.
			// Check against the live zone (z) to avoid mid-mutation clone inflation (CR-03).
			if rrtype == dns.TypeNS && strings.EqualFold(owner, strings.ToLower(z.Origin)) {
				if len(z.GetRecords(owner, dns.TypeNS)) <= 1 {
					sendRcode(dns.RcodeRefused)
					return
				}
			}
			if err := clone.DeleteRecord(rr); err != nil {
				sendRcode(dns.RcodeServerFailure)
				return
			}

		default:
			// Unknown class — ignore (RFC 2136 §3.4.2.3 says to return FORMERR for some,
			// but silently ignoring unknown classes is safe for the clone path).
			sendRcode(dns.RcodeFormatError)
			return
		}
	}

	// 10. Validate the mutated clone (D-05, T-13-07): zone must still be structurally valid.
	// If validation fails the live zone is untouched (no swap).
	if err := clone.Validate(); err != nil {
		sendRcode(dns.RcodeServerFailure)
		return
	}

	// 11. Auto-increment serial (D-09).
	if err := clone.IncrementSerial(); err != nil {
		sendRcode(dns.RcodeServerFailure)
		return
	}

	// 12. Atomic swap: replace the live zone with the validated, serial-incremented clone (D-05, DYNUP-04).
	// CR-01: write lock protects concurrent write to cfg.Zones map.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.zonesMu.Lock()
	s.cfg.Zones[zoneName] = clone
	s.zonesMu.Unlock()

	// 13. updateMu released by defer above.

	// 14. Reply NOERROR.
	// CR-04: RFC 2845 §3.2 requires the response to be TSIG-signed when the request was
	// TSIG-authenticated. Sign using the same key that authenticated the request.
	m := new(dns.Msg)
	m.SetReply(r)
	if reqTsig := r.IsTsig(); reqTsig != nil {
		m.SetTsig(reqTsig.Hdr.Name, reqTsig.Algorithm, reqTsig.Fudge, time.Now().Unix())
	}
	w.WriteMsg(m) //nolint:errcheck

	// 15. Persist to disk if configured (D-11, D-14).
	// WR-04: run in a goroutine so blocking disk I/O does not hold z.Lock() (released
	// by defer above when handleUpdate returns) and does not stall subsequent UPDATE
	// clients waiting on the zone lock. The in-memory swap already succeeded; the
	// acknowledged trade-off (D-14) is that a crash between reply and persist leaves
	// the zone file one serial behind the response already sent to the client.
	s.persistZone(zoneName, clone)
}

// persistZone writes the zone to disk if a persist path is configured for it (D-11, D-13).
// This is a no-op if persistPaths is empty or the zone has no configured path (D-12).
// Write errors are intentionally non-fatal: the in-memory UPDATE already succeeded (D-14).
// Only the path already configured in zone config File field is used — no user-controlled
// path injection is possible (T-13-12).
func (s *Server) persistZone(zoneName string, z *zone.Zone) {
	if len(s.persistPaths) == 0 {
		return
	}
	path, ok := s.persistPaths[zoneName]
	if !ok || path == "" {
		return
	}

	data, err := zone.SerializeDNSZone(z)
	if err != nil {
		fmt.Fprintf(os.Stderr, "persist_updates: serialize zone %s: %v\n", zoneName, err)
		return
	}

	// Write atomically: write to a temp file then rename over the target.
	// This prevents a partial-write from leaving a corrupt zone file (T-13-12).
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "persist_updates: write zone %s to %s: %v\n", zoneName, tmpPath, err)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		fmt.Fprintf(os.Stderr, "persist_updates: rename %s → %s: %v\n", tmpPath, path, err)
		_ = os.Remove(tmpPath) // best-effort cleanup
	}
}
