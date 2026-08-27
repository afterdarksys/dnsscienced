package server

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/zone"
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
//  2. TSIG validity (D-16): bad key/MAC/time → NOTAUTH
//  3. Empty Zone section guard → FORMERR
//  4. Zone lookup: unknown zone → REFUSED
//  5. Per-zone TSIG identity authorization: absent/unlisted key → REFUSED
//  6. ACL check (D-15, D-17): nil ACL (no allow_update) or IP not allowed → REFUSED
//  7. Zone containment: out-of-zone prerequisite/update owner → NOTZONE
//  8. Reserve the authenticated request MAC; coalesce exact replays
//  9. Lock the stable server mutation boundary and re-read the live zone
//  10. Evaluate prerequisites (r.Answer) against live zone
//  11. Clone live zone
//  12. Apply Update section (r.Ns) to clone
//  13. clone.Validate() → SERVFAIL on failure
//  14. clone.IncrementSerial()
//  15. Durably persist when configured
//  16. Atomic swap: s.cfg.Zones[zoneName] = clone
//  17. Reply NOERROR
func (s *Server) handleUpdate(w dns.ResponseWriter, r *dns.Msg, clientIP net.IP) {
	var replayReservation *updateReplayEntry
	// Local helper to send an error rcode without the pooled message path.
	sendRcode := func(rcode int) {
		if replayReservation != nil {
			s.updateReplay.finishUpdate(replayReservation, rcode)
			replayReservation = nil
		}
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

	// 2. TSIG validity check (D-16): bad key, MAC, time, or truncation.
	if verificationErr := w.TsigStatus(); verificationErr != nil {
		writeTSIGVerificationError(w, r, verificationErr)
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
	zoneName := strings.ToLower(dns.Fqdn(r.Question[0].Name))
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

	// 5. A globally valid TSIG key is authenticated, but it is authorized only
	// for zones that name it explicitly.
	reqTSIG := r.IsTsig()
	allowedKeys := s.zoneUpdateKeys[zoneName]
	keyName := strings.ToLower(dns.Fqdn(reqTSIG.Hdr.Name))
	if _, allowed := allowedKeys[keyName]; !allowed {
		sendRcode(dns.RcodeRefused)
		return
	}

	// 6. ACL check (D-15, D-17):
	//    nil ACL = no allow_update configured = deny all (secure-by-default).
	//    non-nil ACL = source IP must be in the allowlist.
	acl := s.zoneUpdateACLs[zoneName]
	if acl == nil || !acl.Check(clientIP) {
		sendRcode(dns.RcodeRefused)
		return
	}

	// 7. RFC 2136 §3.1 requires every prerequisite and update owner name to
	// belong to the Zone section. Reject the complete transaction before
	// evaluating prerequisites or cloning so no partial effect is possible.
	for _, section := range [][]dns.RR{r.Answer, r.Ns} {
		for _, rr := range section {
			if rr == nil || !dns.IsSubDomain(zoneName, strings.ToLower(dns.Fqdn(rr.Header().Name))) {
				sendRcode(dns.RcodeNotZone)
				return
			}
		}
	}

	// RFC 2136 §5 permits duplicate delivery and explicitly identifies malicious
	// duplication as a replay attack. TSIG's time window rejects old packets but
	// permits an exact captured request during the Fudge interval. Reserve the
	// authenticated request MAC before mutation. A duplicate waits for the first
	// transaction and receives its rcode without applying the UPDATE again.
	entry, duplicate, saturated := s.updateReplay.beginUpdate(reqTSIG, time.Now())
	if duplicate {
		s.updateReplays.Add(1)
		updateReplaysTotal.Inc()
		sendRcode(entry.wait())
		return
	}
	if saturated {
		s.updateReplayFull.Add(1)
		updateReplaySaturatedTotal.Inc()
		sendRcode(dns.RcodeServerFailure)
		return
	}
	replayReservation = entry
	defer func() {
		if replayReservation != nil {
			s.updateReplay.finishUpdate(replayReservation, dns.RcodeServerFailure)
		}
	}()

	// 9. Serialize against every zone-map mutation using a lock owned by the
	// server rather than by the Zone object. A successful UPDATE replaces that
	// object, so locking z.updateMu would allow requests that captured the old
	// pointer to overwrite a newer generation. Re-read after locking to make
	// prerequisite evaluation and commit linearizable with AddZone and batches.
	s.persistMu.Lock()
	mutationLocked := true
	defer func() {
		if mutationLocked {
			s.persistMu.Unlock()
		}
	}()
	s.zonesMu.RLock()
	z, ok = s.cfg.Zones[zoneName]
	s.zonesMu.RUnlock()
	if !ok || z == nil {
		sendRcode(dns.RcodeRefused)
		return
	}

	// 10. Evaluate prerequisites (r.Answer = PREREQUISITE section per RFC 2136 §2).
	// Evaluated against the LIVE zone (before cloning) so that concurrent updates
	// are correctly serialized.  Any failure → return error rcode; zero updates applied (D-03).
	if rcode, ok := evaluatePrereqs(r.Answer, z); !ok {
		sendRcode(rcode)
		return
	}

	// 11. Clone the live zone. All mutations are applied to the clone only.
	// The live zone remains readable and consistent until the atomic swap (D-05, T-13-07).
	clone := z.Clone()

	// 12. Apply Update section (r.Ns = UPDATE section per RFC 2136 §2).
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

	// 13. Validate the mutated clone (D-05, T-13-07): zone must still be structurally valid.
	// If validation fails the live zone is untouched (no swap).
	if err := clone.Validate(); err != nil {
		sendRcode(dns.RcodeServerFailure)
		return
	}

	// 14. Auto-increment serial (D-09).
	if err := clone.IncrementSerial(); err != nil {
		sendRcode(dns.RcodeServerFailure)
		return
	}

	// 15. For a persistent primary, make the replacement durable before it can
	// be published or acknowledged. A write, fsync, rename, and directory fsync
	// form the commit boundary. Failure leaves the live zone and IXFR journal
	// untouched and returns SERVFAIL.
	if err := s.persistZone(zoneName, clone); err != nil {
		fmt.Fprintf(os.Stderr, "persist_updates: commit zone %s: %v\n", zoneName, err)
		sendRcode(dns.RcodeServerFailure)
		return
	}

	// 16. Atomic swap: replace the live zone with the validated,
	// serial-incremented clone (D-05, DYNUP-04).
	s.ixfrJournal.Record(z, clone)
	s.zonesMu.Lock()
	s.cfg.Zones[zoneName] = clone
	s.zonesMu.Unlock()
	s.persistMu.Unlock()
	mutationLocked = false

	// 17. Reply NOERROR.
	// CR-04: RFC 2845 §3.2 requires the response to be TSIG-signed when the request was
	// TSIG-authenticated. Sign using the same key that authenticated the request.
	m := new(dns.Msg)
	m.SetReply(r)
	if reqTsig := r.IsTsig(); reqTsig != nil {
		m.SetTsig(reqTsig.Hdr.Name, reqTsig.Algorithm, reqTsig.Fudge, time.Now().Unix())
	}
	if replayReservation != nil {
		s.updateReplay.finishUpdate(replayReservation, dns.RcodeSuccess)
		replayReservation = nil
	}
	w.WriteMsg(m) //nolint:errcheck

	if s.primaryNotifier != nil {
		_ = s.primaryNotifier.Notify(zoneName, clone.SOA)
	}
}

// persistZone writes the zone to disk if a persist path is configured for it (D-11, D-13).
// This is a no-op if persistPaths is empty or the zone has no configured path (D-12).
// Only the path already configured in zone config File field is used — no user-controlled
// path injection is possible (T-13-12).
func (s *Server) persistZone(zoneName string, z *zone.Zone) error {
	if len(s.persistPaths) == 0 {
		return nil
	}
	path, ok := s.persistPaths[zoneName]
	if !ok || path == "" {
		return nil
	}

	data, err := zone.SerializeDNSZone(z)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	directoryPath := filepath.Dir(path)
	file, err := os.CreateTemp(directoryPath, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("open temporary file: %w", err)
	}
	tmpPath := file.Name()
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	written, err := file.Write(data)
	if err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if written != len(data) {
		return fmt.Errorf("write temporary file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temporary file: %w", err)
	}
	cleanup = false

	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return nil
}
