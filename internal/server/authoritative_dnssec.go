package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func requestWantsDNSSEC(request *dns.Msg) bool {
	opt := request.IsEdns0()
	return opt != nil && opt.Do()
}

func appendCoveringSignatures(records []dns.RR, z *zone.Zone) []dns.RR {
	if len(records) == 0 {
		return records
	}
	result := append([]dns.RR(nil), records...)
	seen := make(map[string]struct{})
	for _, rr := range records {
		header := rr.Header()
		key := strings.ToLower(dns.Fqdn(header.Name)) + "/" + fmt.Sprint(header.Rrtype)
		if _, exists := seen[key]; exists || header.Rrtype == dns.TypeRRSIG {
			continue
		}
		seen[key] = struct{}{}
		for _, candidate := range z.ExactRecords(header.Name, dns.TypeRRSIG) {
			signature, ok := candidate.(*dns.RRSIG)
			if ok && signature.TypeCovered == header.Rrtype {
				result = append(result, signature)
			}
		}
	}
	return result
}

func appendAuthoritativeDenial(
	authority []dns.RR,
	z *zone.Zone,
	qname string,
	nameExists bool,
) []dns.RR {
	proofs := make([]dns.RR, 0, 2)
	if nameExists {
		proofs = append(proofs, z.ExactRecords(qname, dns.TypeNSEC)...)
	} else {
		if proof := coveringNSEC(z, qname); proof != nil {
			proofs = append(proofs, proof)
		}
		closest := closestEncloser(z, qname)
		if proof := coveringNSEC(z, "*."+closest); proof != nil && !containsRR(proofs, proof) {
			proofs = append(proofs, proof)
		}
	}
	proofs = appendCoveringSignatures(proofs, z)
	return append(authority, proofs...)
}

func closestEncloser(z *zone.Zone, qname string) string {
	labels := dns.SplitDomainName(qname)
	for i := 0; i <= len(labels); i++ {
		candidate := "."
		if i < len(labels) {
			candidate = dns.Fqdn(strings.Join(labels[i:], "."))
		}
		if z.HasName(candidate) {
			return candidate
		}
	}
	return z.Origin
}

func coveringNSEC(z *zone.Zone, name string) dns.RR {
	name = strings.ToLower(dns.Fqdn(name))
	for _, typeMap := range z.Records {
		for _, rr := range typeMap[dns.TypeNSEC] {
			nsec, ok := rr.(*dns.NSEC)
			if !ok {
				continue
			}
			owner := strings.ToLower(dns.Fqdn(nsec.Hdr.Name))
			next := strings.ToLower(dns.Fqdn(nsec.NextDomain))
			if owner == name || nsecIntervalContains(owner, next, name) {
				return nsec
			}
		}
	}
	return nil
}

func nsecIntervalContains(owner, next, name string) bool {
	ownerBeforeNext := canonicalDNSNameLess(owner, next)
	if ownerBeforeNext {
		return canonicalDNSNameLess(owner, name) && canonicalDNSNameLess(name, next)
	}
	// The final NSEC in canonical order wraps back to the first owner.
	return canonicalDNSNameLess(owner, name) || canonicalDNSNameLess(name, next)
}

func canonicalDNSNameLess(left, right string) bool {
	leftLabels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(left)))
	rightLabels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(right)))
	for li, ri := len(leftLabels)-1, len(rightLabels)-1; li >= 0 && ri >= 0; li, ri = li-1, ri-1 {
		if leftLabels[li] == rightLabels[ri] {
			continue
		}
		return leftLabels[li] < rightLabels[ri]
	}
	return len(leftLabels) < len(rightLabels)
}

func containsRR(records []dns.RR, candidate dns.RR) bool {
	for _, rr := range records {
		if rr.String() == candidate.String() {
			return true
		}
	}
	return false
}

// ValidateRootAuthoritativeZone verifies the minimum signed-zone material
// required before a local-root or public-root profile opens listeners.
func (s *Server) ValidateRootAuthoritativeZone() error {
	s.zonesMu.RLock()
	defer s.zonesMu.RUnlock()
	if len(s.cfg.Zones) != 1 {
		return fmt.Errorf("root service requires exactly one loaded zone")
	}
	root := s.cfg.Zones["."]
	if root == nil || strings.ToLower(dns.Fqdn(root.Origin)) != "." {
		return fmt.Errorf("root service requires the loaded zone origin .")
	}
	required := []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeNSEC}
	for _, rrtype := range required {
		records := root.ExactRecords(".", rrtype)
		if len(records) == 0 {
			return fmt.Errorf("root zone is missing %s records at the apex", dns.TypeToString[rrtype])
		}
		if rrtype == dns.TypeNSEC {
			continue
		}
		if !hasCoveringSignature(root, ".", rrtype) {
			return fmt.Errorf("root zone is missing an RRSIG covering apex %s", dns.TypeToString[rrtype])
		}
	}
	for owner, typeMap := range root.Records {
		if len(typeMap[dns.TypeNSEC]) > 0 && !hasCoveringSignature(root, owner, dns.TypeNSEC) {
			return fmt.Errorf("root zone owner %s has unsigned NSEC denial data", owner)
		}
		if len(typeMap[dns.TypeDS]) > 0 && !hasCoveringSignature(root, owner, dns.TypeDS) {
			return fmt.Errorf("root delegation %s has unsigned DS data", owner)
		}
	}
	return nil
}

func hasCoveringSignature(z *zone.Zone, owner string, rrtype uint16) bool {
	for _, rr := range z.ExactRecords(owner, dns.TypeRRSIG) {
		signature, ok := rr.(*dns.RRSIG)
		if ok &&
			signature.TypeCovered == rrtype &&
			strings.EqualFold(signature.SignerName, ".") &&
			signature.ValidityPeriod(time.Now()) {
			return true
		}
	}
	return false
}
