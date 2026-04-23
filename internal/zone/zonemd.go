package zone

import (
	"crypto/sha512"
	"fmt"
	"sort"

	"github.com/miekg/dns"
)

// ZONEMD scheme and hash algorithm constants per RFC 8976.
const (
	ZONEMDSchemeSimple = 1 // Simple hash: canonically sorted wire-format RRs

	ZONEMDHashSHA384 = 1 // SHA-384 (mandatory per RFC 8976)
	ZONEMDHashSHA512 = 2 // SHA-512
)

// VerifyZONEMD checks zone integrity against its ZONEMD record (RFC 8976).
// Returns nil when the digest matches or when no ZONEMD RR is present.
// A mismatch means the zone was tampered with or corrupted in transit.
//
// NSD 4.3.0+ performs this check automatically at zone load time and refuses
// to serve zones that fail verification.
func VerifyZONEMD(z *Zone) error {
	if z == nil {
		return nil
	}

	// Collect all RRs from the zone into a flat slice.
	var allRRs []dns.RR
	for _, byType := range z.Records {
		for _, rrs := range byType {
			allRRs = append(allRRs, rrs...)
		}
	}
	// Include SOA if present.
	if z.SOA != nil {
		allRRs = append(allRRs, z.SOA)
	}

	// Find ZONEMD RR(s).
	var zonemdRRs []*dns.ZONEMD
	for _, rr := range allRRs {
		if zmd, ok := rr.(*dns.ZONEMD); ok {
			zonemdRRs = append(zonemdRRs, zmd)
		}
	}

	if len(zonemdRRs) == 0 {
		return nil // No ZONEMD present — nothing to verify.
	}

	for _, zmd := range zonemdRRs {
		if err := verifyOne(allRRs, zmd); err != nil {
			return fmt.Errorf("ZONEMD verification failed (scheme=%d alg=%d serial=%d): %w",
				zmd.Scheme, zmd.Hash, zmd.Serial, err)
		}
	}

	return nil
}

// verifyOne verifies a single ZONEMD record.
func verifyOne(allRRs []dns.RR, zmd *dns.ZONEMD) error {
	if zmd.Scheme != ZONEMDSchemeSimple {
		return fmt.Errorf("unsupported ZONEMD scheme %d (only scheme 1 / Simple is supported)", zmd.Scheme)
	}

	computed, err := computeDigest(allRRs, zmd, zmd.Hash)
	if err != nil {
		return err
	}

	if len(computed) != len(zmd.Digest) {
		return fmt.Errorf("digest length mismatch: got %d bytes, want %d", len(computed), len(zmd.Digest))
	}
	for i := range computed {
		if computed[i] != zmd.Digest[i] {
			return fmt.Errorf("digest mismatch: zone may have been tampered with or corrupted")
		}
	}

	return nil
}

// computeDigest computes the RFC 8976 §4 Simple hash over the zone's RRs.
//
// Steps per RFC 8976 §4.3.1:
//  1. Exclude the ZONEMD RR being verified and any RRSIGs that cover ZONEMD.
//  2. Sort remaining RRs in RFC 4034 §6.3 canonical wire order.
//  3. For each RR, zero its TTL, pack to wire format, feed into the hash.
func computeDigest(allRRs []dns.RR, target *dns.ZONEMD, hashAlg uint8) ([]byte, error) {
	// Build eligible set: exclude the target ZONEMD and its covering RRSIGs.
	eligible := make([]dns.RR, 0, len(allRRs))
	for _, rr := range allRRs {
		if rr == target {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
			continue
		}
		eligible = append(eligible, rr)
	}

	// Sort: canonical name order (right-to-left labels), then by type, then by rdata.
	sort.Slice(eligible, func(i, j int) bool {
		ni := dns.CanonicalName(eligible[i].Header().Name)
		nj := dns.CanonicalName(eligible[j].Header().Name)
		if ni != nj {
			return zonemdNameLess(ni, nj)
		}
		ti := eligible[i].Header().Rrtype
		tj := eligible[j].Header().Rrtype
		if ti != tj {
			return ti < tj
		}
		// Same name+type: compare wire-format rdata.
		bi, _ := packRRWire(eligible[i])
		bj, _ := packRRWire(eligible[j])
		return string(bi) < string(bj)
	})

	switch hashAlg {
	case ZONEMDHashSHA384:
		h := sha512.New384()
		if err := feedRRs(h, eligible); err != nil {
			return nil, err
		}
		return h.Sum(nil), nil

	case ZONEMDHashSHA512:
		h := sha512.New()
		if err := feedRRs(h, eligible); err != nil {
			return nil, err
		}
		return h.Sum(nil), nil

	default:
		return nil, fmt.Errorf("unsupported ZONEMD hash algorithm %d", hashAlg)
	}
}

// feedRRs writes each RR's wire representation (with TTL zeroed) into h.
func feedRRs(h interface{ Write([]byte) (int, error) }, rrs []dns.RR) error {
	for _, rr := range rrs {
		wire, err := packRRWire(rr)
		if err != nil {
			return fmt.Errorf("packing RR %s/%d: %w", rr.Header().Name, rr.Header().Rrtype, err)
		}
		if _, err := h.Write(wire); err != nil {
			return err
		}
	}
	return nil
}

// packRRWire returns the wire-format bytes of rr with TTL zeroed, as required
// by RFC 8976 §4.3.1 so that TTL differences do not affect the digest.
func packRRWire(rr dns.RR) ([]byte, error) {
	// Clone header so we don't mutate the live RR.
	origTTL := rr.Header().Ttl
	rr.Header().Ttl = 0
	defer func() { rr.Header().Ttl = origTTL }()

	buf := make([]byte, dns.MaxMsgSize)
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

// zonemdNameLess implements RFC 4034 §6.1 canonical DNS name ordering
// (label-by-label, rightmost first, case-insensitive).
func zonemdNameLess(a, b string) bool {
	aLabels := dns.SplitDomainName(a)
	bLabels := dns.SplitDomainName(b)

	// Reverse so index 0 is the TLD.
	for i, j := 0, len(aLabels)-1; i < j; i, j = i+1, j-1 {
		aLabels[i], aLabels[j] = aLabels[j], aLabels[i]
	}
	for i, j := 0, len(bLabels)-1; i < j; i, j = i+1, j-1 {
		bLabels[i], bLabels[j] = bLabels[j], bLabels[i]
	}

	for i := 0; i < len(aLabels) && i < len(bLabels); i++ {
		if aLabels[i] < bLabels[i] {
			return true
		}
		if aLabels[i] > bLabels[i] {
			return false
		}
	}
	return len(aLabels) < len(bLabels)
}
