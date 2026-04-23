package cache

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// RebindingGuard implements DNS rebinding protection (Unbound private-address feature).
//
// Prevents attacker-controlled public domains from resolving to RFC-1918 / link-local
// addresses, which would allow browser-based attacks to reach internal network services
// via the same-origin policy.
//
// Reference: Unbound private-address / private-domain directives.
type RebindingGuard struct {
	privateRanges  []*net.IPNet
	privateDomains []string // domains legitimately allowed to resolve to private IPs
}

// defaultPrivateRanges matches Unbound's defaults: all RFC-1918, loopback, link-local, ULA.
var defaultPrivateRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16", // IPv4 link-local
	"127.0.0.0/8",    // loopback
	"0.0.0.0/8",      // "this" network
	"::1/128",         // IPv6 loopback
	"fd00::/8",        // IPv6 ULA
	"fe80::/10",       // IPv6 link-local
}

// NewRebindingGuard creates a guard with the given private address ranges.
// If privateAddresses is empty, the default RFC-1918 + link-local ranges are used.
func NewRebindingGuard(privateAddresses []string, privateDomains []string) *RebindingGuard {
	if len(privateAddresses) == 0 {
		privateAddresses = defaultPrivateRanges
	}

	var ranges []*net.IPNet
	for _, cidr := range privateAddresses {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			ranges = append(ranges, ipnet)
		}
	}

	return &RebindingGuard{
		privateRanges:  ranges,
		privateDomains: privateDomains,
	}
}

// isExemptDomain returns true if qname is in the private-domain whitelist,
// meaning it is legitimately expected to resolve to a private IP.
func (g *RebindingGuard) isExemptDomain(qname string) bool {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, d := range g.privateDomains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if qname == d || strings.HasSuffix(qname, "."+d) {
			return true
		}
	}
	return false
}

// isPrivateIP returns true if the IP falls within any configured private range.
func (g *RebindingGuard) isPrivateIP(ip net.IP) bool {
	for _, r := range g.privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// IsSafe inspects a DNS response for rebinding attempts.
// Returns false when the response for a public name contains a private IP —
// the caller must discard the response rather than caching or serving it.
func (g *RebindingGuard) IsSafe(msg *dns.Msg, qname string) bool {
	if g.isExemptDomain(qname) {
		return true
	}

	for _, rr := range msg.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if g.isPrivateIP(r.A) {
				return false
			}
		case *dns.AAAA:
			if g.isPrivateIP(r.AAAA) {
				return false
			}
		}
	}
	return true
}
