package dsync

import (
	"fmt"
	"net"
)

// SourceACL validates inbound NOTIFY source IPs against a CIDR allowlist.
// Satisfies the Allower interface defined in handler.go.
// A nil or empty allowlist means all sources are accepted (per D-05).
type SourceACL struct {
	networks []*net.IPNet
	allowAll bool
}

// Compile-time interface assertion.
var _ Allower = (*SourceACL)(nil)

// NewSourceACL creates an ACL from CIDR strings (e.g., "10.0.0.0/8") or single
// IPs (e.g., "203.0.113.5" treated as /32 or /128). Empty/nil = allow all.
//
// Returns an error if any entry in cidrs is invalid. This prevents a
// misconfigured ACL (e.g., a typo in a CIDR) from silently falling back to
// allow-all behavior.
func NewSourceACL(cidrs []string) (*SourceACL, error) {
	if len(cidrs) == 0 {
		return &SourceACL{allowAll: true}, nil
	}
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as single IP (e.g., "203.0.113.5" → /32 or /128)
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("invalid CIDR/IP in allowed_sources: %q", cidr)
			}
			if ip.To4() != nil {
				_, network, _ = net.ParseCIDR(cidr + "/32")
			} else {
				_, network, _ = net.ParseCIDR(cidr + "/128")
			}
		}
		if network != nil {
			nets = append(nets, network)
		}
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("allowed_sources: all %d entries were invalid", len(cidrs))
	}
	return &SourceACL{networks: nets}, nil
}

// Check returns true if the IP is allowed. Satisfies Allower interface.
func (a *SourceACL) Check(ip net.IP) bool {
	if a.allowAll {
		return true
	}
	for _, n := range a.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
