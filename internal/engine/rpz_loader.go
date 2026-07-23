package engine

import (
	"fmt"
	"strings"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

// LoadRPZFile parses a BIND or DNSZone policy zone and converts its QNAME
// CNAME policies into an in-memory RPZ. The supported targets follow RFC 1034
// RPZ conventions: ".", "*.", "rpz-passthru.", "rpz-drop.", or a rewrite
// target.
func LoadRPZFile(name, filename, reason string) (*RPZ, error) {
	parsed, err := zone.ParseZoneFile(filename, zone.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("parse RPZ file: %w", err)
	}
	if parsed.Origin == "" {
		return nil, fmt.Errorf("RPZ file has no origin")
	}
	if reason == "" {
		reason = name
	}

	rpz := NewRPZ(name)
	ruleCount := 0
	owners := make(map[string]struct{})
	origin := strings.ToLower(dns.Fqdn(parsed.Origin))
	for _, rr := range parsed.GetAllRecords() {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}

		owner := strings.ToLower(dns.Fqdn(cname.Hdr.Name))
		if !dns.IsSubDomain(origin, owner) || owner == origin {
			continue
		}
		relative := strings.TrimSuffix(owner, origin)
		relative = strings.TrimSuffix(relative, ".")
		if relative == "" {
			continue
		}
		if isUnsupportedRPZTrigger(relative) {
			return nil, fmt.Errorf("unsupported RPZ trigger %q", owner)
		}
		if _, duplicate := owners[owner]; duplicate {
			return nil, fmt.Errorf("multiple CNAME policies for RPZ owner %q", owner)
		}
		owners[owner] = struct{}{}

		wildcard := strings.HasPrefix(relative, "*.")
		trigger := strings.TrimPrefix(relative, "*.")
		target := strings.ToLower(dns.Fqdn(cname.Target))

		var action RPZAction
		var rewriteTarget string
		switch target {
		case ".":
			action = RPZActionNXDomain
		case "*.":
			action = RPZActionNoData
		case "rpz-passthru.":
			action = RPZActionPassthru
		case "rpz-drop.":
			action = RPZActionDrop
		default:
			action = RPZActionRewrite
			rewriteTarget = target
		}

		rpz.addRule(trigger, action, rewriteTarget, reason, filename, wildcard, wildcard)
		ruleCount++
	}

	if ruleCount == 0 {
		return nil, fmt.Errorf("RPZ file contains no supported QNAME policies")
	}
	return rpz, nil
}

func isUnsupportedRPZTrigger(relative string) bool {
	for _, suffix := range []string{
		"rpz-ip",
		"rpz-client-ip",
		"rpz-nsip",
		"rpz-nsdname",
	} {
		if relative == suffix || strings.HasSuffix(relative, "."+suffix) {
			return true
		}
	}
	return false
}
