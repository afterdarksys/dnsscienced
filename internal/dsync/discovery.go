package dsync

import (
	"context"
	"strings"

	"github.com/miekg/dns"
)

// DiscoverDSYNC queries _dsync.<delegation> and parent labels for DSYNC records
// per the RFC 9859 §3 discovery algorithm.
//
// It tries _dsync.<delegation>, then _dsync.<parent>, etc., stopping when records
// are found or all labels have been tried. Returns all DSYNCRecord values found;
// empty result is not an error.
//
// Security (T-08-05): the loop is bounded by len(labels)-1 so it cannot exceed
// the number of labels in the delegation name. context.WithTimeout is the caller's
// responsibility for bounding total wall time.
func DiscoverDSYNC(ctx context.Context, delegation string, client *dns.Client, resolver string) ([]DSYNCRecord, error) {
	labels := dns.SplitDomainName(dns.Fqdn(delegation))
	// Try _dsync.<delegation>, then _dsync.<parent>, etc.
	// Stop at len(labels)-1 to avoid querying _dsync.<TLD-only>.
	for i := 0; i < len(labels)-1; i++ {
		suffix := strings.Join(labels[i:], ".") + "."
		candidate := "_dsync." + suffix
		records, err := queryDSYNC(ctx, candidate, client, resolver)
		if err == nil && len(records) > 0 {
			return records, nil
		}
	}
	return nil, nil
}

// queryDSYNC sends a TYPE66 (DSYNC) query and decodes any DSYNC records in the answer.
// Malformed records are silently skipped.
func queryDSYNC(ctx context.Context, name string, client *dns.Client, resolver string) ([]DSYNCRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, TypeDSYNC)
	m.RecursionDesired = true

	resp, _, err := client.ExchangeContext(ctx, m, resolver)
	if err != nil {
		return nil, err
	}

	var results []DSYNCRecord
	for _, rr := range resp.Answer {
		r3, ok := rr.(*dns.RFC3597)
		if !ok || r3.Hdr.Rrtype != TypeDSYNC {
			continue
		}
		rec, err := ParseRFC3597(r3)
		if err != nil {
			continue // skip malformed records (T-08-04)
		}
		// RFC 9859: receivers MUST ignore records with Scheme=0 or Port=0.
		if rec.Scheme == DSYNCSchemeNull || rec.Port == 0 {
			continue
		}
		results = append(results, rec)
	}
	return results, nil
}
