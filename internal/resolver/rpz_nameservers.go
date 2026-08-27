package resolver

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"github.com/afterdarksys/dnsscienced/internal/engine"
	"github.com/miekg/dns"
)

const absoluteMaxRPZNameserverLookups = 256

// DiscoverRPZNameservers walks the ancestor names of every truthful answer
// RRset and obtains their NS data. This follows the RPZ specification's
// permitted "check parent domains" strategy and uses Recursive.Query so normal
// cache, singleflight, DNSSEC, timeout, and worker-pool controls still apply.
func (r *Recursive) DiscoverRPZNameservers(
	ctx context.Context,
	response *dns.Msg,
	needAddresses bool,
	minNSDots int,
	maxLookups int,
) *engine.RPZNameserverData {
	return discoverRPZNameservers(
		ctx,
		response,
		needAddresses,
		minNSDots,
		maxLookups,
		r.Query,
	)
}

type rpzQueryFunc func(context.Context, string, uint16) (*dns.Msg, error)

func discoverRPZNameservers(
	ctx context.Context,
	response *dns.Msg,
	needAddresses bool,
	minNSDots int,
	maxLookups int,
	query rpzQueryFunc,
) *engine.RPZNameserverData {
	result := &engine.RPZNameserverData{}
	if response == nil {
		return result
	}
	if minNSDots < 0 {
		minNSDots = 0
	}
	if maxLookups < 1 || maxLookups > absoluteMaxRPZNameserverLookups {
		maxLookups = absoluteMaxRPZNameserverLookups
	}

	names := make(map[string]struct{})
	addresses := make(map[netip.Addr]struct{})
	lookupCount := 0
	collectRPZNSRecords(response, "", names, addresses)

	owners := rpzAnswerOwners(response)
	ancestors := make(map[string]struct{})
	orderedAncestors := make([]string, 0)
	for _, owner := range owners {
		for ancestor := owner; ; ancestor = rpzParentName(ancestor) {
			if dns.CountLabel(ancestor) < minNSDots {
				break
			}
			if _, exists := ancestors[ancestor]; !exists {
				ancestors[ancestor] = struct{}{}
				orderedAncestors = append(orderedAncestors, ancestor)
			}
			if ancestor == "." || len(orderedAncestors) >= maxLookups {
				break
			}
		}
		if len(orderedAncestors) >= maxLookups {
			break
		}
	}

	for _, ancestor := range orderedAncestors {
		if lookupCount >= maxLookups {
			break
		}
		if err := ctx.Err(); err != nil {
			break
		}
		lookupCount++
		nsResponse, err := query(ctx, ancestor, dns.TypeNS)
		if err != nil {
			continue
		}
		collectRPZNSRecords(nsResponse, ancestor, names, addresses)
	}

	if needAddresses {
		orderedNames := make([]string, 0, len(names))
		for name := range names {
			orderedNames = append(orderedNames, name)
		}
		sort.Strings(orderedNames)
	addressLoop:
		for _, name := range orderedNames {
			if lookupCount >= maxLookups {
				break
			}
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if lookupCount >= maxLookups {
					break addressLoop
				}
				if err := ctx.Err(); err != nil {
					break addressLoop
				}
				lookupCount++
				addressResponse, err := query(ctx, name, qtype)
				if err != nil {
					continue
				}
				collectRPZAnswerAddresses(addressResponse.Answer, addresses)
			}
		}
	}

	result.Names = make([]string, 0, len(names))
	for name := range names {
		result.Names = append(result.Names, name)
	}
	sort.Strings(result.Names)
	result.Addresses = make([]netip.Addr, 0, len(addresses))
	for address := range addresses {
		result.Addresses = append(result.Addresses, address)
	}
	sort.Slice(result.Addresses, func(i, j int) bool {
		return result.Addresses[i].Compare(result.Addresses[j]) < 0
	})
	return result
}

func rpzAnswerOwners(response *dns.Msg) []string {
	seen := make(map[string]struct{})
	owners := make([]string, 0)
	for _, rr := range response.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeOPT:
			continue
		}
		owner := dns.Fqdn(strings.ToLower(rr.Header().Name))
		if _, exists := seen[owner]; exists {
			continue
		}
		seen[owner] = struct{}{}
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	return owners
}

func rpzParentName(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

func collectRPZNSRecords(
	response *dns.Msg,
	owner string,
	names map[string]struct{},
	addresses map[netip.Addr]struct{},
) {
	if response == nil {
		return
	}
	owner = dns.Fqdn(strings.ToLower(owner))
	discovered := make([]string, 0)
	for _, section := range [][]dns.RR{response.Answer, response.Ns} {
		for _, rr := range section {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			if owner != "." && !strings.EqualFold(ns.Header().Name, owner) {
				continue
			}
			name := dns.Fqdn(strings.ToLower(ns.Ns))
			names[name] = struct{}{}
			discovered = append(discovered, name)
		}
	}
	for _, name := range discovered {
		collectRPZAddresses(response.Extra, name, addresses)
	}
}

func collectRPZAddresses(records []dns.RR, owner string, addresses map[netip.Addr]struct{}) {
	for _, rr := range records {
		if !strings.EqualFold(rr.Header().Name, owner) {
			continue
		}
		var address netip.Addr
		switch record := rr.(type) {
		case *dns.A:
			parsed, ok := netip.AddrFromSlice(record.A.To4())
			if !ok {
				continue
			}
			address = parsed
		case *dns.AAAA:
			parsed, ok := netip.AddrFromSlice(record.AAAA)
			if !ok {
				continue
			}
			address = parsed
		default:
			continue
		}
		addresses[address.Unmap()] = struct{}{}
	}
}

func collectRPZAnswerAddresses(records []dns.RR, addresses map[netip.Addr]struct{}) {
	for _, rr := range records {
		var address netip.Addr
		switch record := rr.(type) {
		case *dns.A:
			parsed, ok := netip.AddrFromSlice(record.A.To4())
			if !ok {
				continue
			}
			address = parsed
		case *dns.AAAA:
			parsed, ok := netip.AddrFromSlice(record.AAAA)
			if !ok {
				continue
			}
			address = parsed
		default:
			continue
		}
		addresses[address.Unmap()] = struct{}{}
	}
}
