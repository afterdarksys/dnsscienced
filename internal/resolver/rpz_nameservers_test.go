package resolver

import (
	"context"
	"net"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

func TestDiscoverRPZNameserversWalksAnswerOwnerAncestors(t *testing.T) {
	response := new(dns.Msg)
	response.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "www.child.example.", Rrtype: dns.TypeCNAME},
			Target: "target.other.example.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "target.other.example.", Rrtype: dns.TypeA},
			A:   net.ParseIP("203.0.113.8"),
		},
	}
	queries := make([]string, 0)
	query := func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		queries = append(queries, name+"/"+dns.TypeToString[qtype])
		result := new(dns.Msg)
		if qtype == dns.TypeNS && name == "child.example." {
			result.Answer = []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS},
				Ns:  "ns.child.example.",
			}}
			result.Extra = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "ns.child.example.", Rrtype: dns.TypeA},
				A:   net.ParseIP("192.0.2.53"),
			}}
		}
		if qtype == dns.TypeNS && name == "other.example." {
			result.Answer = []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS},
				Ns:  "ns.other.net.",
			}}
		}
		if qtype == dns.TypeA && name == "ns.other.net." {
			result.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA},
				A:   net.ParseIP("198.51.100.53"),
			}}
		}
		return result, nil
	}

	data := discoverRPZNameservers(context.Background(), response, true, 2, 64, query)
	if !slices.Contains(data.Names, "ns.child.example.") ||
		!slices.Contains(data.Names, "ns.other.net.") {
		t.Fatalf("names = %v, want both answer data paths", data.Names)
	}
	gotAddresses := make([]string, 0, len(data.Addresses))
	for _, address := range data.Addresses {
		gotAddresses = append(gotAddresses, address.String())
	}
	if !slices.Contains(gotAddresses, "192.0.2.53") ||
		!slices.Contains(gotAddresses, "198.51.100.53") {
		t.Fatalf("addresses = %v, want glue and resolved NS address", gotAddresses)
	}
	for _, forbidden := range []string{"example./NS", "./NS"} {
		if slices.Contains(queries, forbidden) {
			t.Fatalf("min_ns_dots=2 queried %s: %v", forbidden, queries)
		}
	}
}

func TestDiscoverRPZNameserversSkipsAddressLookupsWhenUnneeded(t *testing.T) {
	response := new(dns.Msg)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA},
		A:   net.ParseIP("203.0.113.8"),
	}}
	addressQueries := 0
	query := func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		result := new(dns.Msg)
		if qtype == dns.TypeNS && name == "example." {
			result.Answer = []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS},
				Ns:  "ns.example.",
			}}
		} else if qtype == dns.TypeA || qtype == dns.TypeAAAA {
			addressQueries++
		}
		return result, nil
	}

	data := discoverRPZNameservers(context.Background(), response, false, 1, 64, query)
	if !slices.Contains(data.Names, "ns.example.") {
		t.Fatalf("names = %v, want ns.example.", data.Names)
	}
	if addressQueries != 0 {
		t.Fatalf("address queries = %d, want zero for NSDNAME-only policy", addressQueries)
	}
}

func TestDiscoverRPZNameserversHonorsTotalLookupBudget(t *testing.T) {
	response := new(dns.Msg)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "a.b.c.example.", Rrtype: dns.TypeA},
		A:   net.ParseIP("203.0.113.8"),
	}}
	lookups := 0
	query := func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		lookups++
		result := new(dns.Msg)
		if qtype == dns.TypeNS {
			result.Answer = []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS},
				Ns:  "ns." + name,
			}}
		}
		return result, nil
	}

	_ = discoverRPZNameservers(context.Background(), response, true, 0, 2, query)
	if lookups != 2 {
		t.Fatalf("lookups = %d, want hard total budget of 2", lookups)
	}
}
