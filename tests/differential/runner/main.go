// dns-differential compares authoritative protocol behavior from DNSScienced,
// BIND, and NSD after normalizing wire-only differences such as IDs, RR order,
// and compression.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type endpoint struct {
	name string
	addr string
}

type testCase struct {
	name       string
	qname      string
	qtype      uint16
	network    string
	edns       bool
	authority  bool
	additional bool
}

type snapshot struct {
	Rcode      int
	AA         bool
	TC         bool
	Answer     []string
	Authority  []string
	Additional []string
	EDNS       bool
}

var cases = []testCase{
	{name: "apex-soa-udp", qname: "example.test.", qtype: dns.TypeSOA, network: "udp"},
	{name: "apex-ns-udp", qname: "example.test.", qtype: dns.TypeNS, network: "udp"},
	{name: "a-udp", qname: "www.example.test.", qtype: dns.TypeA, network: "udp"},
	{name: "aaaa-udp", qname: "www.example.test.", qtype: dns.TypeAAAA, network: "udp"},
	{name: "a-tcp", qname: "www.example.test.", qtype: dns.TypeA, network: "tcp"},
	{name: "cname-udp", qname: "alias.example.test.", qtype: dns.TypeA, network: "udp"},
	{name: "mx-udp", qname: "example.test.", qtype: dns.TypeMX, network: "udp"},
	{name: "txt-udp", qname: "example.test.", qtype: dns.TypeTXT, network: "udp"},
	{name: "caa-udp", qname: "example.test.", qtype: dns.TypeCAA, network: "udp"},
	{name: "wildcard-udp", qname: "host.wild.example.test.", qtype: dns.TypeA, network: "udp"},
	{name: "nodata-udp", qname: "only-a.example.test.", qtype: dns.TypeAAAA, network: "udp", authority: true},
	{name: "nxdomain-udp", qname: "missing.example.test.", qtype: dns.TypeA, network: "udp", authority: true},
	{name: "delegation-udp", qname: "www.child.example.test.", qtype: dns.TypeA, network: "udp", authority: true, additional: true},
	{name: "edns0-udp", qname: "www.example.test.", qtype: dns.TypeA, network: "udp", edns: true},
}

func main() {
	candidate := flag.String("candidate", "candidate:53", "DNSScienced address")
	bind := flag.String("bind", "bind:53", "BIND address")
	nsd := flag.String("nsd", "nsd:53", "NSD address")
	flag.Parse()

	endpoints := []endpoint{
		{name: "dnsscienced", addr: *candidate},
		{name: "bind", addr: *bind},
		{name: "nsd", addr: *nsd},
	}
	if err := waitReady(endpoints); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	failures := 0
	for _, tc := range cases {
		replies := make(map[string]snapshot, len(endpoints))
		for _, ep := range endpoints {
			msg, err := exchange(ep.addr, tc)
			if err != nil {
				fmt.Fprintf(os.Stderr, "FAIL %-20s %-12s %v\n", tc.name, ep.name, err)
				failures++
				continue
			}
			replies[ep.name] = normalize(msg, tc)
		}
		want, ok := replies["bind"]
		if !ok {
			continue
		}
		caseFailed := false
		for _, name := range []string{"dnsscienced", "nsd"} {
			got, exists := replies[name]
			if !exists {
				caseFailed = true
				continue
			}
			if diff := compare(want, got); diff != "" {
				fmt.Fprintf(os.Stderr, "FAIL %-20s bind != %s: %s\n", tc.name, name, diff)
				caseFailed = true
				failures++
			}
		}
		if !caseFailed {
			fmt.Printf("PASS %-20s %s %s\n", tc.name, strings.ToUpper(tc.network), dns.TypeToString[tc.qtype])
		}
	}
	if failures != 0 {
		fmt.Fprintf(os.Stderr, "\ndifferential conformance failed: %d mismatch(es)\n", failures)
		os.Exit(1)
	}
	fmt.Printf("\ndifferential conformance passed: %d cases across DNSScienced, BIND, and NSD\n", len(cases))
}

func waitReady(endpoints []endpoint) error {
	deadline := time.Now().Add(90 * time.Second)
	for _, ep := range endpoints {
		for {
			_, err := exchange(ep.addr, testCase{
				qname: "example.test.", qtype: dns.TypeSOA, network: "udp",
			})
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s at %s did not become ready: %w", ep.name, ep.addr, err)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	return nil
}

func exchange(addr string, tc testCase) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(tc.qname, tc.qtype)
	if tc.edns {
		query.SetEdns0(1232, false)
	}
	client := &dns.Client{Net: tc.network, Timeout: 3 * time.Second}
	reply, _, err := client.Exchange(query, addr)
	if err != nil {
		return nil, err
	}
	if len(reply.Question) != 1 || !sameQuestion(query.Question[0], reply.Question[0]) {
		return nil, errors.New("response question does not match request")
	}
	if tc.edns && reply.IsEdns0() == nil {
		return nil, errors.New("EDNS(0) response omitted OPT")
	}
	return reply, nil
}

func sameQuestion(a, b dns.Question) bool {
	return strings.EqualFold(a.Name, b.Name) && a.Qtype == b.Qtype && a.Qclass == b.Qclass
}

func normalize(msg *dns.Msg, tc testCase) snapshot {
	s := snapshot{
		Rcode:  msg.Rcode,
		AA:     msg.Authoritative,
		TC:     msg.Truncated,
		Answer: normalizeRRs(msg.Answer),
		EDNS:   msg.IsEdns0() != nil,
	}
	if tc.authority {
		s.Authority = normalizeRRs(msg.Ns)
	}
	if tc.additional {
		s.Additional = normalizeRRs(msg.Extra)
	}
	return s
}

func normalizeRRs(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		copy := dns.Copy(rr)
		copy.Header().Ttl = 0
		copy.Header().Name = strings.ToLower(copy.Header().Name)
		out = append(out, strings.ToLower(copy.String()))
	}
	sort.Strings(out)
	return out
}

func compare(want, got snapshot) string {
	if want.Rcode != got.Rcode {
		return fmt.Sprintf("rcode %s != %s", dns.RcodeToString[want.Rcode], dns.RcodeToString[got.Rcode])
	}
	if want.AA != got.AA {
		return fmt.Sprintf("AA %t != %t", want.AA, got.AA)
	}
	if want.TC != got.TC {
		return fmt.Sprintf("TC %t != %t", want.TC, got.TC)
	}
	if want.EDNS != got.EDNS {
		return fmt.Sprintf("EDNS %t != %t", want.EDNS, got.EDNS)
	}
	if diff := compareStrings("answer", want.Answer, got.Answer); diff != "" {
		return diff
	}
	if diff := compareStrings("authority", want.Authority, got.Authority); diff != "" {
		return diff
	}
	return compareStrings("additional", want.Additional, got.Additional)
}

func compareStrings(section string, want, got []string) string {
	if len(want) != len(got) {
		return fmt.Sprintf("%s count %d != %d; bind=%v other=%v", section, len(want), len(got), want, got)
	}
	for i := range want {
		if want[i] != got[i] {
			return fmt.Sprintf("%s differs; bind=%v other=%v", section, want, got)
		}
	}
	return ""
}
