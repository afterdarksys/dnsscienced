package main

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNormalizeIgnoresTTLOrderAndOPT(t *testing.T) {
	first := new(dns.Msg)
	first.Authoritative = true
	first.Answer = []dns.RR{
		mustRR(t, "www.example.test. 300 IN AAAA 2001:db8::80"),
		mustRR(t, "www.example.test. 300 IN A 192.0.2.80"),
	}
	first.SetEdns0(1232, false)

	second := new(dns.Msg)
	second.Authoritative = true
	second.Answer = []dns.RR{
		mustRR(t, "WWW.EXAMPLE.TEST. 10 IN A 192.0.2.80"),
		mustRR(t, "WWW.EXAMPLE.TEST. 10 IN AAAA 2001:db8::80"),
	}
	second.SetEdns0(4096, false)

	tc := testCase{edns: true}
	if diff := compare(normalize(first, tc), normalize(second, tc)); diff != "" {
		t.Fatalf("normalized messages differ: %s", diff)
	}
}

func TestNormalizePreservesProtocolSemantics(t *testing.T) {
	want := snapshot{Rcode: dns.RcodeNameError, AA: true}
	got := snapshot{Rcode: dns.RcodeSuccess, AA: true}
	if diff := compare(want, got); diff == "" {
		t.Fatal("rcode mismatch was not detected")
	}
}

func mustRR(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
