package server

import (
	"net"
	"testing"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

// cnameTestZone returns a zone with an apex A record and a CNAME-only "www"
// name, matching the real-world www.<domain> -> <domain> pattern.
func cnameTestZone() *zone.Zone {
	return &zone.Zone{
		Name:   "example.com",
		Origin: "example.com.",
		Class:  dns.ClassINET,
		SOA: &dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  1,
			Refresh: 3600, Retry: 600, Expire: 604800, Minttl: 1800,
		},
		Records: map[string]map[uint16][]dns.RR{
			"example.com.": {
				dns.TypeA: {
					&dns.A{
						Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.9"),
					},
				},
			},
			"www.example.com.": {
				dns.TypeCNAME: {
					&dns.CNAME{
						Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
						Target: "example.com.",
					},
				},
			},
		},
	}
}

// TestHandleAuthoritative_CNAMEReturnedForAQuery is a regression test for the
// real cats.exchange outage (2026-07-22): querying type A at a CNAME-only
// name returned NODATA instead of the CNAME record, per RFC 1034 §3.6.2 a
// CNAME must be returned for a query of any type at that owner name.
func TestHandleAuthoritative_CNAMEReturnedForAQuery(t *testing.T) {
	s, err := New(Config{
		Zones: map[string]*zone.Zone{
			"example.com.": cnameTestZone(),
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)

	resp, ok := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if !ok {
		t.Fatal("handleAuthoritative returned ok=false, expected a response")
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got rcode=%d", resp.Rcode)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("expected CNAME and in-zone target A, got %d: %v", len(resp.Answer), resp.Answer)
	}
	cname, ok := resp.Answer[0].(*dns.CNAME)
	if !ok {
		t.Fatalf("expected answer to be a CNAME record, got %T", resp.Answer[0])
	}
	if cname.Target != "example.com." {
		t.Errorf("expected CNAME target example.com., got %q", cname.Target)
	}
	if _, ok := resp.Answer[1].(*dns.A); !ok {
		t.Fatalf("expected terminal A answer, got %T", resp.Answer[1])
	}
}

// TestHandleAuthoritative_ExplicitCNAMEQueryStillWorks guards against
// regressing the already-working explicit-type-CNAME query path.
func TestHandleAuthoritative_ExplicitCNAMEQueryStillWorks(t *testing.T) {
	s, err := New(Config{
		Zones: map[string]*zone.Zone{
			"example.com.": cnameTestZone(),
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeCNAME)

	resp, ok := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if !ok {
		t.Fatal("handleAuthoritative returned ok=false, expected a response")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d", len(resp.Answer))
	}
}

// TestHandleAuthoritative_NoDataStillNXDOMAINForMissingName ensures the
// CNAME-fallback change doesn't turn a genuinely-missing name into NODATA.
func TestHandleAuthoritative_NoDataStillNXDOMAINForMissingName(t *testing.T) {
	s, err := New(Config{
		Zones: map[string]*zone.Zone{
			"example.com.": cnameTestZone(),
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.com.", dns.TypeA)

	resp, ok := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if !ok {
		t.Fatal("handleAuthoritative returned ok=false, expected a response")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for missing name, got rcode=%d", resp.Rcode)
	}
}

// TestHandleAuthoritative_AAAAQueryAtCNAMEName covers a second query type
// beyond A, since the fix must apply to any non-CNAME query type.
func TestHandleAuthoritative_AAAAQueryAtCNAMEName(t *testing.T) {
	s, err := New(Config{
		Zones: map[string]*zone.Zone{
			"example.com.": cnameTestZone(),
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeAAAA)

	resp, ok := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if !ok {
		t.Fatal("handleAuthoritative returned ok=false, expected a response")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer record (the CNAME) for AAAA query, got %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("expected CNAME answer for AAAA query at CNAME name, got %T", resp.Answer[0])
	}
}

func TestHandleAuthoritative_CNAMECycleIsBounded(t *testing.T) {
	z := cnameTestZone()
	z.Records["a.example.com."] = map[uint16][]dns.RR{
		dns.TypeCNAME: {
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "b.example.com.",
			},
		},
	}
	z.Records["b.example.com."] = map[uint16][]dns.RR{
		dns.TypeCNAME: {
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "a.example.com.",
			},
		},
	}
	s, err := New(Config{Zones: map[string]*zone.Zone{"example.com.": z}})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)
	resp, ok := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if !ok {
		t.Fatal("handleAuthoritative returned ok=false")
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("cycle returned %d answers, want two unique CNAMEs: %v", len(resp.Answer), resp.Answer)
	}
}

func TestHandleAuthoritative_CNAMEChainIncludesEachDNSSECSignatureOnce(t *testing.T) {
	z := cnameTestZone()
	z.Records["www.example.com."][dns.TypeRRSIG] = []dns.RR{
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: dns.TypeCNAME,
		},
	}
	z.Records["example.com."][dns.TypeRRSIG] = []dns.RR{
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
			TypeCovered: dns.TypeA,
		},
	}
	s, err := New(Config{Zones: map[string]*zone.Zone{"example.com.": z}})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	req.SetEdns0(1232, true)
	resp, ok := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if !ok {
		t.Fatal("handleAuthoritative returned ok=false")
	}

	signatures := 0
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			signatures++
		}
	}
	if len(resp.Answer) != 4 || signatures != 2 {
		t.Fatalf("answers=%v, want CNAME+RRSIG and A+RRSIG exactly once", resp.Answer)
	}
}
