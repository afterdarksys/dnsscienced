package server

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/dnsscience/dnsscienced/internal/cookie"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func delegationTestZone(t *testing.T) *zone.Zone {
	t.Helper()
	z := zone.New("example.com.")
	records := []dns.RR{
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.example.com.", Mbox: "hostmaster.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.example.com."},
		&dns.NS{Hdr: dns.RR_Header{Name: "child.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.child.example.com."},
		&dns.A{Hdr: dns.RR_Header{Name: "ns.child.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.53")},
		&dns.DS{Hdr: dns.RR_Header{Name: "child.example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}, KeyTag: 12345, Algorithm: dns.RSASHA256, DigestType: dns.SHA256, Digest: "0123456789ABCDEF"},
	}
	for _, rr := range records {
		if err := z.AddRecord(rr); err != nil {
			t.Fatalf("AddRecord(%s): %v", rr, err)
		}
	}
	return z
}

func TestHandleAuthoritativeReturnsReferralBelowDelegation(t *testing.T) {
	z := delegationTestZone(t)
	s, err := New(Config{Zones: map[string]*zone.Zone{"example.com.": z}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("www.child.example.com.", dns.TypeA)
	resp, ok := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if !ok {
		t.Fatal("expected authoritative-zone response")
	}
	if resp.Authoritative || len(resp.Answer) != 0 || len(resp.Ns) != 1 || len(resp.Extra) != 1 {
		t.Fatalf("AA=%v answer=%v authority=%v additional=%v, want referral with glue", resp.Authoritative, resp.Answer, resp.Ns, resp.Extra)
	}
}

func TestHandleDNSPreservesNonAuthoritativeReferralFlag(t *testing.T) {
	z := delegationTestZone(t)
	s, err := New(Config{EnableAuthoritative: true, Zones: map[string]*zone.Zone{"example.com.": z}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("www.child.example.com.", dns.TypeA)
	w := newTestResponseWriter("192.0.2.1")
	s.handleDNS(w, req)
	if w.msg == nil || w.msg.Authoritative {
		t.Fatalf("response=%v, referral must have AA=0", w.msg)
	}
}

func TestHandleAuthoritativeAnswersDSAtDelegation(t *testing.T) {
	z := delegationTestZone(t)
	s, err := New(Config{Zones: map[string]*zone.Zone{"example.com.": z}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("child.example.com.", dns.TypeDS)
	resp, _ := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if !resp.Authoritative || len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != dns.TypeDS {
		t.Fatalf("AA=%v answer=%v, want authoritative DS", resp.Authoritative, resp.Answer)
	}
}

func TestSuccessfulAuthoritativeResponseIncludesCookie(t *testing.T) {
	z := cnameTestZone()
	s, err := New(Config{
		EnableAuthoritative: true,
		Zones:               map[string]*zone.Zone{"example.com.": z},
		EnableCookies:       true,
		CookieConfig:        cookie.Config{Enabled: true},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: hex.EncodeToString([]byte("12345678"))})
	w := newTestResponseWriter("192.0.2.1")
	s.handleDNS(w, req)

	if w.msg == nil || w.msg.IsEdns0() == nil {
		t.Fatal("successful response omitted EDNS COOKIE")
	}
	for _, option := range w.msg.IsEdns0().Option {
		if c, ok := option.(*dns.EDNS0_COOKIE); ok {
			if len(c.Cookie) != 48 {
				t.Fatalf("hex cookie length=%d, want 48", len(c.Cookie))
			}
			return
		}
	}
	t.Fatal("successful response omitted EDNS COOKIE option")
}

func TestHandleDNSRejectsMultipleQuestions(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := new(dns.Msg)
	req.Question = []dns.Question{
		{Name: "one.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "two.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	w := newTestResponseWriter("192.0.2.1")
	s.handleDNS(w, req)
	if w.rcode != dns.RcodeFormatError {
		t.Fatalf("rcode=%d, want FORMERR", w.rcode)
	}
}

func TestHandleDNSRefusesUnsupportedClass(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("version.bind.", dns.TypeTXT)
	req.Question[0].Qclass = dns.ClassCHAOS
	w := newTestResponseWriter("192.0.2.1")
	s.handleDNS(w, req)
	if w.rcode != dns.RcodeRefused {
		t.Fatalf("rcode=%d, want REFUSED", w.rcode)
	}
}

func TestHandleAuthoritativeANYUsesMinimalResponse(t *testing.T) {
	s, err := New(Config{Zones: map[string]*zone.Zone{"example.com.": cnameTestZone()}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)
	resp, _ := s.handleAuthoritative(req, net.ParseIP("192.0.2.1"))
	if len(resp.Answer) != 1 {
		t.Fatalf("answers=%d, want RFC 8482 minimal response", len(resp.Answer))
	}
	hinfo, ok := resp.Answer[0].(*dns.HINFO)
	if !ok || hinfo.Cpu != "RFC8482" {
		t.Fatalf("answer=%v, want RFC8482 HINFO", resp.Answer)
	}
}
