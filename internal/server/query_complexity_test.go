package server

import (
	"testing"

	"github.com/miekg/dns"
)

func TestQueryComplexityScoresNormalAndCompoundQueries(t *testing.T) {
	cfg := defaultQueryComplexityConfig()
	normal := new(dns.Msg)
	normal.SetQuestion("www.example.", dns.TypeA)
	if score := queryComplexityScore(normal, cfg); score != 1 {
		t.Fatalf("normal query score = %d, want 1", score)
	}

	compound := new(dns.Msg)
	compound.SetQuestion("very.long.security.example.", dns.TypeDNSKEY)
	compound.SetEdns0(1232, true)
	for i := 0; i < 20; i++ {
		compound.IsEdns0().Option = append(compound.IsEdns0().Option, &dns.EDNS0_NSID{})
	}
	if score := queryComplexityScore(compound, cfg); score <= cfg.MaxScore {
		t.Fatalf("compound query score = %d, want greater than %d", score, cfg.MaxScore)
	}
}

func TestHandleDNSRejectsExcessiveQueryComplexity(t *testing.T) {
	cfg := DefaultConfig()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("example.", dns.TypeA)
	request.SetEdns0(1232, false)
	for i := 0; i < 21; i++ {
		request.IsEdns0().Option = append(request.IsEdns0().Option, &dns.EDNS0_NSID{})
	}
	writer := newTestResponseWriter("192.0.2.10")
	s.handleDNS(writer, request)
	if writer.msg == nil || writer.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("response = %v, want REFUSED", writer.msg)
	}
	stats := s.GetStats()
	if stats.ComplexityRejected != 1 || stats.Errors != 1 {
		t.Fatalf("stats = %+v, want one complexity rejection and error", stats)
	}
}

func TestQueryComplexityCanBeDisabledAndRejectsInvalidTuning(t *testing.T) {
	disabled := DefaultConfig()
	disabled.QueryComplexity.Enabled = false
	s, err := New(disabled)
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("example.", dns.TypeA)
	request.SetEdns0(1232, false)
	for i := 0; i < 21; i++ {
		request.IsEdns0().Option = append(request.IsEdns0().Option, &dns.EDNS0_NSID{})
	}
	s.handleDNS(newTestResponseWriter("192.0.2.10"), request)
	if got := s.GetStats().ComplexityRejected; got != 0 {
		t.Fatalf("disabled complexity control rejected %d queries", got)
	}

	invalid := DefaultConfig()
	invalid.QueryComplexity.MaxScore = -1
	if _, err := New(invalid); err == nil {
		t.Fatal("negative max_score was accepted")
	}
}
