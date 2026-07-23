package server

import (
	"testing"

	"github.com/miekg/dns"
)

func TestHandleDNSAppliesAdaptiveClientAdmission(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClientReputation.BaseQPS = 1
	cfg.ClientReputation.MinimumQPS = 1
	cfg.ClientReputation.Burst = 1
	cfg.ClientReputation.MaxEntries = 16
	cfg.ClientReputation.ExemptCIDRs = nil
	cfg.ClientReputation.Action = "refused"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("example.", dns.TypeA)

	s.handleDNS(newTestResponseWriter("192.0.2.10"), request)
	writer := newTestResponseWriter("192.0.2.10")
	s.handleDNS(writer, request)

	if writer.msg == nil || writer.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("limited response = %v, want REFUSED", writer.msg)
	}
	stats := s.GetStats().ClientReputation
	if stats.Limited != 1 || stats.Tracked != 1 {
		t.Fatalf("unexpected reputation stats: %+v", stats)
	}
}

func TestHandleDNSFeedsComplexitySignalsToReputation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClientReputation.ExemptCIDRs = nil
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

	s.handleDNS(newTestResponseWriter("192.0.2.10"), request)
	stats := s.GetStats().ClientReputation
	if stats.Observed != 1 || stats.Tracked != 1 {
		t.Fatalf("unexpected reputation stats after complexity rejection: %+v", stats)
	}
}
