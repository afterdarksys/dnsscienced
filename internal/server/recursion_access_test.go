package server

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDefaultConfigDoesNotExposeRecursion(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.EnableRecursive {
		t.Fatal("DefaultConfig enables an open recursive resolver")
	}
	if cfg.RecursiveConfig.CacheConfig.MaxTTL == 0 {
		t.Fatal("DefaultConfig discarded the resolver maximum cache TTL")
	}
}

func TestNewRejectsInvalidRecursionCIDR(t *testing.T) {
	cfg := Config{
		EnableRecursive:       true,
		RecursionAllowedCIDRs: []string{"not-a-network"},
	}

	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "recursion_allowed_cidrs") {
		t.Fatalf("New() error = %v, want recursion ACL validation error", err)
	}
}

func TestRecursiveQueryDeniedOutsideACL(t *testing.T) {
	cfg := Config{
		EnableRecursive:       true,
		RecursionAllowedCIDRs: []string{"127.0.0.0/8", "::1/128"},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newTestResponseWriter("192.0.2.10")
	r := makeQueryRequest("example.com.")
	r.RecursionDesired = true
	s.handleDNS(w, r)

	if !w.written || w.rcode != dns.RcodeRefused {
		t.Fatalf("response written=%v rcode=%d, want REFUSED", w.written, w.rcode)
	}
	if w.recursionAvailable {
		t.Fatal("RA advertised to a client outside the recursion ACL")
	}
}

func TestRDZeroNeverStartsRecursion(t *testing.T) {
	cfg := Config{
		EnableRecursive:       true,
		RecursionAllowedCIDRs: []string{"127.0.0.0/8"},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Stop() //nolint:errcheck

	w := newTestResponseWriter("127.0.0.1")
	r := makeQueryRequest("example.com.")
	r.RecursionDesired = false
	s.handleDNS(w, r)

	if !w.written || w.rcode != dns.RcodeRefused {
		t.Fatalf("response written=%v rcode=%d, want REFUSED without upstream recursion", w.written, w.rcode)
	}
	if !w.recursionAvailable {
		t.Fatal("RA should advertise that recursion is available to this authorized client")
	}
}
