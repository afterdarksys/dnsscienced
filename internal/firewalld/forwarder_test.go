package firewalld

import (
	"testing"
)

// TestUpstreamPool_EmptyPool verifies that Next() returns an error for a nil/empty upstream list.
func TestUpstreamPool_EmptyPool(t *testing.T) {
	p := newUpstreamPool(nil)
	addr, err := p.Next()
	if err == nil {
		t.Fatalf("expected error from empty pool, got addr=%q", addr)
	}
	if addr != "" {
		t.Fatalf("expected empty address from empty pool, got %q", addr)
	}
}

// TestUpstreamPool_SingleUpstream verifies that Next() always returns the sole entry.
func TestUpstreamPool_SingleUpstream(t *testing.T) {
	p := newUpstreamPool([]string{"9.9.9.9:53"})
	for i := 0; i < 5; i++ {
		addr, err := p.Next()
		if err != nil {
			t.Fatalf("unexpected error on call %d: %v", i, err)
		}
		if addr != "9.9.9.9:53" {
			t.Fatalf("call %d: expected %q, got %q", i, "9.9.9.9:53", addr)
		}
	}
}

// TestUpstreamPool_RoundRobin verifies that Next() returns upstreams in round-robin order.
func TestUpstreamPool_RoundRobin(t *testing.T) {
	p := newUpstreamPool([]string{"1.1.1.1:53", "2.2.2.2:53"})
	expected := []string{"1.1.1.1:53", "2.2.2.2:53", "1.1.1.1:53"}
	for i, want := range expected {
		got, err := p.Next()
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if got != want {
			t.Fatalf("call %d: expected %q, got %q", i, want, got)
		}
	}
}

// TestRedirectConfig_Fields verifies that RedirectConfig has the expected structure.
func TestRedirectConfig_Fields(t *testing.T) {
	cfg := RedirectConfig{
		Upstreams: []string{"1.1.1.1:53", "8.8.8.8:53"},
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(cfg.Upstreams))
	}
}

// TestConfig_RedirectField verifies that Config has a Redirect field of type RedirectConfig.
func TestConfig_RedirectField(t *testing.T) {
	cfg := Config{
		Redirect: RedirectConfig{
			Upstreams: []string{"9.9.9.9:53"},
		},
	}
	if len(cfg.Redirect.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(cfg.Redirect.Upstreams))
	}
	if cfg.Redirect.Upstreams[0] != "9.9.9.9:53" {
		t.Fatalf("unexpected upstream: %q", cfg.Redirect.Upstreams[0])
	}
}
