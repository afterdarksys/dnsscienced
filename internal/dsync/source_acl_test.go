package dsync

import (
	"net"
	"testing"
)

// TestSourceACL_EmptyAllowAll: empty allowlist means accept all (per D-05).
func TestSourceACL_EmptyAllowAll(t *testing.T) {
	acl, err := NewSourceACL(nil)
	if err != nil {
		t.Fatalf("NewSourceACL(nil) unexpected error: %v", err)
	}
	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "1.2.3.4"}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if !acl.Check(ip) {
			t.Errorf("empty allowlist: expected Check(%s) = true, got false", s)
		}
	}
}

// TestSourceACL_MatchCIDR: IP inside CIDR is accepted.
func TestSourceACL_MatchCIDR(t *testing.T) {
	acl, err := NewSourceACL([]string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("NewSourceACL unexpected error: %v", err)
	}
	ip := net.ParseIP("192.168.1.5")
	if !acl.Check(ip) {
		t.Errorf("expected Check(192.168.1.5) = true for 192.168.1.0/24")
	}
}

// TestSourceACL_NoMatch: IP outside all CIDRs is rejected.
func TestSourceACL_NoMatch(t *testing.T) {
	acl, err := NewSourceACL([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewSourceACL unexpected error: %v", err)
	}
	ip := net.ParseIP("192.168.1.1")
	if acl.Check(ip) {
		t.Errorf("expected Check(192.168.1.1) = false for 10.0.0.0/8")
	}
}

// TestSourceACL_SingleIP: exact IP match (treated as /32).
func TestSourceACL_SingleIP(t *testing.T) {
	acl, err := NewSourceACL([]string{"203.0.113.5"})
	if err != nil {
		t.Fatalf("NewSourceACL unexpected error: %v", err)
	}

	match := net.ParseIP("203.0.113.5")
	if !acl.Check(match) {
		t.Errorf("expected Check(203.0.113.5) = true for single IP 203.0.113.5")
	}

	noMatch := net.ParseIP("203.0.113.6")
	if acl.Check(noMatch) {
		t.Errorf("expected Check(203.0.113.6) = false for single IP 203.0.113.5")
	}
}

// TestSourceACL_MultipleCIDRs: accepts IP in any of the configured CIDRs.
func TestSourceACL_MultipleCIDRs(t *testing.T) {
	acl, err := NewSourceACL([]string{"10.0.0.0/8", "172.16.0.0/12"})
	if err != nil {
		t.Fatalf("NewSourceACL unexpected error: %v", err)
	}
	ip := net.ParseIP("172.16.5.1")
	if !acl.Check(ip) {
		t.Errorf("expected Check(172.16.5.1) = true for 172.16.0.0/12")
	}
}

// TestSourceACL_InvalidCIDRErrors: invalid CIDR entry returns an error (fail-closed behavior).
func TestSourceACL_InvalidCIDRErrors(t *testing.T) {
	_, err := NewSourceACL([]string{"10.0.0./8"})
	if err == nil {
		t.Error("expected error for malformed CIDR '10.0.0./8', got nil")
	}
}

// TestSourceACL_SatisfiesAllower: compile-time interface assertion.
func TestSourceACL_SatisfiesAllower(t *testing.T) {
	var _ Allower = (*SourceACL)(nil)
}
