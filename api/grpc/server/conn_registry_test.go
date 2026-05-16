package server

import (
	"context"
	"testing"

	"google.golang.org/grpc/stats"
)

// TestConnRegistry_TagConn verifies that TagConn assigns a UUID and stores ConnInfo.
func TestConnRegistry_TagConn(t *testing.T) {
	r := NewConnRegistry()
	ctx := r.TagConn(context.Background(), &stats.ConnTagInfo{})
	id, ok := ConnIDFromContext(ctx)
	if !ok || id == "" {
		t.Fatal("expected connID in context after TagConn")
	}
	conns := r.List()
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection in registry, got %d", len(conns))
	}
	if conns[0].ID != id {
		t.Errorf("expected conn ID %q, got %q", id, conns[0].ID)
	}
}

// TestConnRegistry_RemoveOnEnd verifies that HandleConn removes the connection on ConnEnd.
func TestConnRegistry_RemoveOnEnd(t *testing.T) {
	r := NewConnRegistry()
	ctx := r.TagConn(context.Background(), &stats.ConnTagInfo{})

	if len(r.List()) != 1 {
		t.Fatal("expected 1 connection before ConnEnd")
	}

	r.HandleConn(ctx, &stats.ConnEnd{})

	if len(r.List()) != 0 {
		t.Fatal("expected 0 connections after ConnEnd")
	}
}

// TestConnRegistry_EnrichConn verifies that EnrichConn updates KeyID and CertCN.
func TestConnRegistry_EnrichConn(t *testing.T) {
	r := NewConnRegistry()
	ctx := r.TagConn(context.Background(), &stats.ConnTagInfo{})
	id, _ := ConnIDFromContext(ctx)

	r.EnrichConn(id, "key-123", "admin.example.com")

	conns := r.List()
	if len(conns) != 1 {
		t.Fatal("expected 1 connection")
	}
	if conns[0].KeyID != "key-123" {
		t.Errorf("expected KeyID %q, got %q", "key-123", conns[0].KeyID)
	}
	if conns[0].CertCN != "admin.example.com" {
		t.Errorf("expected CertCN %q, got %q", "admin.example.com", conns[0].CertCN)
	}
}

// TestConnRegistry_EnrichConn_MissingID verifies EnrichConn is a no-op for unknown IDs.
func TestConnRegistry_EnrichConn_MissingID(t *testing.T) {
	r := NewConnRegistry()
	// Should not panic on unknown ID
	r.EnrichConn("nonexistent-id", "key-1", "cn.example.com")
}

// TestSplitHostPort verifies the exported SplitHostPort function.
func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		addr     string
		wantHost string
		wantPort string
	}{
		{"192.168.1.1:8443", "192.168.1.1", "8443"},
		{"[::1]:9000", "::1", "9000"},
		{"/var/run/admin.sock", "/var/run/admin.sock", ""},
	}

	for _, tc := range tests {
		host, port := SplitHostPort(tc.addr)
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("SplitHostPort(%q) = (%q, %q), want (%q, %q)",
				tc.addr, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// TestConnRegistry_TagRPC verifies that TagRPC is a no-op passthrough.
func TestConnRegistry_TagRPC(t *testing.T) {
	r := NewConnRegistry()
	ctx := r.TagRPC(context.Background(), nil)
	if ctx == nil {
		t.Fatal("TagRPC returned nil context")
	}
}

// TestConnRegistry_HandleRPC verifies that HandleRPC does not panic.
func TestConnRegistry_HandleRPC(t *testing.T) {
	r := NewConnRegistry()
	// Should not panic
	r.HandleRPC(context.Background(), nil)
}
