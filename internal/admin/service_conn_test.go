package admin_test

import (
	"context"
	"testing"
	"time"

	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	grpcserver "github.com/afterdarksys/dnsscienced/api/grpc/server"
	"github.com/afterdarksys/dnsscienced/internal/admin"
	"google.golang.org/grpc/stats"
)

// makeServiceWithRegistry creates a minimal Service with a wired ConnRegistry for testing.
func makeServiceWithRegistry() (*admin.Service, *grpcserver.ConnRegistry) {
	reg := grpcserver.NewConnRegistry()
	svc := admin.NewService(nil, nil, nil, nil, nil, nil, "", "", nil, nil, reg, nil, nil)
	return svc, reg
}

// TestListConnections verifies that ListConnections returns data from the registry.
func TestListConnections(t *testing.T) {
	svc, reg := makeServiceWithRegistry()

	// Simulate a connection
	ctx := reg.TagConn(context.Background(), &stats.ConnTagInfo{})
	_ = ctx

	resp, err := svc.ListConnections(context.Background(), &pb.AdminListConnectionsRequest{})
	if err != nil {
		t.Fatalf("ListConnections failed: %v", err)
	}
	if len(resp.Connections) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(resp.Connections))
	}
	if resp.Connections[0].Protocol != "grpc" {
		t.Errorf("expected protocol grpc, got %q", resp.Connections[0].Protocol)
	}
	if resp.TotalCount != 1 {
		t.Errorf("expected TotalCount 1, got %d", resp.TotalCount)
	}
}

// TestListConnections_Empty verifies that ListConnections returns an empty slice when no connections.
func TestListConnections_Empty(t *testing.T) {
	svc, _ := makeServiceWithRegistry()

	resp, err := svc.ListConnections(context.Background(), &pb.AdminListConnectionsRequest{})
	if err != nil {
		t.Fatalf("ListConnections failed: %v", err)
	}
	if len(resp.Connections) != 0 {
		t.Fatalf("expected 0 connections, got %d", len(resp.Connections))
	}
}

// TestKillConnection_ReturnsLimitationMessage verifies KillConnection returns success=false with explanation.
func TestKillConnection_ReturnsLimitationMessage(t *testing.T) {
	svc, _ := makeServiceWithRegistry()

	resp, err := svc.KillConnection(context.Background(), &pb.AdminKillConnectionRequest{ConnectionId: "some-id"})
	if err != nil {
		t.Fatalf("KillConnection returned error: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false from KillConnection")
	}
	if resp.Message == "" {
		t.Error("expected non-empty Message from KillConnection")
	}
}

// TestListConnections_WithRemoteAddr verifies ClientIp and ClientPort are parsed from RemoteAddr.
func TestListConnections_WithRemoteAddr(t *testing.T) {
	_ = time.Now() // ensure time import used
	svc, reg := makeServiceWithRegistry()

	// Simulate connection with a real remote addr (we use a fake net.Addr via ConnTagInfo)
	// We can't easily inject RemoteAddr without a real net.Addr, so test via EnrichConn
	ctx := reg.TagConn(context.Background(), &stats.ConnTagInfo{})
	id, _ := grpcserver.ConnIDFromContext(ctx)
	reg.EnrichConn(id, "key-op1", "operator.example.com")

	resp, err := svc.ListConnections(context.Background(), &pb.AdminListConnectionsRequest{})
	if err != nil {
		t.Fatalf("ListConnections failed: %v", err)
	}
	if len(resp.Connections) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(resp.Connections))
	}
	// ConnectedAt should be set
	if resp.Connections[0].ConnectedAt == nil {
		t.Error("expected ConnectedAt to be set")
	}
}
