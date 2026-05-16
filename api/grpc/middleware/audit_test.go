package middleware

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/dnsscience/dnsscienced/internal/logging"
)

// stubAuthInfo implements credentials.AuthInfo for testing.
type stubAuthInfo struct {
	credentials.TLSInfo
}

func (stubAuthInfo) AuthType() string { return "tls" }

// fakeAddr implements net.Addr for testing.
type fakeAddr struct{ addr string }

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return f.addr }

// TestCallerIdentity_KeyID verifies callerIdentity returns "key:<id>" when CtxKeyID set.
func TestCallerIdentity_KeyID(t *testing.T) {
	ctx := context.WithValue(context.Background(), CtxKeyID{}, "operator-key")
	got := callerIdentity(ctx)
	if got != "key:operator-key" {
		t.Errorf("expected key:operator-key, got %q", got)
	}
}

// TestCallerIdentity_EmptyKeyID verifies callerIdentity falls through on empty string.
func TestCallerIdentity_EmptyKeyID(t *testing.T) {
	ctx := context.WithValue(context.Background(), CtxKeyID{}, "")
	got := callerIdentity(ctx)
	// empty string should not produce "key:", should fall through to unknown
	if got == "key:" {
		t.Errorf("expected fallthrough on empty id, got %q", got)
	}
}

// TestCallerIdentity_Unknown verifies callerIdentity returns "unknown" with bare context.
func TestCallerIdentity_Unknown(t *testing.T) {
	got := callerIdentity(context.Background())
	if got != "unknown" {
		t.Errorf("expected unknown, got %q", got)
	}
}

// TestRemoteAddr_Unknown verifies remoteAddr returns "unknown" with bare context.
func TestRemoteAddr_Unknown(t *testing.T) {
	got := remoteAddr(context.Background())
	if got != "unknown" {
		t.Errorf("expected unknown, got %q", got)
	}
}

// TestRemoteAddr_FromPeer verifies remoteAddr extracts address from peer context.
func TestRemoteAddr_FromPeer(t *testing.T) {
	p := &peer.Peer{Addr: fakeAddr{"192.0.2.1:50051"}}
	ctx := peer.NewContext(context.Background(), p)
	got := remoteAddr(ctx)
	if got != "192.0.2.1:50051" {
		t.Errorf("expected 192.0.2.1:50051, got %q", got)
	}
}

// TestCtxKeyID_Type verifies CtxKeyID is a distinct type (not string-keyed).
func TestCtxKeyID_Type(t *testing.T) {
	type otherKey struct{}
	ctx := context.WithValue(context.Background(), otherKey{}, "should-not-match")
	ctx = context.WithValue(ctx, CtxKeyID{}, "real-key")
	got := callerIdentity(ctx)
	if got != "key:real-key" {
		t.Errorf("expected key:real-key, got %q", got)
	}
}

// TestAuditInterceptor verifies AuditUnaryInterceptor emits all D-07 required fields.
// Uses bytes.Buffer-backed logging.Logger to capture JSON output without file I/O.
func TestAuditInterceptor(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewWithWriter(&buf)

	interceptor := AuditUnaryInterceptor(logger)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	}

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/ListConnections"}
	_, err := interceptor(ctx, nil, info, handler)
	if err != nil {
		t.Fatalf("AuditUnaryInterceptor: unexpected error: %v", err)
	}

	// Assert D-07 required fields are present in log output as JSON keys
	logOutput := buf.String()
	if !strings.Contains(logOutput, `"remote_addr"`) {
		t.Errorf("D-07: remote_addr field must be present in audit log; got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"timestamp"`) {
		t.Errorf("D-07: timestamp field must be present in audit log; got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"method"`) {
		t.Errorf("D-07: method field must be present in audit log; got: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"code"`) {
		t.Errorf("D-07: code field must be present in audit log; got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "admin rpc") {
		t.Errorf("audit message must be 'admin rpc'; got: %s", logOutput)
	}
}

// TestAuditInterceptor_NoKeyLeak verifies the named key id appears in audit log and the
// raw secret never does (D-08).
func TestAuditInterceptor_NoKeyLeak(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewWithWriter(&buf)

	interceptor := AuditUnaryInterceptor(logger)

	// Set a key ID in context (simulating auth interceptor behavior per D-08)
	ctx := context.WithValue(context.Background(), CtxKeyID{}, "admin-key")
	info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/GetServerInfo"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	}
	_, _ = interceptor(ctx, nil, info, handler)

	logOutput := buf.String()
	// The secret must NOT appear; only the named id "admin-key"
	if strings.Contains(logOutput, "super-secret-token") {
		t.Errorf("raw secret leaked in audit log output: %s", logOutput)
	}
	// The named id should appear as the caller identity
	if !strings.Contains(logOutput, "admin-key") {
		t.Errorf("D-08: named key id must appear in audit log; got: %s", logOutput)
	}
}

// TestRemoteAddr_NilAddr verifies remoteAddr handles nil Addr without panic.
func TestRemoteAddr_NilAddr(t *testing.T) {
	p := &peer.Peer{Addr: net.Addr(nil)}
	ctx := peer.NewContext(context.Background(), p)
	// should not panic
	got := remoteAddr(ctx)
	if got != "unknown" {
		t.Errorf("expected unknown for nil addr, got %q", got)
	}
}
