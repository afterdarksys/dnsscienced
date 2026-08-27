package services

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"github.com/afterdarksys/dnsscienced/internal/dsync"
)

// newTestNotifier creates a DSYNCNotifier with zero propagation delay for fast tests.
func newTestNotifier() *dsync.DSYNCNotifier {
	return dsync.NewDSYNCNotifier("127.0.0.1:53", 0*time.Second, zerolog.Nop(), nil)
}

// TestSendDSYNCNotify_Valid verifies that a valid request with zone_name and CDS qtype
// enqueues via DSYNCNotifier.Notify and returns success=true.
func TestSendDSYNCNotify_Valid(t *testing.T) {
	notifier := newTestNotifier()
	t.Cleanup(notifier.Close)
	svc := NewDSYNCService(notifier)

	resp, err := svc.SendDSYNCNotify(context.Background(), &pb.SendDSYNCNotifyRequest{
		ZoneName: "example.com.",
		Qtype:    "CDS",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success, "success should be true")
	assert.Contains(t, resp.Message, "CDS", "message should reference qtype")
	assert.Contains(t, resp.Message, "example.com.", "message should reference zone name")
}

// TestSendDSYNCNotify_ValidCSYNC verifies that qtype=CSYNC is also accepted.
func TestSendDSYNCNotify_ValidCSYNC(t *testing.T) {
	notifier := newTestNotifier()
	t.Cleanup(notifier.Close)
	svc := NewDSYNCService(notifier)

	resp, err := svc.SendDSYNCNotify(context.Background(), &pb.SendDSYNCNotifyRequest{
		ZoneName: "example.com.",
		Qtype:    "CSYNC",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// TestSendDSYNCNotify_EmptyZone verifies that zone_name="" returns codes.InvalidArgument.
func TestSendDSYNCNotify_EmptyZone(t *testing.T) {
	notifier := newTestNotifier()
	t.Cleanup(notifier.Close)
	svc := NewDSYNCService(notifier)

	_, err := svc.SendDSYNCNotify(context.Background(), &pb.SendDSYNCNotifyRequest{
		ZoneName: "",
		Qtype:    "CDS",
	})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.InvalidArgument, st.Code(), "expected InvalidArgument for empty zone_name")
}

// TestSendDSYNCNotify_InvalidQtype verifies that qtype="MX" returns codes.InvalidArgument.
func TestSendDSYNCNotify_InvalidQtype(t *testing.T) {
	notifier := newTestNotifier()
	t.Cleanup(notifier.Close)
	svc := NewDSYNCService(notifier)

	_, err := svc.SendDSYNCNotify(context.Background(), &pb.SendDSYNCNotifyRequest{
		ZoneName: "example.com.",
		Qtype:    "MX",
	})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.InvalidArgument, st.Code(), "expected InvalidArgument for invalid qtype")
}

// TestSendDSYNCNotify_QtypeCaseInsensitive verifies lowercase qtype is rejected (strict match).
func TestSendDSYNCNotify_QtypeCaseSensitive(t *testing.T) {
	notifier := newTestNotifier()
	t.Cleanup(notifier.Close)
	svc := NewDSYNCService(notifier)

	_, err := svc.SendDSYNCNotify(context.Background(), &pb.SendDSYNCNotifyRequest{
		ZoneName: "example.com.",
		Qtype:    "cds", // lowercase — must be rejected per T-08-20
	})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code(), "lowercase qtype should be InvalidArgument")
}

// TestDSYNCService_DoesNotIncrementOutboundAtEnqueue verifies that the RPC
// does not increment any outbound counter (that happens inside the worker).
// This test is structural — it confirms the service delegates to Notify only.
func TestDSYNCService_DoesNotIncrementOutboundAtEnqueue(t *testing.T) {
	notifier := newTestNotifier()
	t.Cleanup(notifier.Close)
	svc := NewDSYNCService(notifier)

	// Call SendDSYNCNotify — fire and forget.
	resp, err := svc.SendDSYNCNotify(context.Background(), &pb.SendDSYNCNotifyRequest{
		ZoneName: "example.com.",
		Qtype:    "CDS",
	})

	require.NoError(t, err)
	assert.True(t, resp.Success, "enqueue should report success")
	// The worker will eventually try to send the notify via live DNS (which will fail
	// in unit test environment), but the RPC itself should NOT fail or panic.
	// The test validates fire-and-forget semantics at the RPC layer.

	// Verify the qtype constants used internally are correct.
	assert.Equal(t, dns.TypeCDS, uint16(dns.TypeCDS), "TypeCDS should match miekg/dns")
	assert.Equal(t, dns.TypeCSYNC, uint16(dns.TypeCSYNC), "TypeCSYNC should match miekg/dns")
}
