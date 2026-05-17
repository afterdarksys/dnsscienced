package services

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"github.com/dnsscience/dnsscienced/internal/dsync"
)

// DSYNCService implements pb.DSYNCAdminServiceServer.
// It is a thin wrapper around DSYNCNotifier that validates inputs and
// delegates to the notifier's fire-and-forget Notify method.
type DSYNCService struct {
	pb.UnimplementedDSYNCAdminServiceServer
	notifier *dsync.DSYNCNotifier
}

// NewDSYNCService constructs a DSYNCService backed by the given DSYNCNotifier.
func NewDSYNCService(notifier *dsync.DSYNCNotifier) *DSYNCService {
	return &DSYNCService{notifier: notifier}
}

// SendDSYNCNotify validates the request and enqueues an outbound NOTIFY event.
//
// Validation rules:
//   - zone_name must be non-empty (codes.InvalidArgument otherwise)
//   - qtype must be exactly "CDS" or "CSYNC" (codes.InvalidArgument otherwise)
//
// The RPC returns immediately after enqueuing. The outbound NOTIFY is sent
// asynchronously by the DSYNCNotifier worker goroutine. OutboundSent counters
// are incremented INSIDE the worker after successful sendNotify — NOT here.
func (s *DSYNCService) SendDSYNCNotify(_ context.Context, req *pb.SendDSYNCNotifyRequest) (*pb.SendDSYNCNotifyResponse, error) {
	if req.ZoneName == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_name is required")
	}

	var qtype uint16
	switch req.Qtype {
	case "CDS":
		qtype = dns.TypeCDS
	case "CSYNC":
		qtype = dns.TypeCSYNC
	default:
		return nil, status.Errorf(codes.InvalidArgument, "qtype must be CDS or CSYNC, got %q", req.Qtype)
	}

	// Fire-and-forget: Notify enqueues on buffered channel (per D-10).
	// OutboundSent counter is incremented INSIDE the worker after successful send (not here).
	s.notifier.Notify(req.ZoneName, qtype)

	return &pb.SendDSYNCNotifyResponse{
		Success: true,
		Message: fmt.Sprintf("NOTIFY(%s) enqueued for zone %s", req.Qtype, req.ZoneName),
	}, nil
}
