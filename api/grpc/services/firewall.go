package services

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
)

// FirewallService implements pb.FirewallAdminServiceServer.
// It delegates all operations to the live *firewalld.Firewall instance.
// All handlers are thin wrappers — no business logic lives here.
type FirewallService struct {
	pb.UnimplementedFirewallAdminServiceServer
	fw *firewalld.Firewall
}

// NewFirewallService constructs a FirewallService backed by the given Firewall.
func NewFirewallService(fw *firewalld.Firewall) *FirewallService {
	return &FirewallService{fw: fw}
}

// FirewallStats returns a snapshot of the firewall counters.
func (s *FirewallService) FirewallStats(_ context.Context, _ *pb.FirewallStatsRequest) (*pb.FirewallStatsResponse, error) {
	stats := s.fw.Stats()
	return &pb.FirewallStatsResponse{
		TotalQueries:    stats.TotalQueries,
		TotalBlocked:    stats.TotalBlocked,
		TotalNxdomain:   stats.TotalNXDomain,
		TotalDropped:    stats.TotalDropped,
		TotalRedirected: stats.TotalRedirected,
	}, nil
}

// LoadScript compiles and activates a Starlark policy script supplied as a string body.
// script_id and body are both required.
func (s *FirewallService) LoadScript(_ context.Context, req *pb.FirewallLoadScriptRequest) (*pb.FirewallLoadScriptResponse, error) {
	if req.ScriptId == "" {
		return nil, status.Error(codes.InvalidArgument, "script_id is required")
	}
	if req.Body == "" {
		return nil, status.Error(codes.InvalidArgument, "body is required")
	}
	if err := s.fw.LoadSource(req.ScriptId, req.Body); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "compile script: %v", err)
	}
	return &pb.FirewallLoadScriptResponse{ScriptId: req.ScriptId}, nil
}

// RemoveScript unloads the named Starlark policy script.
// script_id is required; silently succeeds if the script is not loaded.
func (s *FirewallService) RemoveScript(_ context.Context, req *pb.FirewallRemoveScriptRequest) (*pb.FirewallRemoveScriptResponse, error) {
	if req.ScriptId == "" {
		return nil, status.Error(codes.InvalidArgument, "script_id is required")
	}
	s.fw.RemoveScript(req.ScriptId)
	return &pb.FirewallRemoveScriptResponse{}, nil
}

// InjectScore adds or updates a threat score for a domain or IP address.
// Exactly one of domain or ip must be set (oneof target).
func (s *FirewallService) InjectScore(_ context.Context, req *pb.FirewallInjectScoreRequest) (*pb.FirewallInjectScoreResponse, error) {
	ti := s.fw.ThreatIntelEngine()
	switch t := req.Target.(type) {
	case *pb.FirewallInjectScoreRequest_Domain:
		if t.Domain == "" {
			return nil, status.Error(codes.InvalidArgument, "domain is required")
		}
		ti.AddDomainScore(t.Domain, int(req.Score))
	case *pb.FirewallInjectScoreRequest_Ip:
		if t.Ip == "" {
			return nil, status.Error(codes.InvalidArgument, "ip is required")
		}
		ti.AddIPScore(t.Ip, int(req.Score))
	default:
		return nil, status.Error(codes.InvalidArgument, "target must be domain or ip")
	}
	return &pb.FirewallInjectScoreResponse{}, nil
}
