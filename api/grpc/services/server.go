package services

import (
	"context"

	"github.com/afterdarksys/dnsscienced/api/grpc/ports"
	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ServerService struct {
	pb.UnimplementedServerServiceServer
	Mgr ports.ControlManager
}

func NewServerService(m ports.ControlManager) *ServerService { return &ServerService{Mgr: m} }

func (s *ServerService) GetStatus(ctx context.Context, in *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	ss, err := s.Mgr.Status(ctx, in.GetIncludeResources())
	if err != nil { return nil, err }
	return &pb.GetStatusResponse{
		Server: &pb.ServerInfo{Id: ss.Server.ID, Version: ss.Server.Version, Daemon: ss.Server.Daemon, UptimeSeconds: ss.Server.Uptime, Hostname: ss.Server.Hostname},
		Health: &pb.HealthInfo{Status: pb.HealthStatus_HEALTH_STATUS_HEALTHY},
	}, nil
}

func (s *ServerService) GetStats(ctx context.Context, in *pb.GetStatsRequest) (*pb.GetStatsResponse, error) {
	st, err := s.Mgr.Stats(ctx, in.GetPeriod().String(), in.GetBreakdowns())
	if err != nil { return nil, err }
	return &pb.GetStatsResponse{
		Period: st.Period,
		Queries: &pb.QueryStats{
			Total:       st.Queries.Total,
			PerSecond:   st.Queries.PerSecond,
			ByType:      st.Queries.ByType,
			ByRcode:     st.Queries.ByRcode,
			ByTransport: st.Queries.ByTransport,
		},
		Latency: &pb.LatencyStats{
			AvgMs: st.Latency.AvgMs,
			P50Ms: st.Latency.P50Ms,
			P95Ms: st.Latency.P95Ms,
			P99Ms: st.Latency.P99Ms,
			MaxMs: st.Latency.MaxMs,
		},
		Cache: &pb.CacheStats{
			Entries:     st.Cache.Entries,
			SizeBytes:   st.Cache.SizeBytes,
			MaxBytes:    st.Cache.MaxBytes,
			Utilization: st.Cache.Utilization,
		},
	}, nil
}

func (s *ServerService) Reload(ctx context.Context, in *pb.ReloadRequest) (*pb.ReloadResponse, error) {
	rr, err := s.Mgr.Reload(ctx, in.GetSections())
	if err != nil { return nil, err }
	return &pb.ReloadResponse{Success: rr.Success, Message: rr.Message, DurationMs: rr.DurationMs, Reloaded: rr.Reloaded, Errors: rr.Errors}, nil
}

func (s *ServerService) Shutdown(ctx context.Context, in *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
	sr, err := s.Mgr.Shutdown(ctx, in.GetTimeoutSeconds(), in.GetForce())
	if err != nil { return nil, err }
	return &pb.ShutdownResponse{Message: sr.Message, GracefulPeriodSeconds: sr.GracefulPeriodSec}, nil
}

func (s *ServerService) GetConfig(ctx context.Context, in *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
	cfg, err := s.Mgr.Config(ctx, in.GetSection(), in.GetRedactSecrets())
	if err != nil { return nil, err }
	return &pb.GetConfigResponse{Config: cfg}, nil
}

func (s *ServerService) GetLicense(ctx context.Context, _ *pb.GetLicenseRequest) (*pb.GetLicenseResponse, error) {
	li, err := s.Mgr.License(ctx)
	if err != nil { return nil, err }
	return &pb.GetLicenseResponse{License: &pb.LicenseInfo{Product: li.Product, Version: li.Version, Licensee: li.Licensee, IsValid: li.IsValid, DaysUntilExpiry: li.DaysUntilExpiry, Features: li.Features, Serial: li.Serial}}, nil
}

func (s *ServerService) WatchStatus(*pb.WatchStatusRequest, pb.ServerService_WatchStatusServer) error {
	return status.Error(codes.Unimplemented, "WatchStatus not implemented yet")
}

func (s *ServerService) GetMetrics(context.Context, *pb.GetMetricsRequest) (*pb.GetMetricsResponse, error) {
	return &pb.GetMetricsResponse{Format: "prometheus", Content: "# HELP dnsscienced_up 1\n# TYPE dnsscienced_up gauge\ndnsscienced_up 1"}, nil
}
