package admin

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/health"
	"github.com/dnsscience/dnsscienced/internal/logging"
	"github.com/dnsscience/dnsscienced/internal/reload"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
)

// AdminSrvStats mirrors services.SrvStats — defined here to avoid import cycle.
type AdminSrvStats struct {
	Queries    uint64
	UDPQueries uint64
	TCPQueries uint64
	Errors     uint64
	NXDomain   uint64
}

// AdminSrvAdapter is the minimal interface admin.Service needs from the live DNS server.
// The concrete implementation (serverSrvAdapter in cmd/dnsscienced/main.go) satisfies both
// this interface and services.SrvAdapter via structural typing.
type AdminSrvAdapter interface {
	GetZone(origin string) *zone.Zone
	AddZone(z *zone.Zone) error
	RemoveZone(origin string)
	GetAdminStats() AdminSrvStats
}

// Service implements the AdminService gRPC interface
type Service struct {
	pb.UnimplementedAdminServiceServer

	cache      *cache.ShardedCache
	reloadMgr  *reload.Manager
	healthMgr  *health.Health
	logger     *logging.Logger
	startTime  time.Time
	shutdownFn func() error

	// New fields for zone/record CRUD, metrics, rate limiting
	srv        AdminSrvAdapter
	zonesDir   string
	compileBin string
	rrlLimiter *rrl.Limiter // may be nil; nil-guarded at call sites
}

// NewService creates a new admin service
func NewService(
	cache *cache.ShardedCache,
	reloadMgr *reload.Manager,
	healthMgr *health.Health,
	logger *logging.Logger,
	shutdownFn func() error,
	srv AdminSrvAdapter,
	zonesDir string,
	compileBin string,
	rrlLimiter *rrl.Limiter,
) *Service {
	return &Service{
		cache:      cache,
		reloadMgr:  reloadMgr,
		healthMgr:  healthMgr,
		logger:     logger,
		startTime:  time.Now(),
		shutdownFn: shutdownFn,
		srv:        srv,
		zonesDir:   zonesDir,
		compileBin: compileBin,
		rrlLimiter: rrlLimiter,
	}
}

// FlushCache flushes cache entries based on criteria
func (s *Service) FlushCache(ctx context.Context, req *pb.AdminFlushCacheRequest) (*pb.AdminFlushCacheResponse, error) {
	var flushed uint64

	switch req.Type {
	case pb.AdminFlushCacheRequest_ALL:
		// Flush entire cache
		s.cache.Flush()
		stats := s.cache.GetStats()
		flushed = uint64(stats.Size)
		return &pb.AdminFlushCacheResponse{
			EntriesFlushed: flushed,
			Message:        "Entire cache flushed",
		}, nil

	case pb.AdminFlushCacheRequest_BY_NAME:
		// Flush specific name
		if req.Name == "" {
			return nil, fmt.Errorf("name required for BY_NAME flush")
		}
		// Calculate hash for the name
		hash := cache.HashKey(req.Name, 1, 1) // Type A, Class IN
		s.cache.Delete(hash)
		flushed = 1
		return &pb.AdminFlushCacheResponse{
			EntriesFlushed: 1,
			Message:        fmt.Sprintf("Flushed cache for %s", req.Name),
		}, nil

	case pb.AdminFlushCacheRequest_BY_DOMAIN:
		// Flush all entries under domain
		if req.Name == "" {
			return nil, fmt.Errorf("domain required for BY_DOMAIN flush")
		}
		flushed = s.flushByPattern(req.Name + "*")
		return &pb.AdminFlushCacheResponse{
			EntriesFlushed: flushed,
			Message:        fmt.Sprintf("Flushed %d entries for domain %s", flushed, req.Name),
		}, nil

	case pb.AdminFlushCacheRequest_BY_TLD:
		// Flush entire TLD
		if req.Name == "" {
			return nil, fmt.Errorf("TLD required for BY_TLD flush")
		}
		flushed = s.flushByPattern("*." + req.Name)
		return &pb.AdminFlushCacheResponse{
			EntriesFlushed: flushed,
			Message:        fmt.Sprintf("Flushed %d entries for TLD .%s", flushed, req.Name),
		}, nil

	case pb.AdminFlushCacheRequest_NEGATIVE_ONLY:
		// Flush only negative cache entries
		flushed = s.flushNegativeEntries()
		return &pb.AdminFlushCacheResponse{
			EntriesFlushed: flushed,
			Message:        fmt.Sprintf("Flushed %d negative cache entries", flushed),
		}, nil

	case pb.AdminFlushCacheRequest_EXPIRED_ONLY:
		// Flush expired entries
		flushed = s.flushExpiredEntries()
		return &pb.AdminFlushCacheResponse{
			EntriesFlushed: flushed,
			Message:        fmt.Sprintf("Flushed %d expired entries", flushed),
		}, nil

	default:
		return nil, fmt.Errorf("unknown flush type: %v", req.Type)
	}
}

// GetCacheStats returns current cache statistics
func (s *Service) GetCacheStats(ctx context.Context, req *emptypb.Empty) (*pb.AdminCacheStatsResponse, error) {
	stats := s.cache.GetStats()

	return &pb.AdminCacheStatsResponse{
		Hits:        stats.Hits,
		Misses:      stats.Misses,
		Evictions:   stats.Evictions,
		Expirations: stats.Expirations,
		Size:        int32(stats.Size),
		HitRate:     stats.HitRate,
		MemoryBytes: stats.MemoryBytes,
		MaxMemory:   stats.MaxMemory,
	}, nil
}

// PurgeCache purges entries matching a pattern
func (s *Service) PurgeCache(ctx context.Context, req *pb.AdminPurgeCacheRequest) (*pb.AdminPurgeCacheResponse, error) {
	var samples []string
	var toDelete []uint64

	if req.Regex {
		// Compile regex pattern
		re, err := regexp.Compile(req.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}

		// Phase 1: Collect hashes to delete (read-only)
		s.cache.ForEach(func(hash uint64, entry *cache.Entry) {
			if re.MatchString(entry.QName) {
				toDelete = append(toDelete, hash)
				if len(samples) < 10 {
					samples = append(samples, entry.QName)
				}
			}
		})

		// Phase 2: Delete collected hashes
		for _, hash := range toDelete {
			s.cache.Delete(hash)
		}
	} else {
		// Glob pattern matching (already uses two-phase approach)
		purged := s.flushByPattern(req.Pattern)
		return &pb.AdminPurgeCacheResponse{
			EntriesPurged: purged,
			Samples:       nil, // flushByPattern doesn't collect samples
		}, nil
	}

	return &pb.AdminPurgeCacheResponse{
		EntriesPurged: uint64(len(toDelete)),
		Samples:       samples,
	}, nil
}

// RefreshZone forces a zone refresh
func (s *Service) RefreshZone(ctx context.Context, req *pb.AdminRefreshZoneRequest) (*pb.AdminRefreshZoneResponse, error) {
	// Trigger zone reload for specific zone
	err := s.reloadMgr.Reload()
	if err != nil {
		return &pb.AdminRefreshZoneResponse{
			Refreshed: false,
			Message:   fmt.Sprintf("Zone refresh failed: %v", err),
		}, nil
	}

	zone, ok := s.reloadMgr.GetZone(req.ZoneName)
	if !ok {
		return &pb.AdminRefreshZoneResponse{
			Refreshed: false,
			Message:   fmt.Sprintf("Zone %s not found", req.ZoneName),
		}, nil
	}

	stats := zone.GetStats()
	return &pb.AdminRefreshZoneResponse{
		Refreshed:     true,
		Message:       fmt.Sprintf("Zone %s refreshed successfully", req.ZoneName),
		RecordsLoaded: int32(stats.Records),
	}, nil
}

// ListZones lists all loaded zones
func (s *Service) ListZones(ctx context.Context, req *emptypb.Empty) (*pb.AdminListZonesResponse, error) {
	zones := s.reloadMgr.GetAllZones()
	zoneInfos := make([]*pb.AdminZoneInfo, 0, len(zones))

	for name, zone := range zones {
		stats := zone.GetStats()
		zoneInfos = append(zoneInfos, &pb.AdminZoneInfo{
			Name:        name,
			RecordCount: int32(stats.Records),
			LastLoaded:  timestamppb.New(s.reloadMgr.GetLastReload()),
			SourceFile:  "", // Would need to track this
			Compiled:    false,
			Serial:      0, // Would need to extract from SOA
		})
	}

	return &pb.AdminListZonesResponse{
		Zones: zoneInfos,
	}, nil
}

// ReloadZones reloads all zones from disk
func (s *Service) ReloadZones(ctx context.Context, req *emptypb.Empty) (*pb.AdminReloadZonesResponse, error) {
	err := s.reloadMgr.Reload()

	if err != nil {
		return &pb.AdminReloadZonesResponse{
			ZonesReloaded: 0,
			Message:       fmt.Sprintf("Reload failed: %v", err),
		}, nil
	}

	zoneCount := s.reloadMgr.ZoneCount()
	return &pb.AdminReloadZonesResponse{
		ZonesReloaded: int32(zoneCount),
		FailedZones:   []string{},
		Message:       fmt.Sprintf("Successfully reloaded %d zones", zoneCount),
	}, nil
}

// SetQueryLogging enables/disables query logging
func (s *Service) SetQueryLogging(ctx context.Context, req *pb.AdminSetQueryLoggingRequest) (*pb.AdminSetQueryLoggingResponse, error) {
	// This would require adding methods to the logging package to dynamically enable/disable
	// For now, return not implemented
	return &pb.AdminSetQueryLoggingResponse{
		Success: false,
		Message: "Dynamic query logging control not yet implemented",
	}, nil
}

// GetQueryLoggingStatus returns query logging status
func (s *Service) GetQueryLoggingStatus(ctx context.Context, req *emptypb.Empty) (*pb.AdminQueryLoggingStatusResponse, error) {
	// Would need to query logging configuration
	return &pb.AdminQueryLoggingStatusResponse{
		Enabled:        false,
		LogPath:        "",
		Format:         "",
		QueriesLogged:  0,
		LogSizeBytes:   0,
	}, nil
}

// SetRateLimit adjusts rate limiting configuration
func (s *Service) SetRateLimit(ctx context.Context, req *pb.AdminSetRateLimitRequest) (*pb.AdminSetRateLimitResponse, error) {
	// Would require adding methods to rate limiter for dynamic updates
	return &pb.AdminSetRateLimitResponse{
		Success: false,
		Message: "Dynamic rate limit control not yet implemented",
	}, nil
}

// GetRateLimitStatus returns rate limiting status
func (s *Service) GetRateLimitStatus(ctx context.Context, req *emptypb.Empty) (*pb.AdminRateLimitStatusResponse, error) {
	// Would need to query rate limiter
	return &pb.AdminRateLimitStatusResponse{
		Enabled:              false,
		ResponsesPerSecond:   0,
		ErrorsPerSecond:      0,
		NxdomainsPerSecond:   0,
		TotalDropped:         0,
		TotalSlipped:         0,
	}, nil
}

// GetServerStatus returns server health and status
func (s *Service) GetServerStatus(ctx context.Context, req *emptypb.Empty) (*pb.AdminServerStatusResponse, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	components := []*pb.AdminComponentStatus{
		{
			Name:    "cache",
			Healthy: s.healthMgr.IsHealthy(),
			Message: "OK",
		},
		{
			Name:    "zones",
			Healthy: s.reloadMgr.ZoneCount() > 0,
			Message: fmt.Sprintf("%d zones loaded", s.reloadMgr.ZoneCount()),
		},
	}

	return &pb.AdminServerStatusResponse{
		Version:      "1.0.0", // Would pull from build info
		StartTime:    timestamppb.New(s.startTime),
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
		Goroutines:   int32(runtime.NumGoroutine()),
		MemoryBytes:  int64(m.Alloc),
		ZonesLoaded:  int32(s.reloadMgr.ZoneCount()),
		Healthy:      s.healthMgr.IsHealthy(),
		Components:   components,
	}, nil
}

// GetMetrics returns server metrics
func (s *Service) GetMetrics(ctx context.Context, req *emptypb.Empty) (*pb.AdminMetricsResponse, error) {
	stats := s.cache.GetStats()

	return &pb.AdminMetricsResponse{
		QueriesTotal:    stats.Hits + stats.Misses,
		QueriesUdp:      0, // Would need to track
		QueriesTcp:      0, // Would need to track
		CacheHits:       stats.Hits,
		CacheMisses:     stats.Misses,
		UpstreamFailures: 0, // Would need to track
		AvgLatencyMs:    0.0,
		P99LatencyMs:    0.0,
	}, nil
}

// ShutdownServer gracefully shuts down the server
func (s *Service) ShutdownServer(ctx context.Context, req *pb.AdminShutdownRequest) (*pb.AdminShutdownResponse, error) {
	if s.shutdownFn == nil {
		return &pb.AdminShutdownResponse{
			Success: false,
			Message: "Shutdown function not configured",
		}, nil
	}

	// Trigger graceful shutdown
	go func() {
		time.Sleep(time.Duration(req.GracePeriodSeconds) * time.Second)
		s.shutdownFn()
	}()

	return &pb.AdminShutdownResponse{
		Success: true,
		Message: fmt.Sprintf("Server shutdown initiated with %d second grace period", req.GracePeriodSeconds),
	}, nil
}

// ListConnections lists active connections
func (s *Service) ListConnections(ctx context.Context, req *pb.AdminListConnectionsRequest) (*pb.AdminListConnectionsResponse, error) {
	// Would require tracking connections in the transport layer
	return &pb.AdminListConnectionsResponse{
		Connections: []*pb.AdminConnectionInfo{},
		TotalCount:  0,
	}, nil
}

// KillConnection terminates a specific connection
func (s *Service) KillConnection(ctx context.Context, req *pb.AdminKillConnectionRequest) (*pb.AdminKillConnectionResponse, error) {
	// Would require connection tracking and termination capability
	return &pb.AdminKillConnectionResponse{
		Success: false,
		Message: "Connection management not yet implemented",
	}, nil
}

// Helper functions

func (s *Service) flushByPattern(pattern string) uint64 {
	// Pre-compile regex pattern for performance
	regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return 0
	}

	// Phase 1: Collect hashes to delete (read-only)
	var toDelete []uint64
	s.cache.ForEach(func(hash uint64, entry *cache.Entry) {
		if re.MatchString(entry.QName) {
			toDelete = append(toDelete, hash)
		}
	})

	// Phase 2: Delete collected hashes
	for _, hash := range toDelete {
		s.cache.Delete(hash)
	}

	return uint64(len(toDelete))
}

func (s *Service) flushNegativeEntries() uint64 {
	// Phase 1: Collect hashes to delete (read-only)
	var toDelete []uint64
	s.cache.ForEach(func(hash uint64, entry *cache.Entry) {
		if entry.IsNegative {
			toDelete = append(toDelete, hash)
		}
	})

	// Phase 2: Delete collected hashes
	for _, hash := range toDelete {
		s.cache.Delete(hash)
	}

	return uint64(len(toDelete))
}

func (s *Service) flushExpiredEntries() uint64 {
	// Phase 1: Collect hashes to delete (read-only)
	var toDelete []uint64
	s.cache.ForEach(func(hash uint64, entry *cache.Entry) {
		if entry.IsExpired() {
			toDelete = append(toDelete, hash)
		}
	})

	// Phase 2: Delete collected hashes
	for _, hash := range toDelete {
		s.cache.Delete(hash)
	}

	return uint64(len(toDelete))
}
