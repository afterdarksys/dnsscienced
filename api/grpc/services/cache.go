package services

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/afterdarksys/dnsscienced/api/grpc/ports"
	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"github.com/afterdarksys/dnsscienced/internal/cache"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CacheService struct {
	pb.UnimplementedCacheServiceServer
	Mgr    ports.CacheManager
	Scorer *cache.ThreatScorer
}

func NewCacheService(m ports.CacheManager, scorer *cache.ThreatScorer) *CacheService {
	return &CacheService{Mgr: m, Scorer: scorer}
}

func (s *CacheService) GetStats(ctx context.Context, in *pb.GetCacheStatsRequest) (*pb.GetCacheStatsResponse, error) {
	st, err := s.Mgr.Stats(ctx, in.GetBackend())
	if err != nil {
		return nil, err
	}
	return &pb.GetCacheStatsResponse{Stats: &pb.CacheStats{Entries: st.Entries, SizeBytes: st.SizeBytes, MaxBytes: st.MaxBytes, Utilization: float32(st.Utilization), Hits: st.Hits, Misses: st.Misses, HitRate: float32(st.HitRate), ByType: st.ByType, AvgTtlSeconds: st.AvgTTL, MinTtlSeconds: st.MinTTL, MaxTtlSeconds: st.MaxTTL, EvictionsTotal: st.Evictions, EvictionsByReason: st.EvictByReason, Backend: st.Backend}}, nil
}

func (s *CacheService) Lookup(ctx context.Context, in *pb.CacheLookupRequest) (*pb.CacheLookupResponse, error) {
	entries, err := s.Mgr.Lookup(ctx, in.GetName(), in.GetType())
	if err != nil {
		return nil, err
	}
	resp := &pb.CacheLookupResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &pb.CacheEntry{Name: e.Name, Type: e.Type, Class: e.Class, Ttl: e.TTL, OriginalTtl: e.OriginalTTL, Data: e.Data, Source: e.Source})
	}
	resp.Count = int32(len(resp.Entries))
	return resp, nil
}

func (s *CacheService) CheckURL(ctx context.Context, in *pb.CheckURLRequest) (*pb.CheckURLResponse, error) {
	if s.Scorer == nil {
		return nil, status.Error(codes.Unimplemented, "threat scorer not configured")
	}

	score, cats, err := s.Scorer.CheckURL(ctx, in.GetUrl())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check URL: %v", err)
	}

	blocked := score > 80
	var primaryCat string
	if len(cats) > 0 {
		primaryCat = cats[0]
	}

	return &pb.CheckURLResponse{
		Blocked:     blocked,
		ThreatScore: score,
		Category:    primaryCat,
	}, nil
}

func (s *CacheService) Flush(ctx context.Context, in *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
	fr, err := s.Mgr.Flush(ctx, in.GetScope().String(), in.GetDomain(), in.GetType(), in.GetIncludeSubdomains())
	if err != nil {
		return nil, err
	}
	return &pb.FlushCacheResponse{EntriesRemoved: fr.Removed, BytesFreed: fr.BytesFreed}, nil
}

func (s *CacheService) Prefetch(ctx context.Context, in *pb.PrefetchRequest) (*pb.PrefetchResponse, error) {
	pr, err := s.Mgr.Prefetch(ctx, in.GetNames(), in.GetTypes(), in.GetPriority())
	if err != nil {
		return nil, err
	}
	return &pb.PrefetchResponse{Queued: pr.Queued, Errors: pr.Errors}, nil
}

func (s *CacheService) WatchCache(req *pb.WatchCacheRequest, stream pb.CacheService_WatchCacheServer) error {
	// 1. Cast Manager to Subscriber interface
	type Subscriber interface {
		Subscribe() chan *pb.CacheEvent
		Unsubscribe(chan *pb.CacheEvent)
	}

	sub, ok := s.Mgr.(Subscriber)
	if !ok {
		return status.Error(codes.Unimplemented, "Cache manager does not support streaming")
	}

	// 2. Create subscription
	ch := sub.Subscribe()
	defer sub.Unsubscribe(ch)

	ctx := stream.Context()

	// 3. Optimize filters
	// Pre-calculate filter map for O(1) lookups
	filterTypes, err := cacheEventTypeFilter(req.GetTypes())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	domainPattern := normalizeDomainPattern(req.GetDomainPattern())
	if domainPattern != "" {
		if _, err := path.Match(domainPattern, "validation.example"); err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid domain_pattern: %v", err)
		}
	}

	// 4. Stream loop
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, open := <-ch:
			if !open {
				return nil
			}
			// Apply Filters
			if len(filterTypes) > 0 && !filterTypes[event.Type] {
				continue
			}
			if domainPattern != "" && !matchesDomainPattern(domainPattern, event.GetName()) {
				continue
			}

			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

func cacheEventTypeFilter(types []string) (map[pb.CacheEvent_EventType]bool, error) {
	result := make(map[pb.CacheEvent_EventType]bool, len(types))
	for _, requested := range types {
		name := strings.ToUpper(strings.TrimSpace(requested))
		if name == "" {
			continue
		}
		if !strings.HasPrefix(name, "EVENT_TYPE_") {
			name = "EVENT_TYPE_" + name
		}
		value, ok := pb.CacheEvent_EventType_value[name]
		if !ok || pb.CacheEvent_EventType(value) == pb.CacheEvent_EVENT_TYPE_UNSPECIFIED {
			return nil, fmt.Errorf("unknown cache event type %q", requested)
		}
		result[pb.CacheEvent_EventType(value)] = true
	}
	return result, nil
}

func normalizeDomainPattern(pattern string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
}

func matchesDomainPattern(pattern, name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	matched, err := path.Match(pattern, name)
	return err == nil && matched
}
