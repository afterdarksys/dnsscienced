package admin

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpcserver "github.com/dnsscience/dnsscienced/api/grpc/server"
	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/catalog"
	"github.com/dnsscience/dnsscienced/internal/eventbus"
	"github.com/dnsscience/dnsscienced/internal/health"
	"github.com/dnsscience/dnsscienced/internal/logging"
	"github.com/dnsscience/dnsscienced/internal/reload"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/tsig"
	"github.com/dnsscience/dnsscienced/internal/zone"

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
	GetTsigKeyRing() *tsig.KeyRing
	GetZoneNames() []string
}

// CatalogStatusSource exposes a read-only, bounded operator view without
// allowing the admin plane to mutate reconciliation state.
type CatalogStatusSource interface {
	Statuses() []catalog.Status
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
	srv          AdminSrvAdapter
	zonesDir     string
	compileBin   string
	rrlLimiter   *rrl.Limiter             // may be nil; nil-guarded at call sites
	tsigKeyRing  *tsig.KeyRing            // may be nil; set from server's key ring
	connRegistry *grpcserver.ConnRegistry // may be nil; wired in Plan 04 (conn tracking)
	bus          *eventbus.Bus            // may be nil; provides real-time query stream
	catalogs     CatalogStatusSource      // may be nil when catalog zones are disabled
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
	tsigKeyRing *tsig.KeyRing, // may be nil
	connRegistry *grpcserver.ConnRegistry, // may be nil; wired in Plan 04
	bus *eventbus.Bus, // may be nil; enables WatchQueryEvents
	catalogs CatalogStatusSource, // may be nil when catalog zones are disabled
) *Service {
	return &Service{
		cache:        cache,
		reloadMgr:    reloadMgr,
		healthMgr:    healthMgr,
		logger:       logger,
		startTime:    time.Now(),
		shutdownFn:   shutdownFn,
		srv:          srv,
		zonesDir:     zonesDir,
		compileBin:   compileBin,
		rrlLimiter:   rrlLimiter,
		tsigKeyRing:  tsigKeyRing,
		connRegistry: connRegistry,
		bus:          bus,
		catalogs:     catalogs,
	}
}

// SetConnRegistry wires the connection registry post-construction.
// Called from main.go after grpcserver.New() returns the ConnRegistry.
func (s *Service) SetConnRegistry(reg *grpcserver.ConnRegistry) {
	s.connRegistry = reg
}

// validateZoneName rejects names containing path traversal sequences.
func validateZoneName(name string) error {
	if name == "" {
		return status.Error(codes.InvalidArgument, "zone_name is required")
	}
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		return status.Error(codes.InvalidArgument, "zone_name must not contain '/' or '..'")
	}
	return nil
}

// compileZone runs the external compiler binary.
func (s *Service) compileZone(ctx context.Context, inputPath, outputPath string) error {
	if s.compileBin == "" {
		return fmt.Errorf("compileBin not configured")
	}
	cmd := exec.CommandContext(ctx, s.compileBin, "-input", inputPath, "-output", outputPath, "-verify")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compiler failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CreateZone creates a new zone from zone_content, compiles it, and loads it into the server.
func (s *Service) CreateZone(ctx context.Context, req *pb.AdminCreateZoneRequest) (*pb.AdminCreateZoneResponse, error) {
	if err := validateZoneName(req.ZoneName); err != nil {
		return nil, err
	}
	if s.zonesDir == "" {
		return nil, status.Error(codes.Internal, "zonesDir not configured")
	}
	if s.srv == nil {
		return nil, status.Error(codes.Internal, "server adapter not configured")
	}

	domain := strings.TrimSuffix(req.ZoneName, ".")
	origin := dns.Fqdn(domain)

	// Conflict check
	if existing := s.srv.GetZone(origin); existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "zone %s already exists", origin)
	}

	dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
	dzcPath := filepath.Join(s.zonesDir, domain+".dzc")

	// Write zone content
	if err := os.WriteFile(dnszonePath, []byte(req.ZoneContent), 0644); err != nil {
		return nil, status.Errorf(codes.Internal, "write zone file: %v", err)
	}

	// Always compile — dzc required for LoadCompiledZone
	if err := s.compileZone(ctx, dnszonePath, dzcPath); err != nil {
		return nil, status.Errorf(codes.Internal, "compile zone: %v", err)
	}

	z, err := zone.LoadCompiledZone(dzcPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load compiled zone: %v", err)
	}
	if err := s.srv.AddZone(z); err != nil {
		return nil, status.Errorf(codes.Internal, "add zone: %v", err)
	}

	stats := z.GetStats()
	return &pb.AdminCreateZoneResponse{
		Success:      true,
		Message:      fmt.Sprintf("Zone %s created with %d records", origin, stats.Records),
		RecordCount:  int32(stats.Records),
		ZoneFilePath: dnszonePath,
	}, nil
}

// UpdateZone overwrites the zone file and optionally hot-reloads.
func (s *Service) UpdateZone(ctx context.Context, req *pb.AdminUpdateZoneRequest) (*pb.AdminUpdateZoneResponse, error) {
	if err := validateZoneName(req.ZoneName); err != nil {
		return nil, err
	}
	if s.zonesDir == "" || s.srv == nil {
		return nil, status.Error(codes.Internal, "server not configured")
	}

	domain := strings.TrimSuffix(req.ZoneName, ".")
	dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
	dzcPath := filepath.Join(s.zonesDir, domain+".dzc")

	if err := os.WriteFile(dnszonePath, []byte(req.ZoneContent), 0644); err != nil {
		return nil, status.Errorf(codes.Internal, "write zone file: %v", err)
	}

	if req.Compile || req.Reload {
		if err := s.compileZone(ctx, dnszonePath, dzcPath); err != nil {
			return nil, status.Errorf(codes.Internal, "compile zone: %v", err)
		}
		if req.Reload {
			z, err := zone.LoadCompiledZone(dzcPath)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "load compiled zone: %v", err)
			}
			if err := s.srv.AddZone(z); err != nil {
				return nil, status.Errorf(codes.Internal, "reload zone: %v", err)
			}
			stats := z.GetStats()
			return &pb.AdminUpdateZoneResponse{
				Success:     true,
				Message:     fmt.Sprintf("Zone %s updated and reloaded (%d records)", dns.Fqdn(domain), stats.Records),
				RecordCount: int32(stats.Records),
			}, nil
		}
	}

	return &pb.AdminUpdateZoneResponse{
		Success: true,
		Message: fmt.Sprintf("Zone %s file updated (not reloaded)", dns.Fqdn(domain)),
	}, nil
}

// DeleteZone removes a zone from the server and optionally deletes its files.
func (s *Service) DeleteZone(ctx context.Context, req *pb.AdminDeleteZoneRequest) (*pb.AdminDeleteZoneResponse, error) {
	if err := validateZoneName(req.ZoneName); err != nil {
		return nil, err
	}
	if s.srv == nil {
		return nil, status.Error(codes.Internal, "server adapter not configured")
	}

	domain := strings.TrimSuffix(req.ZoneName, ".")
	origin := dns.Fqdn(domain)

	s.srv.RemoveZone(origin)

	if req.DeleteFiles && s.zonesDir != "" {
		_ = os.Remove(filepath.Join(s.zonesDir, domain+".dnszone"))
		_ = os.Remove(filepath.Join(s.zonesDir, domain+".dzc"))
	}

	return &pb.AdminDeleteZoneResponse{
		Success: true,
		Message: fmt.Sprintf("Zone %s removed", origin),
	}, nil
}

// GetZone returns AdminZoneInfo plus zone_content read from the .dnszone file.
func (s *Service) GetZone(ctx context.Context, req *pb.AdminGetZoneRequest) (*pb.AdminGetZoneResponse, error) {
	if err := validateZoneName(req.ZoneName); err != nil {
		return nil, err
	}
	if s.srv == nil {
		return nil, status.Error(codes.Internal, "server adapter not configured")
	}

	domain := strings.TrimSuffix(req.ZoneName, ".")
	origin := dns.Fqdn(domain)

	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", origin)
	}

	stats := z.GetStats()
	serial := uint32(0)
	if z.SOA != nil {
		serial = z.SOA.Serial
	}

	dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
	dzcPath := filepath.Join(s.zonesDir, domain+".dzc")
	_, compiledErr := os.Stat(dzcPath)

	content, _ := os.ReadFile(dnszonePath) // best-effort; empty if file missing

	return &pb.AdminGetZoneResponse{
		Zone: &pb.AdminZoneInfo{
			Name:        origin,
			RecordCount: int32(stats.Records),
			LastLoaded:  timestamppb.Now(),
			SourceFile:  dnszonePath,
			Compiled:    compiledErr == nil,
			Serial:      serial,
		},
		ZoneContent: string(content),
	}, nil
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
	if s.reloadMgr == nil {
		return &pb.AdminRefreshZoneResponse{Refreshed: false, Message: "reload manager not configured"}, nil
	}
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

// ListZones lists all loaded zones with SourceFile, Compiled, and Serial fields.
func (s *Service) ListZones(ctx context.Context, req *emptypb.Empty) (*pb.AdminListZonesResponse, error) {
	var zoneInfos []*pb.AdminZoneInfo

	if s.reloadMgr != nil {
		// Primary path: use reloadMgr when available.
		zones := s.reloadMgr.GetAllZones()
		zoneInfos = make([]*pb.AdminZoneInfo, 0, len(zones))
		for name, z := range zones {
			zoneInfos = append(zoneInfos, s.buildZoneInfo(name, z))
		}
	} else if s.srv != nil {
		// Fallback: enumerate zones from the live server (ADMIN-LISTZONES-01).
		names := s.srv.GetZoneNames()
		zoneInfos = make([]*pb.AdminZoneInfo, 0, len(names))
		for _, name := range names {
			z := s.srv.GetZone(name)
			if z != nil {
				zoneInfos = append(zoneInfos, s.buildZoneInfo(name, z))
			}
		}
	}

	return &pb.AdminListZonesResponse{Zones: zoneInfos}, nil
}

// buildZoneInfo constructs an AdminZoneInfo from a zone name and Zone object.
func (s *Service) buildZoneInfo(name string, z *zone.Zone) *pb.AdminZoneInfo {
	domain := strings.TrimSuffix(name, ".")
	dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
	dzcPath := filepath.Join(s.zonesDir, domain+".dzc")
	_, compiledErr := os.Stat(dzcPath)

	serial := uint32(0)
	if z.SOA != nil {
		serial = z.SOA.Serial
	}

	stats := z.GetStats()
	info := &pb.AdminZoneInfo{
		Name:        name,
		RecordCount: int32(stats.Records),
		SourceFile:  dnszonePath,
		Compiled:    compiledErr == nil,
		Serial:      serial,
	}
	if s.reloadMgr != nil {
		info.LastLoaded = timestamppb.New(s.reloadMgr.GetLastReload())
	}
	return info
}

// ReloadZones reloads all zones from disk
func (s *Service) ReloadZones(ctx context.Context, req *emptypb.Empty) (*pb.AdminReloadZonesResponse, error) {
	if s.reloadMgr == nil {
		return &pb.AdminReloadZonesResponse{Message: "reload manager not configured"}, nil
	}
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

// adminBuildRR constructs a dns.RR from the admin proto fields.
// Handles A, AAAA, CNAME, MX, TXT, NS; falls back to generic for others.
func adminBuildRR(owner, rtype, content string, ttl uint32, priority int32, origin string) (dns.RR, error) {
	if rtype == "" {
		return nil, fmt.Errorf("record_type is required")
	}

	// Normalize owner to FQDN
	if owner == "" || owner == "@" {
		owner = origin
	} else if owner[len(owner)-1] != '.' {
		owner = strings.ToLower(owner) + "." + origin
	}
	owner = strings.ToLower(owner)

	dnsType, ok := dns.StringToType[strings.ToUpper(rtype)]
	if !ok {
		return nil, fmt.Errorf("unknown record type: %s", rtype)
	}

	ttlVal := ttl
	if ttlVal == 0 {
		ttlVal = 3600
	}

	hdr := dns.RR_Header{Name: owner, Rrtype: dnsType, Class: dns.ClassINET, Ttl: ttlVal}

	switch dnsType {
	case dns.TypeA:
		ip := net.ParseIP(content)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP for A record: %s", content)
		}
		return &dns.A{Hdr: hdr, A: ip.To4()}, nil
	case dns.TypeAAAA:
		ip := net.ParseIP(content)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP for AAAA record: %s", content)
		}
		return &dns.AAAA{Hdr: hdr, AAAA: ip.To16()}, nil
	case dns.TypeCNAME:
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(content)}, nil
	case dns.TypeMX:
		pref := uint16(priority)
		return &dns.MX{Hdr: hdr, Preference: pref, Mx: dns.Fqdn(content)}, nil
	case dns.TypeTXT:
		return &dns.TXT{Hdr: hdr, Txt: []string{content}}, nil
	case dns.TypeNS:
		return &dns.NS{Hdr: hdr, Ns: dns.Fqdn(content)}, nil
	default:
		// Generic fallback using dns.NewRR
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", owner, ttlVal, rtype, content))
		if err != nil {
			return nil, fmt.Errorf("cannot build RR for type %s: %v", rtype, err)
		}
		return rr, nil
	}
}

// adminMakeRecordID returns "owner:type:content" — matches ManagementService format.
func adminMakeRecordID(owner, rtype, content string) string {
	return fmt.Sprintf("%s:%s:%s", owner, strings.ToUpper(rtype), content)
}

// adminParseRecordID splits "owner:type:content" — at most 3 parts.
func adminParseRecordID(id string) (owner, rtype, content string, err error) {
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid record_id %q: expected owner:type:content", id)
	}
	return parts[0], parts[1], parts[2], nil
}

// adminRemoveRecord removes a record matching id (owner:type:content) from the zone's in-memory map.
// Zone has no RemoveRecord method — we implement it inline here using GetAllRecords + AddRecord.
func adminRemoveRecord(z *zone.Zone, id string) {
	owner, rtype, content, err := adminParseRecordID(id)
	if err != nil {
		return
	}
	dnsType, ok := dns.StringToType[strings.ToUpper(rtype)]
	if !ok {
		return
	}
	ownerKey := strings.ToLower(owner)
	typeMap, exists := z.Records[ownerKey]
	if !exists {
		return
	}
	existing := typeMap[dnsType]
	var kept []dns.RR
	for _, rr := range existing {
		// Build content string the same way ListRecords does
		hdr := rr.Header()
		rrContent := strings.TrimSpace(strings.TrimPrefix(rr.String(), hdr.String()))
		if rrContent != content {
			kept = append(kept, rr)
		}
	}
	if len(kept) == 0 {
		delete(typeMap, dnsType)
		if len(typeMap) == 0 {
			delete(z.Records, ownerKey)
		}
	} else {
		typeMap[dnsType] = kept
	}
}

// CreateRecord adds a new record to a zone.
func (s *Service) CreateRecord(ctx context.Context, req *pb.AdminCreateRecordRequest) (*pb.AdminCreateRecordResponse, error) {
	if err := validateZoneName(req.ZoneName); err != nil {
		return nil, err
	}
	if s.srv == nil {
		return nil, status.Error(codes.Internal, "server adapter not configured")
	}

	domain := strings.TrimSuffix(req.ZoneName, ".")
	origin := dns.Fqdn(domain)

	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", origin)
	}

	rr, err := adminBuildRR(req.Owner, req.RecordType, req.Content, uint32(req.Ttl), req.Priority, origin)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "build record: %v", err)
	}

	if err := z.AddRecord(rr); err != nil {
		return nil, status.Errorf(codes.Internal, "add record: %v", err)
	}

	// Persist and hot-reload (best-effort; skip if zone serialization unavailable)
	if s.zonesDir != "" && s.compileBin != "" {
		dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
		dzcPath := filepath.Join(s.zonesDir, domain+".dzc")
		if data, serErr := zone.SerializeDNSZone(z); serErr == nil {
			_ = os.WriteFile(dnszonePath, data, 0644)
			if compErr := s.compileZone(ctx, dnszonePath, dzcPath); compErr == nil {
				if updated, loadErr := zone.LoadCompiledZone(dzcPath); loadErr == nil {
					_ = s.srv.AddZone(updated)
				}
			}
		}
	}

	recordID := adminMakeRecordID(rr.Header().Name, req.RecordType, req.Content)
	return &pb.AdminCreateRecordResponse{
		Success:  true,
		Message:  fmt.Sprintf("Record %s added to zone %s", recordID, origin),
		RecordId: recordID,
	}, nil
}

// UpdateRecord replaces an existing record (delete old + add new).
func (s *Service) UpdateRecord(ctx context.Context, req *pb.AdminUpdateRecordRequest) (*pb.AdminUpdateRecordResponse, error) {
	if err := validateZoneName(req.ZoneName); err != nil {
		return nil, err
	}
	if s.srv == nil {
		return nil, status.Error(codes.Internal, "server adapter not configured")
	}

	domain := strings.TrimSuffix(req.ZoneName, ".")
	origin := dns.Fqdn(domain)

	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", origin)
	}

	// Update = delete old + add new
	owner, rtype, _, err := adminParseRecordID(req.RecordId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	adminRemoveRecord(z, req.RecordId)

	newOwner := req.Owner
	if newOwner == "" {
		newOwner = owner
	}
	newType := req.RecordType
	if newType == "" {
		newType = rtype
	}

	rr, err := adminBuildRR(newOwner, newType, req.Content, uint32(req.Ttl), req.Priority, origin)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "build record: %v", err)
	}
	if err := z.AddRecord(rr); err != nil {
		return nil, status.Errorf(codes.Internal, "add record: %v", err)
	}

	return &pb.AdminUpdateRecordResponse{
		Success: true,
		Message: fmt.Sprintf("Record %s updated in zone %s", req.RecordId, origin),
	}, nil
}

// DeleteRecord removes a record from a zone.
func (s *Service) DeleteRecord(ctx context.Context, req *pb.AdminDeleteRecordRequest) (*pb.AdminDeleteRecordResponse, error) {
	if err := validateZoneName(req.ZoneName); err != nil {
		return nil, err
	}
	if s.srv == nil {
		return nil, status.Error(codes.Internal, "server adapter not configured")
	}

	domain := strings.TrimSuffix(req.ZoneName, ".")
	origin := dns.Fqdn(domain)

	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", origin)
	}

	adminRemoveRecord(z, req.RecordId)
	return &pb.AdminDeleteRecordResponse{
		Success: true,
		Message: fmt.Sprintf("Record %s removed from zone %s", req.RecordId, origin),
	}, nil
}

// ListRecords lists all records in a zone with optional type/owner filters.
func (s *Service) ListRecords(ctx context.Context, req *pb.AdminListRecordsRequest) (*pb.AdminListRecordsResponse, error) {
	if err := validateZoneName(req.ZoneName); err != nil {
		return nil, err
	}
	if s.srv == nil {
		return nil, status.Error(codes.Internal, "server adapter not configured")
	}

	domain := strings.TrimSuffix(req.ZoneName, ".")
	origin := dns.Fqdn(domain)

	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", origin)
	}

	filterType := strings.ToUpper(req.RecordType)
	filterOwner := strings.ToLower(req.Owner)

	var records []*pb.AdminRecordInfo
	for _, rr := range z.GetAllRecords() {
		hdr := rr.Header()
		rrtype := dns.TypeToString[hdr.Rrtype]
		owner := hdr.Name
		content := strings.TrimSpace(strings.TrimPrefix(rr.String(), hdr.String()))

		if filterType != "" && rrtype != filterType {
			continue
		}
		if filterOwner != "" && !strings.HasPrefix(strings.ToLower(owner), filterOwner) {
			continue
		}

		records = append(records, &pb.AdminRecordInfo{
			RecordId:   adminMakeRecordID(owner, rrtype, content),
			Owner:      owner,
			RecordType: rrtype,
			Content:    content,
			Ttl:        int32(hdr.Ttl),
		})
	}

	return &pb.AdminListRecordsResponse{
		Records:    records,
		TotalCount: int32(len(records)),
	}, nil
}

// SetQueryLogging enables/disables query logging via the live logger.
func (s *Service) SetQueryLogging(ctx context.Context, req *pb.AdminSetQueryLoggingRequest) (*pb.AdminSetQueryLoggingResponse, error) {
	if s.logger == nil {
		return nil, status.Error(codes.Unimplemented, "logger not wired (wire in Phase 7)")
	}
	if err := s.logger.SetQueryLogEnabled(req.Enabled); err != nil {
		return &pb.AdminSetQueryLoggingResponse{
			Success: false,
			Message: fmt.Sprintf("failed to set query logging: %v", err),
		}, nil
	}
	state := "disabled"
	if req.Enabled {
		state = "enabled"
	}
	return &pb.AdminSetQueryLoggingResponse{
		Success: true,
		Message: fmt.Sprintf("Query logging %s", state),
	}, nil
}

// GetQueryLoggingStatus returns the live query logging state from the logger.
func (s *Service) GetQueryLoggingStatus(ctx context.Context, req *emptypb.Empty) (*pb.AdminQueryLoggingStatusResponse, error) {
	if s.logger == nil {
		return &pb.AdminQueryLoggingStatusResponse{Enabled: false}, nil
	}
	path, format := s.logger.QueryLogConfig()
	var sizeBytes int64
	if info, err := os.Stat(path); err == nil {
		sizeBytes = info.Size()
	}
	return &pb.AdminQueryLoggingStatusResponse{
		Enabled:       s.logger.IsQueryLogEnabled(),
		LogPath:       path,
		Format:        format,
		QueriesLogged: s.logger.QueriesLogged(),
		LogSizeBytes:  sizeBytes,
	}, nil
}

// SetRateLimit updates the rate limiter configuration.
func (s *Service) SetRateLimit(ctx context.Context, req *pb.AdminSetRateLimitRequest) (*pb.AdminSetRateLimitResponse, error) {
	if s.rrlLimiter == nil {
		return nil, status.Error(codes.Unimplemented, "rate limiter not wired (wire in Phase 7)")
	}
	cfg := s.rrlLimiter.GetConfig()
	cfg.Enabled = req.Enabled
	if req.ResponsesPerSecond > 0 {
		cfg.ResponsesPerSecond = int(req.ResponsesPerSecond)
	}
	if req.ErrorsPerSecond > 0 {
		cfg.ErrorsPerSecond = int(req.ErrorsPerSecond)
	}
	if req.NxdomainsPerSecond > 0 {
		cfg.NXDOMAINsPerSecond = int(req.NxdomainsPerSecond)
	}
	s.rrlLimiter.UpdateConfig(cfg)
	return &pb.AdminSetRateLimitResponse{
		Success: true,
		Message: fmt.Sprintf("Rate limit updated (enabled=%v, rps=%d)", cfg.Enabled, cfg.ResponsesPerSecond),
	}, nil
}

// GetRateLimitStatus returns the live rate limiter configuration and stats.
func (s *Service) GetRateLimitStatus(ctx context.Context, req *emptypb.Empty) (*pb.AdminRateLimitStatusResponse, error) {
	if s.rrlLimiter == nil {
		return &pb.AdminRateLimitStatusResponse{Enabled: false}, nil
	}
	cfg := s.rrlLimiter.GetConfig()
	stats := s.rrlLimiter.GetStats()
	return &pb.AdminRateLimitStatusResponse{
		Enabled:            cfg.Enabled,
		ResponsesPerSecond: int32(cfg.ResponsesPerSecond),
		ErrorsPerSecond:    int32(cfg.ErrorsPerSecond),
		NxdomainsPerSecond: int32(cfg.NXDOMAINsPerSecond),
		TotalDropped:       stats.Dropped,
		TotalSlipped:       stats.Slipped,
	}, nil
}

// GetServerStatus returns server health and status
func (s *Service) GetServerStatus(ctx context.Context, req *emptypb.Empty) (*pb.AdminServerStatusResponse, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	healthy := true
	if s.healthMgr != nil {
		healthy = s.healthMgr.IsHealthy()
	}

	zoneCount := 0
	if s.reloadMgr != nil {
		zoneCount = s.reloadMgr.ZoneCount()
	}

	components := []*pb.AdminComponentStatus{
		{
			Name:    "cache",
			Healthy: healthy,
			Message: "OK",
		},
		{
			Name:    "zones",
			Healthy: zoneCount > 0,
			Message: fmt.Sprintf("%d zones loaded", zoneCount),
		},
	}
	if s.catalogs != nil {
		for _, catalogStatus := range s.catalogs.Statuses() {
			catalogHealthy := catalogStatus.LastError == ""
			message := fmt.Sprintf(
				"serial=%d members=%d freshness=unknown",
				catalogStatus.Serial,
				catalogStatus.Members,
			)
			if !catalogStatus.LastSuccess.IsZero() {
				message = fmt.Sprintf(
					"serial=%d members=%d freshness=%s",
					catalogStatus.Serial,
					catalogStatus.Members,
					time.Since(catalogStatus.LastSuccess).Round(time.Second),
				)
			}
			if catalogStatus.LastError != "" {
				message += " last_error=" + catalogStatus.LastError
			}
			components = append(components, &pb.AdminComponentStatus{
				Name:    "catalog:" + catalogStatus.Name,
				Healthy: catalogHealthy,
				Message: message,
			})
			healthy = healthy && catalogHealthy
		}
	}

	return &pb.AdminServerStatusResponse{
		Version:       "1.0.0", // Would pull from build info
		StartTime:     timestamppb.New(s.startTime),
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
		Goroutines:    int32(runtime.NumGoroutine()),
		MemoryBytes:   int64(m.Alloc),
		ZonesLoaded:   int32(zoneCount),
		Healthy:       healthy,
		Components:    components,
	}, nil
}

// GetMetrics returns server metrics
func (s *Service) GetMetrics(ctx context.Context, req *emptypb.Empty) (*pb.AdminMetricsResponse, error) {
	resp := &pb.AdminMetricsResponse{
		AvgLatencyMs: 0.0, // TODO: add EMA tracking in a future phase
		P99LatencyMs: 0.0, // TODO: add histogram tracking in a future phase
	}

	// Live server stats (queries, UDP/TCP split, errors)
	if s.srv != nil {
		srvStats := s.srv.GetAdminStats()
		resp.QueriesTotal = srvStats.Queries
		resp.QueriesUdp = srvStats.UDPQueries
		resp.QueriesTcp = srvStats.TCPQueries
		resp.UpstreamFailures = srvStats.Errors
	}

	// Cache stats
	if s.cache != nil {
		cacheStats := s.cache.GetStats()
		resp.CacheHits = cacheStats.Hits
		resp.CacheMisses = cacheStats.Misses
	}

	return resp, nil
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

// ListConnections lists active admin gRPC connections from the connection registry.
// Returns real data from ConnRegistry wired in Plan 04 via grpc.StatsHandler.
func (s *Service) ListConnections(ctx context.Context, req *pb.AdminListConnectionsRequest) (*pb.AdminListConnectionsResponse, error) {
	if s.connRegistry == nil {
		return &pb.AdminListConnectionsResponse{}, nil
	}
	conns := s.connRegistry.List()
	infos := make([]*pb.AdminConnectionInfo, 0, len(conns))
	for _, c := range conns {
		host, portStr := grpcserver.SplitHostPort(c.RemoteAddr)
		port := int32(0)
		if p, err := strconv.ParseInt(portStr, 10, 32); err == nil {
			port = int32(p)
		}
		infos = append(infos, &pb.AdminConnectionInfo{
			Id:            c.ID,
			Protocol:      "grpc",
			ClientIp:      host,
			ClientPort:    port,
			ConnectedAt:   timestamppb.New(c.ConnectedAt),
			QueriesServed: c.QueriesServed,
			// D-12: KeyID and CertCN populated by auth interceptor via EnrichConn (Plan 05)
			// Not yet exposed in proto response fields; available via connRegistry for diagnostics
		})
	}
	return &pb.AdminListConnectionsResponse{
		Connections: infos,
		TotalCount:  int32(len(infos)),
	}, nil
}

// KillConnection returns success=false with an explanation of the API limitation.
// The gRPC v1.78.0 public API does not expose a CloseConn method; graceful shutdown
// or connection timeout must be used instead.
func (s *Service) KillConnection(ctx context.Context, req *pb.AdminKillConnectionRequest) (*pb.AdminKillConnectionResponse, error) {
	return &pb.AdminKillConnectionResponse{
		Success: false,
		Message: "connection teardown is not supported via the gRPC public API (no CloseConn in v1.78.0); use server restart or connection timeout",
	}, nil
}

// AddTsigKey adds a new TSIG key to the live key ring.
func (s *Service) AddTsigKey(ctx context.Context, req *pb.AdminAddTsigKeyRequest) (*pb.AdminAddTsigKeyResponse, error) {
	if s.tsigKeyRing == nil {
		return nil, status.Error(codes.FailedPrecondition, "TSIG key ring not configured (no keys in config)")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.Secret == "" {
		return nil, status.Error(codes.InvalidArgument, "secret is required")
	}

	cfg := tsig.KeyConfig{
		Name:      req.Name,
		Algorithm: req.Algorithm,
		Secret:    req.Secret,
	}
	if err := s.tsigKeyRing.Add(cfg); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "add TSIG key: %v", err)
	}

	return &pb.AdminAddTsigKeyResponse{
		Success: true,
		Message: fmt.Sprintf("TSIG key %q added (algorithm: %s)", req.Name, req.Algorithm),
	}, nil
}

// RemoveTsigKey removes a TSIG key from the live key ring.
func (s *Service) RemoveTsigKey(ctx context.Context, req *pb.AdminRemoveTsigKeyRequest) (*pb.AdminRemoveTsigKeyResponse, error) {
	if s.tsigKeyRing == nil {
		return nil, status.Error(codes.FailedPrecondition, "TSIG key ring not configured")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	if !s.tsigKeyRing.Remove(req.Name) {
		return nil, status.Errorf(codes.NotFound, "TSIG key %q not found", req.Name)
	}

	return &pb.AdminRemoveTsigKeyResponse{
		Success: true,
		Message: fmt.Sprintf("TSIG key %q removed", req.Name),
	}, nil
}

// ListTsigKeys returns all configured TSIG key names and algorithms (secrets are NOT returned).
func (s *Service) ListTsigKeys(ctx context.Context, req *emptypb.Empty) (*pb.AdminListTsigKeysResponse, error) {
	if s.tsigKeyRing == nil {
		return &pb.AdminListTsigKeysResponse{}, nil
	}

	algs := s.tsigKeyRing.Algorithms()
	keys := make([]*pb.TsigKeyInfo, 0, len(algs))
	for name, alg := range algs {
		keys = append(keys, &pb.TsigKeyInfo{
			Name:      name,
			Algorithm: alg,
		})
	}

	return &pb.AdminListTsigKeysResponse{Keys: keys}, nil
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

// WatchQueryEvents streams real-time DNS query events to the caller.
// The stream runs until the client disconnects or the server shuts down.
// An optional zone_filter on the request restricts events to a specific zone.
func (s *Service) WatchQueryEvents(req *pb.WatchQueryEventsRequest, stream pb.AdminService_WatchQueryEventsServer) error {
	if s.bus == nil {
		return status.Error(codes.Unavailable, "query event bus not configured")
	}

	sub := s.bus.Subscribe(stream.Context(), eventbus.TopicQuery)
	defer sub.Close()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev, ok := <-sub.Ch:
			if !ok {
				return nil
			}
			qe, ok := ev.Data.(eventbus.QueryEvent)
			if !ok {
				continue
			}
			// Apply zone filter when set
			if req.ZoneFilter != "" && qe.Zone != req.ZoneFilter {
				continue
			}
			msg := &pb.QueryEventMessage{
				Domain:       qe.Domain,
				Qtype:        qe.QType,
				Verdict:      qe.Verdict,
				Zone:         qe.Zone,
				ClientPrefix: qe.ClientPrefix,
				Protocol:     qe.Protocol,
				LatencyUs:    qe.LatencyUs,
				Timestamp:    timestamppb.New(time.Unix(0, qe.Timestamp)),
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}
