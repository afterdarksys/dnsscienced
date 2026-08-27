package services

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mgmt "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb/mgmt"
	"github.com/afterdarksys/dnsscienced/internal/admin"
	"github.com/afterdarksys/dnsscienced/internal/cache"
	"github.com/afterdarksys/dnsscienced/internal/firewalld"
	"github.com/afterdarksys/dnsscienced/internal/rrl"
	"github.com/afterdarksys/dnsscienced/internal/tsig"
	"github.com/afterdarksys/dnsscienced/internal/zone"
)

// SrvAdapter is the minimal interface ManagementService needs from the DNS server.
// Defined here to avoid importing internal/server (which would create an import cycle).
type SrvAdapter interface {
	Live() bool
	HandleDNS(ctx context.Context, req *dns.Msg, remoteAddr net.Addr) (*dns.Msg, error)
	GetZone(origin string) *zone.Zone
	AddZone(z *zone.Zone) error
	RemoveZone(origin string)
	GetStats() SrvStats
	GetFirewall() *firewalld.Firewall
	GetShardedCache() *cache.ShardedCache
	GetAdminStats() admin.AdminSrvStats
	GetTsigKeyRing() *tsig.KeyRing
	GetRRL() *rrl.Limiter
	GetZoneNames() []string
}

// SrvStats carries the statistics fields that ManagementService reads.
// Callers should populate this from server.Stats.
type SrvStats struct {
	Queries         uint64
	Answers         uint64
	Errors          uint64
	NXDomain        uint64
	UDPQueries      uint64 // queries received via UDP
	TCPQueries      uint64 // queries received via TCP
	RecursiveHits   uint64
	RecursiveMisses uint64
}

// ManagementService implements mgmt.ManagementServiceServer.
// It manages zones on disk (zonesDir) and delegates to a SrvAdapter for
// live in-memory zone operations.
type ManagementService struct {
	mgmt.UnimplementedManagementServiceServer
	srv        SrvAdapter
	zonesDir   string
	compileBin string
	startTime  time.Time
}

// NewManagementService constructs a ManagementService.
func NewManagementService(srv SrvAdapter, zonesDir string, compileBin string) *ManagementService {
	return &ManagementService{
		srv:        srv,
		zonesDir:   zonesDir,
		compileBin: compileBin,
		startTime:  time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Zone Management
// ---------------------------------------------------------------------------

// CreateZone creates a new DNS zone from the supplied request, writes the
// .dnszone file, compiles it, and loads it into the running server.
func (s *ManagementService) CreateZone(ctx context.Context, req *mgmt.CreateZoneRequest) (*mgmt.CreateZoneResponse, error) {
	if req.Domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain is required")
	}
	if s.zonesDir == "" {
		return nil, status.Error(codes.Internal, "zonesDir not configured")
	}

	// Normalise domain: no trailing dot for filenames, FQDN for DNS ops.
	domain := strings.TrimSuffix(req.Domain, ".")
	origin := dns.Fqdn(domain)

	ttl := req.Ttl
	if ttl <= 0 {
		ttl = 3600
	}

	// Build SOA section.
	soaSec := zone.SOASection{
		Serial:      "auto",
		Refresh:     "3600",
		Retry:       "600",
		Expire:      "604800",
		NegativeTTL: "1800",
	}
	primaryNS := ""
	if req.Soa != nil {
		if req.Soa.PrimaryNs != "" {
			soaSec.PrimaryNS = req.Soa.PrimaryNs
			primaryNS = req.Soa.PrimaryNs
		}
		if req.Soa.Contact != "" {
			soaSec.Contact = req.Soa.Contact
		}
		if req.Soa.Refresh > 0 {
			soaSec.Refresh = fmt.Sprintf("%d", req.Soa.Refresh)
		}
		if req.Soa.Retry > 0 {
			soaSec.Retry = fmt.Sprintf("%d", req.Soa.Retry)
		}
		if req.Soa.Expire > 0 {
			soaSec.Expire = fmt.Sprintf("%d", req.Soa.Expire)
		}
		if req.Soa.NegativeTtl > 0 {
			soaSec.NegativeTTL = fmt.Sprintf("%d", req.Soa.NegativeTtl)
		}
	}

	// Use first nameserver as primary NS if not set from SOA.
	if soaSec.PrimaryNS == "" && len(req.Nameservers) > 0 {
		soaSec.PrimaryNS = dns.Fqdn(req.Nameservers[0])
		primaryNS = soaSec.PrimaryNS
	}
	if soaSec.PrimaryNS == "" {
		soaSec.PrimaryNS = "ns1." + domain + "."
		primaryNS = soaSec.PrimaryNS
	}
	if soaSec.Contact == "" {
		soaSec.Contact = "hostmaster@" + domain
	}
	_ = primaryNS

	// Build records section: NS records + any initial records.
	records := make(map[string]zone.RecordSection)
	apexSec := zone.RecordSection{}

	// Add NS records at apex.
	if len(req.Nameservers) > 0 {
		if len(req.Nameservers) == 1 {
			apexSec.NS = dns.Fqdn(req.Nameservers[0])
		} else {
			ns := make([]interface{}, len(req.Nameservers))
			for i, n := range req.Nameservers {
				ns[i] = dns.Fqdn(n)
			}
			apexSec.NS = ns
		}
	}
	records["@"] = apexSec

	// Add initial records if supplied.
	for owner, rs := range req.InitialRecords {
		sec := zone.RecordSection{}
		if len(rs.Values) == 1 {
			sec.A = rs.Values[0]
		} else if len(rs.Values) > 1 {
			iface := make([]interface{}, len(rs.Values))
			for i, v := range rs.Values {
				iface[i] = v
			}
			sec.A = iface
		}
		records[owner] = sec
	}

	zf := zone.DNSZoneFile{
		Zone: zone.ZoneSection{
			Name:  domain,
			Class: "IN",
			TTL:   fmt.Sprintf("%d", ttl),
		},
		SOA:     soaSec,
		Records: records,
	}

	// Serialize to YAML.
	yamlData, err := zone.MarshalZoneFile(&zf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "serialize zone: %v", err)
	}

	dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
	dzcPath := filepath.Join(s.zonesDir, domain+".dzc")

	if err := os.WriteFile(dnszonePath, yamlData, 0644); err != nil {
		return nil, status.Errorf(codes.Internal, "write zone file: %v", err)
	}

	// Compile the zone.
	if err := s.compileZone(ctx, dnszonePath, dzcPath); err != nil {
		return nil, status.Errorf(codes.Internal, "compile zone: %v", err)
	}

	// Load compiled zone and register with server.
	z, err := zone.LoadCompiledZone(dzcPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load compiled zone: %v", err)
	}

	if err := s.srv.AddZone(z); err != nil {
		return nil, status.Errorf(codes.Internal, "add zone: %v", err)
	}

	return &mgmt.CreateZoneResponse{
		Success:     true,
		ZoneId:      domain,
		Nameservers: req.Nameservers,
		Message:     fmt.Sprintf("zone %s created", origin),
	}, nil
}

// DeleteZone removes a zone from the server and deletes its files on disk.
func (s *ManagementService) DeleteZone(ctx context.Context, req *mgmt.DeleteZoneRequest) (*mgmt.DeleteZoneResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}
	if s.zonesDir == "" {
		return nil, status.Error(codes.Internal, "zonesDir not configured")
	}

	domain := strings.TrimSuffix(req.ZoneId, ".")
	origin := dns.Fqdn(domain)

	s.srv.RemoveZone(origin)

	// Best-effort file removal; ignore errors.
	_ = os.Remove(filepath.Join(s.zonesDir, domain+".dnszone"))
	_ = os.Remove(filepath.Join(s.zonesDir, domain+".dzc"))

	return &mgmt.DeleteZoneResponse{
		Success: true,
		Message: fmt.Sprintf("zone %s deleted", origin),
	}, nil
}

// GetZone retrieves zone metadata for a single zone.
func (s *ManagementService) GetZone(ctx context.Context, req *mgmt.GetZoneRequest) (*mgmt.GetZoneResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}

	origin := dns.Fqdn(strings.TrimSuffix(req.ZoneId, "."))
	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", req.ZoneId)
	}

	return &mgmt.GetZoneResponse{
		Success: true,
		Zone:    zoneToPB(z),
	}, nil
}

// ListZones lists all zones currently loaded in the server.
func (s *ManagementService) ListZones(ctx context.Context, req *mgmt.ListZonesRequest) (*mgmt.ListZonesResponse, error) {
	if s.zonesDir == "" {
		return &mgmt.ListZonesResponse{Success: true}, nil
	}

	entries, err := os.ReadDir(s.zonesDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read zones dir: %v", err)
	}

	var zones []*mgmt.Zone
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".dzc") {
			continue
		}
		domain := strings.TrimSuffix(e.Name(), ".dzc")
		origin := dns.Fqdn(domain)
		z := s.srv.GetZone(origin)
		if z != nil {
			zones = append(zones, zoneToPB(z))
		}
	}

	// Apply limit/offset.
	total := int32(len(zones))
	offset := int(req.Offset)
	if offset > len(zones) {
		offset = len(zones)
	}
	zones = zones[offset:]
	if req.Limit > 0 && int(req.Limit) < len(zones) {
		zones = zones[:req.Limit]
	}

	return &mgmt.ListZonesResponse{
		Success: true,
		Zones:   zones,
		Total:   total,
	}, nil
}

// ReloadZones reloads one or more zones from their compiled .dzc files.
// If zone_ids is empty, all zones in zonesDir are reloaded.
func (s *ManagementService) ReloadZones(ctx context.Context, req *mgmt.ReloadZonesRequest) (*mgmt.ReloadZonesResponse, error) {
	if s.zonesDir == "" {
		return nil, status.Error(codes.Internal, "zonesDir not configured")
	}

	var toReload []string

	if len(req.ZoneIds) > 0 {
		for _, id := range req.ZoneIds {
			domain := strings.TrimSuffix(id, ".")
			toReload = append(toReload, domain)
		}
	} else {
		// Reload all .dzc files.
		entries, err := os.ReadDir(s.zonesDir)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read zones dir: %v", err)
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".dzc") {
				toReload = append(toReload, strings.TrimSuffix(e.Name(), ".dzc"))
			}
		}
	}

	reloaded := int32(0)
	var errs []string
	for _, domain := range toReload {
		dzcPath := filepath.Join(s.zonesDir, domain+".dzc")
		z, err := zone.LoadCompiledZone(dzcPath)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", domain, err))
			continue
		}
		if err := s.srv.AddZone(z); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", domain, err))
			continue
		}
		reloaded++
	}

	errMsg := strings.Join(errs, "; ")
	return &mgmt.ReloadZonesResponse{
		Success:       len(errs) == 0,
		ZonesReloaded: reloaded,
		Message:       fmt.Sprintf("reloaded %d zones", reloaded),
		Error:         errMsg,
	}, nil
}

// ---------------------------------------------------------------------------
// Record Management
// ---------------------------------------------------------------------------

// CreateRecord adds a single DNS record to an existing zone.
func (s *ManagementService) CreateRecord(ctx context.Context, req *mgmt.CreateRecordRequest) (*mgmt.CreateRecordResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}
	if req.Record == nil {
		return nil, status.Error(codes.InvalidArgument, "record is required")
	}

	origin := dns.Fqdn(strings.TrimSuffix(req.ZoneId, "."))
	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", req.ZoneId)
	}

	rr, err := buildRR(req.Record, origin)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "build record: %v", err)
	}

	if err := z.AddRecord(rr); err != nil {
		return nil, status.Errorf(codes.Internal, "add record: %v", err)
	}

	if err := s.serializeCompileReload(ctx, z, origin); err != nil {
		return nil, err
	}

	recordID := makeRecordID(req.Record.Name, req.Record.RecordType, req.Record.Content)
	return &mgmt.CreateRecordResponse{
		Success:  true,
		RecordId: recordID,
		Message:  "record created",
	}, nil
}

// UpdateRecord replaces an existing record identified by record_id.
func (s *ManagementService) UpdateRecord(ctx context.Context, req *mgmt.UpdateRecordRequest) (*mgmt.UpdateRecordResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}
	if req.RecordId == "" {
		return nil, status.Error(codes.InvalidArgument, "record_id is required")
	}
	if req.Record == nil {
		return nil, status.Error(codes.InvalidArgument, "record is required")
	}

	origin := dns.Fqdn(strings.TrimSuffix(req.ZoneId, "."))
	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", req.ZoneId)
	}

	oldOwner, oldType, oldContent, err := parseRecordID(req.RecordId, origin)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid record_id: %v", err)
	}

	// Remove old record.
	removeRecord(z, oldOwner, oldType, oldContent)

	// Add new record.
	rr, err := buildRR(req.Record, origin)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "build record: %v", err)
	}
	if err := z.AddRecord(rr); err != nil {
		return nil, status.Errorf(codes.Internal, "add record: %v", err)
	}

	if err := s.serializeCompileReload(ctx, z, origin); err != nil {
		return nil, err
	}

	return &mgmt.UpdateRecordResponse{Success: true, Message: "record updated"}, nil
}

// DeleteRecord removes a record identified by record_id from a zone.
func (s *ManagementService) DeleteRecord(ctx context.Context, req *mgmt.DeleteRecordRequest) (*mgmt.DeleteRecordResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}
	if req.RecordId == "" {
		return nil, status.Error(codes.InvalidArgument, "record_id is required")
	}

	origin := dns.Fqdn(strings.TrimSuffix(req.ZoneId, "."))
	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", req.ZoneId)
	}

	owner, rrtype, content, err := parseRecordID(req.RecordId, origin)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid record_id: %v", err)
	}

	removeRecord(z, owner, rrtype, content)

	if err := s.serializeCompileReload(ctx, z, origin); err != nil {
		return nil, err
	}

	return &mgmt.DeleteRecordResponse{Success: true, Message: "record deleted"}, nil
}

// ListRecords lists DNS records in a zone, optionally filtered by type.
func (s *ManagementService) ListRecords(ctx context.Context, req *mgmt.ListRecordsRequest) (*mgmt.ListRecordsResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}

	origin := dns.Fqdn(strings.TrimSuffix(req.ZoneId, "."))
	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", req.ZoneId)
	}

	var records []*mgmt.DNSRecord
	for owner, typeMap := range z.Records {
		for rrtype, rrs := range typeMap {
			if req.RecordType != "" {
				if dns.TypeToString[rrtype] != strings.ToUpper(req.RecordType) {
					continue
				}
			}
			for _, rr := range rrs {
				if pbRec := rrToPBRecord(rr, owner); pbRec != nil {
					records = append(records, pbRec)
				}
			}
		}
	}

	total := int32(len(records))
	offset := int(req.Offset)
	if offset > len(records) {
		offset = len(records)
	}
	records = records[offset:]
	if req.Limit > 0 && int(req.Limit) < len(records) {
		records = records[:req.Limit]
	}

	return &mgmt.ListRecordsResponse{
		Success: true,
		Records: records,
		Total:   total,
	}, nil
}

// ---------------------------------------------------------------------------
// Batch Operations
// ---------------------------------------------------------------------------

// BatchCreateRecords creates multiple records in a single compile/reload cycle.
func (s *ManagementService) BatchCreateRecords(ctx context.Context, req *mgmt.BatchCreateRecordsRequest) (*mgmt.BatchCreateRecordsResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}

	origin := dns.Fqdn(strings.TrimSuffix(req.ZoneId, "."))
	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", req.ZoneId)
	}

	var recordIDs []string
	var errs []string
	created := int32(0)

	for _, rec := range req.Records {
		rr, err := buildRR(rec, origin)
		if err != nil {
			errs = append(errs, fmt.Sprintf("build %s %s: %v", rec.Name, rec.RecordType, err))
			continue
		}
		if err := z.AddRecord(rr); err != nil {
			errs = append(errs, fmt.Sprintf("add %s %s: %v", rec.Name, rec.RecordType, err))
			continue
		}
		recordIDs = append(recordIDs, makeRecordID(rec.Name, rec.RecordType, rec.Content))
		created++
	}

	if created > 0 {
		if err := s.serializeCompileReload(ctx, z, origin); err != nil {
			return nil, err
		}
	}

	return &mgmt.BatchCreateRecordsResponse{
		Success:      len(errs) == 0,
		CreatedCount: created,
		RecordIds:    recordIDs,
		Errors:       errs,
		Message:      fmt.Sprintf("created %d records", created),
	}, nil
}

// BatchUpdateRecords updates multiple records in a single compile/reload cycle.
func (s *ManagementService) BatchUpdateRecords(ctx context.Context, req *mgmt.BatchUpdateRecordsRequest) (*mgmt.BatchUpdateRecordsResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}

	origin := dns.Fqdn(strings.TrimSuffix(req.ZoneId, "."))
	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", req.ZoneId)
	}

	var errs []string
	updated := int32(0)

	for _, upd := range req.Updates {
		if upd.Record == nil {
			errs = append(errs, fmt.Sprintf("update %s: nil record", upd.RecordId))
			continue
		}
		oldOwner, oldType, oldContent, err := parseRecordID(upd.RecordId, origin)
		if err != nil {
			errs = append(errs, fmt.Sprintf("parse record_id %s: %v", upd.RecordId, err))
			continue
		}
		removeRecord(z, oldOwner, oldType, oldContent)

		rr, err := buildRR(upd.Record, origin)
		if err != nil {
			errs = append(errs, fmt.Sprintf("build %s %s: %v", upd.Record.Name, upd.Record.RecordType, err))
			continue
		}
		if err := z.AddRecord(rr); err != nil {
			errs = append(errs, fmt.Sprintf("add %s %s: %v", upd.Record.Name, upd.Record.RecordType, err))
			continue
		}
		updated++
	}

	if updated > 0 {
		if err := s.serializeCompileReload(ctx, z, origin); err != nil {
			return nil, err
		}
	}

	return &mgmt.BatchUpdateRecordsResponse{
		Success:      len(errs) == 0,
		UpdatedCount: updated,
		Errors:       errs,
		Message:      fmt.Sprintf("updated %d records", updated),
	}, nil
}

// BatchDeleteRecords deletes multiple records in a single compile/reload cycle.
func (s *ManagementService) BatchDeleteRecords(ctx context.Context, req *mgmt.BatchDeleteRecordsRequest) (*mgmt.BatchDeleteRecordsResponse, error) {
	if req.ZoneId == "" {
		return nil, status.Error(codes.InvalidArgument, "zone_id is required")
	}

	origin := dns.Fqdn(strings.TrimSuffix(req.ZoneId, "."))
	z := s.srv.GetZone(origin)
	if z == nil {
		return nil, status.Errorf(codes.NotFound, "zone %s not found", req.ZoneId)
	}

	var errs []string
	deleted := int32(0)

	for _, rid := range req.RecordIds {
		owner, rrtype, content, err := parseRecordID(rid, origin)
		if err != nil {
			errs = append(errs, fmt.Sprintf("parse record_id %s: %v", rid, err))
			continue
		}
		removeRecord(z, owner, rrtype, content)
		deleted++
	}

	if deleted > 0 {
		if err := s.serializeCompileReload(ctx, z, origin); err != nil {
			return nil, err
		}
	}

	return &mgmt.BatchDeleteRecordsResponse{
		Success:      len(errs) == 0,
		DeletedCount: deleted,
		Errors:       errs,
		Message:      fmt.Sprintf("deleted %d records", deleted),
	}, nil
}

// ---------------------------------------------------------------------------
// Health & Status
// ---------------------------------------------------------------------------

// HealthCheck returns basic liveness information.
func (s *ManagementService) HealthCheck(ctx context.Context, req *mgmt.HealthCheckRequest) (*mgmt.HealthCheckResponse, error) {
	hostname, _ := os.Hostname()
	uptime := int64(time.Since(s.startTime).Seconds())
	return &mgmt.HealthCheckResponse{
		Healthy:       true,
		Version:       "1.0",
		UptimeSeconds: uptime,
		ServerName:    hostname,
	}, nil
}

// GetServerStatus returns detailed server status metrics.
func (s *ManagementService) GetServerStatus(ctx context.Context, req *mgmt.GetServerStatusRequest) (*mgmt.GetServerStatusResponse, error) {
	hostname, _ := os.Hostname()
	uptime := int64(time.Since(s.startTime).Seconds())

	stats := s.srv.GetStats()

	// Count loaded zones from .dzc files.
	zonesLoaded := int32(0)
	if s.zonesDir != "" {
		if entries, err := os.ReadDir(s.zonesDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".dzc") {
					zonesLoaded++
				}
			}
		}
	}

	// Gather memory stats.
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memMB := float64(memStats.Alloc) / (1024 * 1024)

	return &mgmt.GetServerStatusResponse{
		Success: true,
		Status: &mgmt.ServerStatus{
			ServerName:       hostname,
			Version:          "1.0",
			UptimeSeconds:    uptime,
			ZonesLoaded:      zonesLoaded,
			QueriesPerSecond: int64(stats.Queries),
			MemoryUsageMb:    memMB,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// serializeCompileReload persists the zone to disk, compiles it, and reloads it
// into the live server. Used after any record mutation.
func (s *ManagementService) serializeCompileReload(ctx context.Context, z *zone.Zone, origin string) error {
	if s.zonesDir == "" {
		return status.Error(codes.Internal, "zonesDir not configured")
	}

	domain := strings.TrimSuffix(origin, ".")
	dnszonePath := filepath.Join(s.zonesDir, domain+".dnszone")
	dzcPath := filepath.Join(s.zonesDir, domain+".dzc")

	data, err := zone.SerializeDNSZone(z)
	if err != nil {
		return status.Errorf(codes.Internal, "serialize zone: %v", err)
	}
	if err := os.WriteFile(dnszonePath, data, 0644); err != nil {
		return status.Errorf(codes.Internal, "write zone file: %v", err)
	}

	if err := s.compileZone(ctx, dnszonePath, dzcPath); err != nil {
		return status.Errorf(codes.Internal, "compile zone: %v", err)
	}

	updated, err := zone.LoadCompiledZone(dzcPath)
	if err != nil {
		return status.Errorf(codes.Internal, "load compiled zone: %v", err)
	}
	if err := s.srv.AddZone(updated); err != nil {
		return status.Errorf(codes.Internal, "reload zone: %v", err)
	}
	return nil
}

// compileZone runs the external compiler binary.
func (s *ManagementService) compileZone(ctx context.Context, inputPath, outputPath string) error {
	if s.compileBin == "" {
		return fmt.Errorf("compileBin not configured")
	}
	cmd := exec.CommandContext(ctx, s.compileBin,
		"-input", inputPath,
		"-output", outputPath,
		"-verify",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compiler failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// buildRR constructs a dns.RR from a protobuf DNSRecord.
func buildRR(rec *mgmt.DNSRecord, origin string) (dns.RR, error) {
	if rec == nil {
		return nil, fmt.Errorf("nil record")
	}
	if rec.RecordType == "" {
		return nil, fmt.Errorf("record_type is required")
	}

	rrtype, ok := dns.StringToType[strings.ToUpper(rec.RecordType)]
	if !ok {
		return nil, fmt.Errorf("unknown record type: %s", rec.RecordType)
	}

	// Build owner FQDN.
	ownerName := rec.Name
	if ownerName == "" || ownerName == "@" {
		ownerName = origin
	} else if ownerName[len(ownerName)-1] != '.' {
		// Relative name — qualify against zone origin.
		ownerName = strings.ToLower(ownerName) + "." + origin
	}
	ownerName = strings.ToLower(ownerName)

	ttl := uint32(rec.Ttl)
	if ttl == 0 {
		ttl = 3600
	}

	hdr := dns.RR_Header{
		Name:   ownerName,
		Rrtype: rrtype,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}

	switch rrtype {
	case dns.TypeA:
		ip := net.ParseIP(rec.Content)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", rec.Content)
		}
		return &dns.A{Hdr: hdr, A: ip.To4()}, nil

	case dns.TypeAAAA:
		ip := net.ParseIP(rec.Content)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", rec.Content)
		}
		return &dns.AAAA{Hdr: hdr, AAAA: ip.To16()}, nil

	case dns.TypeCNAME:
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(rec.Content)}, nil

	case dns.TypeNS:
		return &dns.NS{Hdr: hdr, Ns: dns.Fqdn(rec.Content)}, nil

	case dns.TypePTR:
		return &dns.PTR{Hdr: hdr, Ptr: dns.Fqdn(rec.Content)}, nil

	case dns.TypeMX:
		return &dns.MX{
			Hdr:        hdr,
			Preference: uint16(rec.Priority),
			Mx:         dns.Fqdn(rec.Content),
		}, nil

	case dns.TypeTXT:
		return &dns.TXT{Hdr: hdr, Txt: []string{rec.Content}}, nil

	case dns.TypeSRV:
		return &dns.SRV{
			Hdr:      hdr,
			Priority: uint16(rec.Priority),
			Weight:   uint16(rec.Weight),
			Port:     uint16(rec.Port),
			Target:   dns.Fqdn(rec.Content),
		}, nil

	default:
		// Generic fallback via dns.NewRR.
		rrStr := fmt.Sprintf("%s %d IN %s %s", ownerName, ttl, rec.RecordType, rec.Content)
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			return nil, fmt.Errorf("parse generic record: %w", err)
		}
		return rr, nil
	}
}

// zoneToPB converts a *zone.Zone to a protobuf Zone message.
func zoneToPB(z *zone.Zone) *mgmt.Zone {
	domain := strings.TrimSuffix(z.Origin, ".")
	zoneID := domain

	pb := &mgmt.Zone{
		Domain: domain,
		ZoneId: zoneID,
		Status: "active",
	}

	if z.SOA != nil {
		pb.Ttl = int32(z.SOA.Header().Ttl)
		pb.Soa = &mgmt.SOARecord{
			PrimaryNs:   z.SOA.Ns,
			Contact:     z.SOA.Mbox,
			Serial:      int64(z.SOA.Serial),
			Refresh:     int32(z.SOA.Refresh),
			Retry:       int32(z.SOA.Retry),
			Expire:      int32(z.SOA.Expire),
			NegativeTtl: int32(z.SOA.Minttl),
		}
	}

	// Collect NS records.
	ns := z.GetNameservers()
	for _, n := range ns {
		pb.Nameservers = append(pb.Nameservers, n.Ns)
	}

	if z.DNSSEC != nil && z.DNSSEC.Enabled {
		pb.DnssecEnabled = true
	}

	// Count records (excluding SOA).
	count := int32(0)
	for _, typeMap := range z.Records {
		for rrtype, rrs := range typeMap {
			if rrtype == dns.TypeSOA {
				continue
			}
			count += int32(len(rrs))
		}
	}
	pb.RecordCount = count

	return pb
}

// rrToPBRecord converts a dns.RR to a protobuf DNSRecord.
func rrToPBRecord(rr dns.RR, owner string) *mgmt.DNSRecord {
	hdr := rr.Header()
	rrtype := dns.TypeToString[hdr.Rrtype]
	if rrtype == "" {
		rrtype = fmt.Sprintf("TYPE%d", hdr.Rrtype)
	}

	content := ""
	priority := int32(0)
	weight := int32(0)
	port := int32(0)

	switch v := rr.(type) {
	case *dns.A:
		content = v.A.String()
	case *dns.AAAA:
		content = v.AAAA.String()
	case *dns.CNAME:
		content = v.Target
	case *dns.NS:
		content = v.Ns
	case *dns.PTR:
		content = v.Ptr
	case *dns.MX:
		content = v.Mx
		priority = int32(v.Preference)
	case *dns.TXT:
		content = strings.Join(v.Txt, "")
	case *dns.SRV:
		content = v.Target
		priority = int32(v.Priority)
		weight = int32(v.Weight)
		port = int32(v.Port)
	default:
		// Skip SOA and unsupported types.
		if hdr.Rrtype == dns.TypeSOA {
			return nil
		}
		content = rr.String()
	}

	rec := &mgmt.DNSRecord{
		RecordId:   makeRecordID(owner, rrtype, content),
		Name:       owner,
		RecordType: rrtype,
		Content:    content,
		Ttl:        int32(hdr.Ttl),
		Priority:   priority,
		Weight:     weight,
		Port:       port,
	}
	return rec
}

// makeRecordID constructs a stable record identifier of the form "owner:type:content".
func makeRecordID(name, rrtype, content string) string {
	return fmt.Sprintf("%s:%s:%s", name, rrtype, content)
}

// parseRecordID parses a record_id of the form "owner:type:content".
// The owner component may be a relative name, "@", or a fully-qualified name.
// Returns the fully-qualified owner, the uint16 type code, and the content string.
func parseRecordID(recordID, origin string) (string, uint16, string, error) {
	// Split only on the first two colons, leaving content intact (may contain ":").
	parts := strings.SplitN(recordID, ":", 3)
	if len(parts) != 3 {
		return "", 0, "", fmt.Errorf("expected owner:type:content, got %q", recordID)
	}
	ownerRel := parts[0]
	typeName := parts[1]
	content := parts[2]

	// Resolve owner to FQDN.
	var ownerFQDN string
	switch {
	case ownerRel == "@":
		ownerFQDN = origin
	case ownerRel == "" || ownerRel == origin:
		ownerFQDN = origin
	case ownerRel[len(ownerRel)-1] == '.':
		ownerFQDN = strings.ToLower(ownerRel)
	default:
		ownerFQDN = strings.ToLower(ownerRel) + "." + origin
	}

	rrtype, ok := dns.StringToType[strings.ToUpper(typeName)]
	if !ok {
		return "", 0, "", fmt.Errorf("unknown record type: %s", typeName)
	}

	return ownerFQDN, rrtype, content, nil
}

// removeRecord removes a record matching (owner, rrtype, content) from z.Records.
func removeRecord(z *zone.Zone, owner string, rrtype uint16, content string) {
	typeMap, ok := z.Records[owner]
	if !ok {
		return
	}
	rrs, ok := typeMap[rrtype]
	if !ok {
		return
	}

	filtered := rrs[:0]
	for _, rr := range rrs {
		if rrContent(rr) != content {
			filtered = append(filtered, rr)
		}
	}

	if len(filtered) == 0 {
		delete(typeMap, rrtype)
	} else {
		typeMap[rrtype] = filtered
	}
	if len(typeMap) == 0 {
		delete(z.Records, owner)
	}
}

// rrContent extracts the data portion of a dns.RR as a string, matching the
// format used by makeRecordID/rrToPBRecord.
func rrContent(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return v.Target
	case *dns.NS:
		return v.Ns
	case *dns.PTR:
		return v.Ptr
	case *dns.MX:
		return v.Mx
	case *dns.TXT:
		return strings.Join(v.Txt, "")
	case *dns.SRV:
		return v.Target
	default:
		return rr.String()
	}
}
