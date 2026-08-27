package mock

import (
	"context"
	"time"

	"github.com/afterdarksys/dnsscienced/api/grpc/ports"
)

type Resolver struct{}

func (r *Resolver) Resolve(ctx context.Context, name, qtype, class string, dnssec, rd, cd bool) (*ports.ResolveResult, error) {
	return &ports.ResolveResult{
		RCode:     3,
		RCodeName: "NXDOMAIN",
		Answer:    nil,
		Authority: nil,
		Additional: nil,
		Authoritative: false,
		Truncated: false,
		RecursionAvailable: true,
		Meta: map[string]string{"mock": "true"},
		Wire: nil,
	}, nil
}

type ZoneMgr struct{}

type CacheMgr struct{}

type ControlMgr struct{}

type DNSSECMgr struct{}

func (z *ZoneMgr) ListZones(ctx context.Context, zoneType, pattern string) ([]ports.ZoneInfo, error) {
	return []ports.ZoneInfo{}, nil
}
func (z *ZoneMgr) GetZone(ctx context.Context, name string, includeRecords bool, recordType string) (*ports.ZoneInfo, []ports.ResourceRecord, error) {
	zi := &ports.ZoneInfo{Name: name, Type: "primary", Status: "loaded"}
	return zi, nil, nil
}
func (z *ZoneMgr) ReloadZone(ctx context.Context, name string, verifyOnly bool) (*ports.ReloadOutcome, error) {
	return &ports.ReloadOutcome{Zone: name, Success: true, Message: "reloaded", DurationMs: 10}, nil
}
func (z *ZoneMgr) Notify(ctx context.Context, name string, servers []string) (*ports.NotifyOutcome, error) {
	return &ports.NotifyOutcome{Zone: name, Serial: 1}, nil
}
func (z *ZoneMgr) Transfer(ctx context.Context, name string, typ string, server string) (*ports.TransferOutcome, error) {
	return &ports.TransferOutcome{Zone: name, Type: typ, Success: true}, nil
}
func (z *ZoneMgr) UpdateRecords(ctx context.Context, name string, updates []ports.RecordUpdate, incrementSerial bool) (*ports.UpdateOutcome, error) {
	return &ports.UpdateOutcome{Zone: name, Applied: int32(len(updates)), NewSerial: 1}, nil
}
func (z *ZoneMgr) GetRecords(ctx context.Context, name string, host string, rtype string) ([]ports.ResourceRecord, error) {
	return nil, nil
}

func (c *CacheMgr) Stats(ctx context.Context, backend string) (*ports.CacheStats, error) {
	return &ports.CacheStats{Entries: 0, SizeBytes: 0, MaxBytes: 0, Utilization: 0, MeasuredAtUnix: time.Now().Unix()}, nil
}
func (c *CacheMgr) Lookup(ctx context.Context, name, rtype string) ([]ports.CacheEntry, error) { return nil, nil }
func (c *CacheMgr) Flush(ctx context.Context, scope, domain, rtype string, includeSubs bool) (*ports.FlushResult, error) {
	return &ports.FlushResult{Removed: 0, BytesFreed: 0, FlushedAtUnix: time.Now().Unix()}, nil
}
func (c *CacheMgr) Prefetch(ctx context.Context, names []string, types []string, priority int32) (*ports.PrefetchOutcome, error) {
	return &ports.PrefetchOutcome{Queued: int32(len(names))}, nil
}

func (m *ControlMgr) Status(ctx context.Context, includeResources bool) (*ports.StatusSnapshot, error) {
	return &ports.StatusSnapshot{Server: ports.ServerInfo{ID: "mock", Daemon: "dnsscience-grpc", Uptime: 1}}, nil
}
func (m *ControlMgr) Stats(ctx context.Context, period string, breakdowns []string) (*ports.StatsSnapshot, error) {
	return &ports.StatsSnapshot{Period: period}, nil
}
func (m *ControlMgr) Reload(ctx context.Context, sections []string) (*ports.ReloadReport, error) {
	return &ports.ReloadReport{Success: true, Reloaded: sections}, nil
}
func (m *ControlMgr) Shutdown(ctx context.Context, timeoutSec int32, force bool) (*ports.ShutdownReport, error) {
	return &ports.ShutdownReport{Message: "shutting down"}, nil
}
func (m *ControlMgr) Config(ctx context.Context, section string, redact bool) (map[string]string, error) { return map[string]string{"section": section}, nil }
func (m *ControlMgr) License(ctx context.Context) (*ports.LicenseInfo, error) { return &ports.LicenseInfo{Product: "dnsscienced"}, nil }

func (d *DNSSECMgr) Status(ctx context.Context, zone string) (*ports.DNSSECStatus, error) {
	return &ports.DNSSECStatus{Zone: zone, Enabled: false, Signed: false}, nil
}
func (d *DNSSECMgr) Sign(ctx context.Context, zone string, incSerial bool, resignAll bool) (*ports.SignOutcome, error) {
	return &ports.SignOutcome{Zone: zone, Success: true}, nil
}
func (d *DNSSECMgr) Rollover(ctx context.Context, zone string, keyType string, newAlgo string, keySize int32) (*ports.RolloverPlan, error) {
	return &ports.RolloverPlan{Zone: zone, KeyType: keyType, Status: "initiated"}, nil
}
func (d *DNSSECMgr) GetDS(ctx context.Context, zone string, keyType string) ([]ports.DSRecord, error) { return nil, nil }
func (d *DNSSECMgr) GenerateKey(ctx context.Context, zone, typ, algo string, keySize int32, activate bool) (*ports.KeyMaterial, error) {
	return &ports.KeyMaterial{Key: ports.KeyInfo{ID: "k1", Type: typ, Algorithm: algo}}, nil
}
func (d *DNSSECMgr) ImportKey(ctx context.Context, zone, typ, algo, pub, priv string, activate bool) (*ports.KeyInfo, error) {
	return &ports.KeyInfo{ID: "imported", Type: typ, Algorithm: algo}, nil
}
func (d *DNSSECMgr) ExportKey(ctx context.Context, zone, keyID string, includePrivate bool) (*ports.KeyMaterial, error) {
	return &ports.KeyMaterial{Key: ports.KeyInfo{ID: keyID}}, nil
}
func (d *DNSSECMgr) DeleteKey(ctx context.Context, zone, keyID string, force bool) (*ports.DeleteResult, error) {
	return &ports.DeleteResult{KeyID: keyID, Success: true}, nil
}
func (d *DNSSECMgr) ValidateChain(ctx context.Context, zone string, anchors []string) (*ports.ValidationReport, error) {
	return &ports.ValidationReport{Zone: zone, Valid: true}, nil
}
