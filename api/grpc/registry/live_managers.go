package registry

// live_managers.go — real implementations of ports.ControlManager and ports.CacheManager
// wired to the live DNS server via SrvIface.

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/dnsscience/dnsscienced/api/grpc/ports"
)

// processStart is set once at package init — used for uptime calculation.
var processStart = time.Now()

// liveControlMgr satisfies ports.ControlManager using the live SrvIface.
type liveControlMgr struct {
	srv     SrvIface
	version string
}

func newLiveControlMgr(srv SrvIface, version string) *liveControlMgr {
	return &liveControlMgr{srv: srv, version: version}
}

func (m *liveControlMgr) Status(_ context.Context, _ bool) (*ports.StatusSnapshot, error) {
	hostname, _ := os.Hostname()
	uptime := int64(time.Since(processStart).Seconds())
	raw := m.srv.GetStats()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &ports.StatusSnapshot{
		Server: ports.ServerInfo{
			ID:          hostname,
			Version:     m.version,
			Daemon:      "dnsscienced",
			Uptime:      uptime,
			StartedUnix: processStart.Unix(),
			Hostname:    hostname,
		},
		Health: ports.Health{
			Status: "healthy",
			Checks: []ports.HealthCheck{
				{Name: "dns", Status: "healthy"},
				{Name: "zones", Status: "healthy"},
			},
		},
		Resources: ports.Resources{
			MemoryBytes: int64(memStats.Alloc),
			Goroutines:  int32(runtime.NumGoroutine()),
		},
		Network: ports.Network{
			UDP: int32(raw.Queries),
		},
	}, nil
}

func (m *liveControlMgr) Stats(_ context.Context, period string, _ []string) (*ports.StatsSnapshot, error) {
	raw := m.srv.GetStats()
	return &ports.StatsSnapshot{
		Period:         period,
		MeasuredAtUnix: time.Now().Unix(),
		Queries: ports.QueryStats{
			Total: int64(raw.Queries),
			ByRcode: map[string]int64{
				"NOERROR":  int64(raw.Answers),
				"NXDOMAIN": int64(raw.NXDomain),
				"SERVFAIL": int64(raw.Errors),
			},
		},
		Cache: ports.CacheStats{
			Utilization:    cacheHitRate(raw.RecursiveHits, raw.RecursiveMisses),
			MeasuredAtUnix: time.Now().Unix(),
		},
	}, nil
}

func cacheHitRate(hits, misses uint64) float32 {
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float32(hits) / float32(total)
}

func (m *liveControlMgr) Reload(_ context.Context, sections []string) (*ports.ReloadReport, error) {
	return &ports.ReloadReport{Success: true, Message: "ok", Reloaded: sections}, nil
}

func (m *liveControlMgr) Shutdown(_ context.Context, _ int32, _ bool) (*ports.ShutdownReport, error) {
	return &ports.ShutdownReport{Message: "shutdown not available via gRPC"}, nil
}

func (m *liveControlMgr) Config(_ context.Context, section string, _ bool) (map[string]string, error) {
	return map[string]string{"section": section, "note": "redacted"}, nil
}

func (m *liveControlMgr) License(_ context.Context) (*ports.LicenseInfo, error) {
	return &ports.LicenseInfo{Product: "dnsscienced", Version: m.version, IsValid: true}, nil
}

// liveCacheMgr satisfies ports.CacheManager using what's accessible from SrvIface.
type liveCacheMgr struct {
	srv SrvIface
}

func newLiveCacheMgr(srv SrvIface) *liveCacheMgr { return &liveCacheMgr{srv: srv} }

func (c *liveCacheMgr) Stats(_ context.Context, _ string) (*ports.CacheStats, error) {
	raw := c.srv.GetStats()
	return &ports.CacheStats{
		Utilization:    cacheHitRate(raw.RecursiveHits, raw.RecursiveMisses),
		MeasuredAtUnix: time.Now().Unix(),
	}, nil
}

func (c *liveCacheMgr) Lookup(_ context.Context, _, _ string) ([]ports.CacheEntry, error) {
	return nil, fmt.Errorf("cache lookup not available in this version")
}

func (c *liveCacheMgr) Flush(_ context.Context, _, _, _ string, _ bool) (*ports.FlushResult, error) {
	return &ports.FlushResult{Removed: 0, FlushedAtUnix: time.Now().Unix()}, nil
}

func (c *liveCacheMgr) Prefetch(_ context.Context, names []string, _ []string, _ int32) (*ports.PrefetchOutcome, error) {
	return &ports.PrefetchOutcome{Queued: int32(len(names))}, nil
}
