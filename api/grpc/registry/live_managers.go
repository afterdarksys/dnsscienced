package registry

// live_managers.go — real implementations of ports.ControlManager and ports.CacheManager
// wired to the live DNS server via SrvIface.

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/api/grpc/ports"
	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/miekg/dns"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type liveDNSResolver struct{ srv SrvIface }

func newLiveDNSResolver(srv SrvIface) *liveDNSResolver { return &liveDNSResolver{srv: srv} }

func (r *liveDNSResolver) Resolve(ctx context.Context, name, qtype, class string, wantDNSSEC, rd, cd bool) (*ports.ResolveResult, error) {
	typeCode, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown DNS type %q", qtype)
	}
	classCode, ok := dns.StringToClass[strings.ToUpper(class)]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown DNS class %q", class)
	}
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), typeCode)
	req.Question[0].Qclass = classCode
	req.RecursionDesired = rd
	req.CheckingDisabled = cd
	if wantDNSSEC {
		req.SetEdns0(1232, true)
	}
	resp, err := r.srv.HandleDNS(ctx, req, &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}
	wire, err := resp.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS response: %w", err)
	}
	return &ports.ResolveResult{
		RCode:              int32(resp.Rcode),
		RCodeName:          dns.RcodeToString[resp.Rcode],
		Answer:             convertRRs(resp.Answer),
		Authority:          convertRRs(resp.Ns),
		Additional:         convertRRs(resp.Extra),
		Authoritative:      resp.Authoritative,
		Truncated:          resp.Truncated,
		RecursionAvailable: resp.RecursionAvailable,
		Wire:               wire,
	}, nil
}

func convertRRs(rrs []dns.RR) []ports.ResourceRecord {
	out := make([]ports.ResourceRecord, 0, len(rrs))
	for _, rr := range rrs {
		h := rr.Header()
		full, header := rr.String(), h.String()
		data := strings.TrimSpace(strings.TrimPrefix(full, header))
		wire := make([]byte, dns.Len(rr))
		if off, err := dns.PackRR(rr, wire, 0, nil, false); err == nil {
			wire = wire[:off]
		} else {
			wire = nil
		}
		out = append(out, ports.ResourceRecord{Name: h.Name, Type: dns.TypeToString[h.Rrtype], Class: dns.ClassToString[h.Class], TTL: h.Ttl, Data: data, RData: wire})
	}
	return out
}

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
			UDP: int32(raw.UDPQueries),
			TCP: int32(raw.TCPQueries),
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
	return nil, status.Errorf(codes.Unimplemented, "runtime reload is not wired; send SIGHUP instead (requested sections: %v)", sections)
}

func (m *liveControlMgr) Shutdown(_ context.Context, _ int32, _ bool) (*ports.ShutdownReport, error) {
	return nil, status.Error(codes.Unimplemented, "shutdown via ServerService is not implemented")
}

func (m *liveControlMgr) Config(_ context.Context, section string, _ bool) (map[string]string, error) {
	return nil, status.Errorf(codes.Unimplemented, "runtime config inspection is not implemented (section %q)", section)
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
	live := c.srv.GetShardedCache()
	if live == nil {
		return nil, status.Error(codes.FailedPrecondition, "recursive cache is disabled")
	}
	raw := live.GetStats()
	byType := make(map[string]int64)
	var ttlTotal uint64
	var ttlCount uint64
	var minTTL, maxTTL uint32
	live.ForEach(func(_ uint64, entry *cache.Entry) {
		remaining := remainingTTL(entry)
		byType[dns.TypeToString[entry.QType]]++
		ttlTotal += uint64(remaining)
		ttlCount++
		if ttlCount == 1 || remaining < minTTL {
			minTTL = remaining
		}
		if remaining > maxTTL {
			maxTTL = remaining
		}
	})
	var avgTTL uint32
	if ttlCount > 0 {
		avgTTL = uint32(ttlTotal / ttlCount)
	}
	return &ports.CacheStats{
		Entries:        int64(raw.Size),
		SizeBytes:      raw.MemoryBytes,
		MaxBytes:       raw.MaxMemory,
		Utilization:    utilization(raw.MemoryBytes, raw.MaxMemory),
		Hits:           int64(raw.Hits),
		Misses:         int64(raw.Misses),
		HitRate:        float32(raw.HitRate),
		ByType:         byType,
		AvgTTL:         avgTTL,
		MinTTL:         minTTL,
		MaxTTL:         maxTTL,
		Evictions:      int64(raw.Evictions),
		MeasuredAtUnix: time.Now().Unix(),
	}, nil
}

func utilization(used, maximum int64) float32 {
	if maximum <= 0 {
		return 0
	}
	return float32(used) / float32(maximum)
}

func remainingTTL(entry *cache.Entry) uint32 {
	remaining := time.Until(entry.ExpiresAt)
	if remaining <= 0 {
		return 0
	}
	return uint32(remaining / time.Second)
}

func (c *liveCacheMgr) Lookup(_ context.Context, name, rtype string) ([]ports.CacheEntry, error) {
	live := c.srv.GetShardedCache()
	if live == nil {
		return nil, status.Error(codes.FailedPrecondition, "recursive cache is disabled")
	}
	name = strings.ToLower(dns.Fqdn(name))
	var typeCode uint16
	if rtype != "" {
		var ok bool
		typeCode, ok = dns.StringToType[strings.ToUpper(rtype)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "unknown DNS type %q", rtype)
		}
	}
	entries := make([]ports.CacheEntry, 0)
	live.ForEach(func(_ uint64, entry *cache.Entry) {
		if strings.ToLower(dns.Fqdn(entry.QName)) != name || (typeCode != 0 && entry.QType != typeCode) || entry.IsExpired() {
			return
		}
		data := make([]string, 0)
		msg := new(dns.Msg)
		if err := msg.Unpack(entry.Data); err == nil {
			for _, rr := range msg.Answer {
				data = append(data, rr.String())
			}
		}
		cachedAt := entry.ExpiresAt.Add(-time.Duration(entry.OrigTTL) * time.Second)
		entries = append(entries, ports.CacheEntry{
			Name: entry.QName, Type: dns.TypeToString[entry.QType], Class: dns.ClassToString[entry.QClass],
			TTL: remainingTTL(entry), OriginalTTL: entry.OrigTTL, Data: data,
			CachedAtUnix: cachedAt.Unix(), ExpiresAtUnix: entry.ExpiresAt.Unix(), Source: "recursive",
		})
	})
	return entries, nil
}

func (c *liveCacheMgr) Flush(_ context.Context, scope, domain, rtype string, includeSubs bool) (*ports.FlushResult, error) {
	live := c.srv.GetShardedCache()
	if live == nil {
		return nil, status.Error(codes.FailedPrecondition, "recursive cache is disabled")
	}
	scope = strings.ToUpper(scope)
	if scope == "FLUSH_SCOPE_ALL" {
		stats := live.GetStats()
		live.Flush()
		return &ports.FlushResult{Removed: int32(stats.Size), BytesFreed: stats.MemoryBytes, FlushedAtUnix: time.Now().Unix()}, nil
	}
	if scope != "FLUSH_SCOPE_DOMAIN" && scope != "FLUSH_SCOPE_TYPE" && scope != "FLUSH_SCOPE_EXACT" {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported flush scope %q", scope)
	}
	wantName := strings.ToLower(dns.Fqdn(domain))
	var typeCode uint16
	if scope == "FLUSH_SCOPE_TYPE" || scope == "FLUSH_SCOPE_EXACT" {
		var ok bool
		typeCode, ok = dns.StringToType[strings.ToUpper(rtype)]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "unknown DNS type %q", rtype)
		}
	}
	if (scope == "FLUSH_SCOPE_DOMAIN" || scope == "FLUSH_SCOPE_EXACT") && domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain is required for this flush scope")
	}
	type removal struct {
		hash  uint64
		bytes int64
	}
	removals := make([]removal, 0)
	live.ForEach(func(hash uint64, entry *cache.Entry) {
		entryName := strings.ToLower(dns.Fqdn(entry.QName))
		nameMatch := entryName == wantName || (includeSubs && dns.IsSubDomain(wantName, entryName))
		match := scope == "FLUSH_SCOPE_TYPE" && entry.QType == typeCode ||
			scope == "FLUSH_SCOPE_DOMAIN" && nameMatch ||
			scope == "FLUSH_SCOPE_EXACT" && nameMatch && entry.QType == typeCode
		if match {
			removals = append(removals, removal{hash: hash, bytes: int64(len(entry.Data))})
		}
	})
	var bytesFreed int64
	for _, item := range removals {
		live.Delete(item.hash)
		bytesFreed += item.bytes
	}
	return &ports.FlushResult{Removed: int32(len(removals)), BytesFreed: bytesFreed, FlushedAtUnix: time.Now().Unix()}, nil
}

func (c *liveCacheMgr) Prefetch(_ context.Context, _, _ []string, _ int32) (*ports.PrefetchOutcome, error) {
	return nil, status.Error(codes.Unimplemented, "cache prefetch is not wired to the live resolver")
}

func (c *liveCacheMgr) Subscribe() chan *pb.CacheEvent {
	if live := c.srv.GetShardedCache(); live != nil {
		return live.Subscribe()
	}
	return nil
}

func (c *liveCacheMgr) Unsubscribe(ch chan *pb.CacheEvent) {
	if live := c.srv.GetShardedCache(); live != nil && ch != nil {
		live.Unsubscribe(ch)
	}
}
