package registry

import (
	"google.golang.org/grpc"

	grpcserver "github.com/dnsscience/dnsscienced/api/grpc/server"
	"github.com/dnsscience/dnsscienced/api/grpc/mock"
	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	mgmtpb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb/mgmt"
	"github.com/dnsscience/dnsscienced/api/grpc/services"
	"github.com/dnsscience/dnsscienced/internal/admin"
	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/dsync"
	"github.com/dnsscience/dnsscienced/internal/engine"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
	"github.com/dnsscience/dnsscienced/internal/tsig"
	"github.com/dnsscience/dnsscienced/internal/zone"
)

// version is injected at build time via -ldflags "-X ...registry.version=..."
var version = "dev"

// NoopSrvAdapter is a zero-value SrvIface used by standalone gRPC binaries
// that don't have a live DNS server to back the admin managers.
type NoopSrvAdapter struct{}

func (NoopSrvAdapter) GetZone(_ string) *zone.Zone               { return nil }
func (NoopSrvAdapter) AddZone(_ *zone.Zone) error                { return nil }
func (NoopSrvAdapter) RemoveZone(_ string)                       {}
func (NoopSrvAdapter) GetStats() services.SrvStats               { return services.SrvStats{} }
func (NoopSrvAdapter) GetFirewall() *firewalld.Firewall          { return nil }
func (NoopSrvAdapter) GetShardedCache() *cache.ShardedCache      { return nil }
func (NoopSrvAdapter) GetAdminStats() admin.AdminSrvStats        { return admin.AdminSrvStats{} }
func (NoopSrvAdapter) GetTsigKeyRing() *tsig.KeyRing             { return nil }

// SrvIface is the interface that RegisterAll requires from the DNS server.
// It matches services.SrvAdapter so the caller can pass a *server.Server directly.
type SrvIface = services.SrvAdapter

// RegisterAll registers all gRPC service implementations on s.
//
// srv is the live DNS server (must satisfy SrvIface / services.SrvAdapter).
// zonesDir is the directory where .dnszone / .dzc files live.
// compileBin is the path to the dnsscienced-compile binary.
// connRegistry is the connection registry for ListConnections (may be nil — Plan 04 wires it).
// dsyncNotifier is the DSYNC outbound notifier (nil when DSYNC is disabled in config).
func RegisterAll(s *grpc.Server, srv SrvIface, zonesDir string, compileBin string, connRegistry *grpcserver.ConnRegistry, dsyncNotifier *dsync.DSYNCNotifier) {
	// Engine-backed managers.
	resolver := engine.NewResolver("")
	dnssec := &mock.DNSSECMgr{}

	threatScorer := cache.NewThreatScorer("")

	pb.RegisterDNSServiceServer(s, services.NewDNSService(resolver))
	// Use LiveZoneManager so ZoneService.UpdateRecords writes to the live server.
	liveZoneMgr := services.NewLiveZoneManager(srv, zonesDir, compileBin)
	pb.RegisterZoneServiceServer(s, services.NewZoneService(liveZoneMgr))
	pb.RegisterCacheServiceServer(s, services.NewCacheService(newLiveCacheMgr(srv), threatScorer))
	pb.RegisterServerServiceServer(s, services.NewServerService(newLiveControlMgr(srv, version)))
	pb.RegisterDNSSECServiceServer(s, services.NewDNSSECService(dnssec))

	// Management service — wired to the live DNS server.
	mgmtpb.RegisterManagementServiceServer(s, services.NewManagementService(srv, zonesDir, compileBin))

	// FirewallAdminService — registered only when the firewall is enabled in config.
	// srv.GetFirewall() returns nil when firewall.enabled is false in config.yaml.
	if fw := srv.GetFirewall(); fw != nil {
		pb.RegisterFirewallAdminServiceServer(s, services.NewFirewallService(fw))
	}

	// AdminService — always registered; provides cache, zone, metrics, logging, and rate-limit control.
	adminSvc := admin.NewService(
		srv.GetShardedCache(),
		nil, // reloadMgr — legacy stubs nil-guarded in Plan 03
		nil, // healthMgr — GetServerStatus nil-guarded in Plan 03
		nil, // logger — wired in Phase 7; SetQueryLogging/GetQueryLoggingStatus nil-guard
		nil, // shutdownFn — ShutdownServer nil-guards this already
		srv, // AdminSrvAdapter — srv satisfies interface via GetAdminStats/GetZone/AddZone/RemoveZone
		zonesDir,
		compileBin,
		nil,                   // rrlLimiter — wired in Phase 7
		srv.GetTsigKeyRing(), // may be nil if no TSIG keys configured
		connRegistry,          // may be nil; wired from grpcserver.New() 4-return in Plan 04
	)
	pb.RegisterAdminServiceServer(s, adminSvc)

	// DSYNCAdminService — registered only when a DSYNCNotifier is provided (DSYNC enabled in config).
	if dsyncNotifier != nil {
		pb.RegisterDSYNCAdminServiceServer(s, services.NewDSYNCService(dsyncNotifier))
	}
}
