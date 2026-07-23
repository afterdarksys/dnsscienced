package registry

import (
	"context"
	"net"

	"github.com/miekg/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	mgmtpb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb/mgmt"
	grpcserver "github.com/dnsscience/dnsscienced/api/grpc/server"
	"github.com/dnsscience/dnsscienced/api/grpc/services"
	"github.com/dnsscience/dnsscienced/internal/admin"
	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/dsync"
	"github.com/dnsscience/dnsscienced/internal/eventbus"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
	"github.com/dnsscience/dnsscienced/internal/logging"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/tsig"
	"github.com/dnsscience/dnsscienced/internal/zone"
)

// version is injected at build time via -ldflags "-X ...registry.version=..."
var version = "dev"

// NoopSrvAdapter is a zero-value SrvIface used by standalone gRPC binaries
// that don't have a live DNS server to back the admin managers.
type NoopSrvAdapter struct{}

func (NoopSrvAdapter) Live() bool { return false }
func (NoopSrvAdapter) HandleDNS(context.Context, *dns.Msg, net.Addr) (*dns.Msg, error) {
	return nil, status.Error(codes.Unavailable, "no live DNS server is attached")
}
func (NoopSrvAdapter) GetZone(_ string) *zone.Zone { return nil }
func (NoopSrvAdapter) AddZone(_ *zone.Zone) error {
	return status.Error(codes.Unavailable, "no live DNS server is attached")
}
func (NoopSrvAdapter) RemoveZone(_ string)                  {}
func (NoopSrvAdapter) GetStats() services.SrvStats          { return services.SrvStats{} }
func (NoopSrvAdapter) GetFirewall() *firewalld.Firewall     { return nil }
func (NoopSrvAdapter) GetShardedCache() *cache.ShardedCache { return nil }
func (NoopSrvAdapter) GetAdminStats() admin.AdminSrvStats   { return admin.AdminSrvStats{} }
func (NoopSrvAdapter) GetTsigKeyRing() *tsig.KeyRing        { return nil }
func (NoopSrvAdapter) GetRRL() *rrl.Limiter                 { return nil }
func (NoopSrvAdapter) GetZoneNames() []string               { return nil }

// SrvIface is the interface that RegisterAll requires from the DNS server.
// It matches services.SrvAdapter so the caller can pass a *server.Server directly.
type SrvIface = services.SrvAdapter

// RegisterAll registers all gRPC service implementations on s.
//
// srv is the live DNS server (must satisfy SrvIface / services.SrvAdapter).
// zonesDir is the directory where .dnszone / .dzc files live.
// compileBin is the path to the dnsscienced-compile binary.
// connRegistry is always nil here; use SetConnRegistry post-construction instead.
// dsyncNotifier is the DSYNC outbound notifier (nil when DSYNC is disabled in config).
// logger is the admin audit logger for SetQueryLogging RPC wiring.
// bus is the event bus for real-time query streaming (nil disables WatchQueryEvents).
func RegisterAll(s *grpc.Server, srv SrvIface, zonesDir string, compileBin string, connRegistry *grpcserver.ConnRegistry, dsyncNotifier *dsync.DSYNCNotifier, logger *logging.Logger, bus *eventbus.Bus, catalogs admin.CatalogStatusSource) *admin.Service {
	if !srv.Live() {
		pb.RegisterDNSServiceServer(s, &pb.UnimplementedDNSServiceServer{})
		pb.RegisterZoneServiceServer(s, &pb.UnimplementedZoneServiceServer{})
		pb.RegisterCacheServiceServer(s, &pb.UnimplementedCacheServiceServer{})
		pb.RegisterServerServiceServer(s, &pb.UnimplementedServerServiceServer{})
		pb.RegisterDNSSECServiceServer(s, &pb.UnimplementedDNSSECServiceServer{})
		pb.RegisterAdminServiceServer(s, &pb.UnimplementedAdminServiceServer{})
		mgmtpb.RegisterManagementServiceServer(s, &mgmtpb.UnimplementedManagementServiceServer{})
		return nil
	}

	threatScorer := cache.NewThreatScorer("")

	pb.RegisterDNSServiceServer(s, services.NewDNSService(newLiveDNSResolver(srv)))
	// Use LiveZoneManager so ZoneService.UpdateRecords writes to the live server.
	liveZoneMgr := services.NewLiveZoneManager(srv, zonesDir, compileBin)
	pb.RegisterZoneServiceServer(s, services.NewZoneService(liveZoneMgr))
	pb.RegisterCacheServiceServer(s, services.NewCacheService(newLiveCacheMgr(srv), threatScorer))
	pb.RegisterServerServiceServer(s, services.NewServerService(newLiveControlMgr(srv, version)))
	// Authoritative signing and key lifecycle are not implemented. Register the
	// generated unimplemented service so callers receive an honest UNIMPLEMENTED
	// status instead of successful responses from an in-memory mock.
	pb.RegisterDNSSECServiceServer(s, &pb.UnimplementedDNSSECServiceServer{})

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
		nil,    // reloadMgr — legacy stubs nil-guarded in Plan 03
		nil,    // healthMgr — GetServerStatus nil-guarded in Plan 03
		logger, // wired from main.go (ADMIN-LOG-02)
		nil,    // shutdownFn — ShutdownServer nil-guards this already
		srv,    // AdminSrvAdapter — srv satisfies interface via GetAdminStats/GetZone/AddZone/RemoveZone
		zonesDir,
		compileBin,
		srv.GetRRL(),         // wired from live server (ADMIN-RRL-02)
		srv.GetTsigKeyRing(), // may be nil if no TSIG keys configured
		connRegistry,         // always nil here; wired post-construction via SetConnRegistry (ADMIN-CONN-01)
		bus,                  // event bus for WatchQueryEvents streaming RPC
		catalogs,             // live catalog status, nil when catalog zones are disabled
	)
	pb.RegisterAdminServiceServer(s, adminSvc)

	// DSYNCAdminService — registered only when a DSYNCNotifier is provided (DSYNC enabled in config).
	if dsyncNotifier != nil {
		pb.RegisterDSYNCAdminServiceServer(s, services.NewDSYNCService(dsyncNotifier))
	}

	return adminSvc
}
