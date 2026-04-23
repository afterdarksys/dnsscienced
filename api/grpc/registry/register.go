package registry

import (
	"google.golang.org/grpc"

	"github.com/dnsscience/dnsscienced/api/grpc/mock"
	"github.com/dnsscience/dnsscienced/api/grpc/ports"
	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	mgmtpb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb/mgmt"
	"github.com/dnsscience/dnsscienced/api/grpc/services"
	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/engine"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
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

// SrvIface is the interface that RegisterAll requires from the DNS server.
// It matches services.SrvAdapter so the caller can pass a *server.Server directly.
type SrvIface = services.SrvAdapter

// RegisterAll registers all gRPC service implementations on s.
//
// srv is the live DNS server (must satisfy SrvIface / services.SrvAdapter).
// zonesDir is the directory where .dnszone / .dzc files live.
// compileBin is the path to the dnsscienced-compile binary.
func RegisterAll(s *grpc.Server, srv SrvIface, zonesDir string, compileBin string) {
	// Engine-backed managers for the existing 5 services.
	resolver := engine.NewResolver("")
	zoneMgr := engine.NewZoneManager()

	// Seed a demonstration zone so the existing ZoneService tests pass.
	zoneMgr.AddZone(ports.ZoneInfo{
		Name:   "example.com.",
		Type:   "primary",
		Status: "active",
		SOA: ports.SOA{
			Primary: "ns1.example.com.",
			Admin:   "hostmaster.example.com.",
			Serial:  2024010101,
		},
	}, []ports.ResourceRecord{
		{Name: "example.com.", Type: "A", TTL: 3600, Data: "127.0.0.1"},
		{Name: "www.example.com.", Type: "CNAME", TTL: 3600, Data: "example.com."},
	})

	dnssec := &mock.DNSSECMgr{}

	threatScorer := cache.NewThreatScorer("")

	pb.RegisterDNSServiceServer(s, services.NewDNSService(resolver))
	pb.RegisterZoneServiceServer(s, services.NewZoneService(zoneMgr))
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
}
