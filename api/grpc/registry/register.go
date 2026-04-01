package registry

import (
	"google.golang.org/grpc"

	"github.com/dnsscience/dnsscienced/api/grpc/mock"
	"github.com/dnsscience/dnsscienced/api/grpc/ports"
	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"github.com/dnsscience/dnsscienced/api/grpc/services"
	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/engine"
)

// RegisterAll registers services.
// By default, it now uses the real engine implementations.
func RegisterAll(s *grpc.Server) {
	// Initialize the real engine components
	// In a real app, config would refine the upstream/options.
	resolver := engine.NewResolver("")
	zone := engine.NewZoneManager()

	// Seed a test zone for demonstration
	zone.AddZone(ports.ZoneInfo{
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

	// Still using mocks for unimplemented managers
	cacheMgr := &mock.CacheMgr{}
	control := &mock.ControlMgr{}
	dnssec := &mock.DNSSECMgr{}
	
	// Native Threat Intel Engine
	threatScorer := cache.NewThreatScorer("")

	pb.RegisterDNSServiceServer(s, services.NewDNSService(resolver))
	pb.RegisterZoneServiceServer(s, services.NewZoneService(zone))
	pb.RegisterCacheServiceServer(s, services.NewCacheService(cacheMgr, threatScorer))
	pb.RegisterServerServiceServer(s, services.NewServerService(control))
	pb.RegisterDNSSECServiceServer(s, services.NewDNSSECService(dnssec))
}
