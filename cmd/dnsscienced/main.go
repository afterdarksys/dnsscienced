package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/dnsscience/dnsscienced/api/grpc/middleware"
	"github.com/dnsscience/dnsscienced/api/grpc/registry"
	grpcserver "github.com/dnsscience/dnsscienced/api/grpc/server"
	"github.com/dnsscience/dnsscienced/api/grpc/services"
	"github.com/dnsscience/dnsscienced/internal/admin"
	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/catalog"
	"github.com/dnsscience/dnsscienced/internal/config"
	"github.com/dnsscience/dnsscienced/internal/defensive"
	"github.com/dnsscience/dnsscienced/internal/eventbus"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
	"github.com/dnsscience/dnsscienced/internal/logging"
	"github.com/dnsscience/dnsscienced/internal/primarynotify"
	"github.com/dnsscience/dnsscienced/internal/resolver"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/secondary"
	"github.com/dnsscience/dnsscienced/internal/server"
	"github.com/dnsscience/dnsscienced/internal/tsig"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
	"google.golang.org/grpc"
)

// serverSrvAdapter wraps *server.Server to satisfy services.SrvAdapter without
// importing internal/server inside the services package (which would create an
// import cycle via registry).
type serverSrvAdapter struct {
	s *server.Server
}

func (a *serverSrvAdapter) Live() bool { return true }
func (a *serverSrvAdapter) HandleDNS(ctx context.Context, req *dns.Msg, remoteAddr net.Addr) (*dns.Msg, error) {
	return a.s.HandleDNS(ctx, req, remoteAddr)
}
func (a *serverSrvAdapter) GetZone(origin string) *zone.Zone { return a.s.GetZone(origin) }
func (a *serverSrvAdapter) AddZone(z *zone.Zone) error       { return a.s.AddZone(z) }
func (a *serverSrvAdapter) RemoveZone(origin string)         { a.s.RemoveZone(origin) }
func (a *serverSrvAdapter) GetFirewall() *firewalld.Firewall { return a.s.GetFirewall() }
func (a *serverSrvAdapter) GetStats() services.SrvStats {
	raw := a.s.GetStats()
	s := services.SrvStats{
		Queries:    raw.Queries,
		Answers:    raw.Answers,
		Errors:     raw.Errors,
		NXDomain:   raw.NXDOMAIN,
		UDPQueries: raw.UDPQueries,
		TCPQueries: raw.TCPQueries,
	}
	if raw.Recursive != nil {
		s.RecursiveHits = raw.Recursive.Cache.Hits
		s.RecursiveMisses = raw.Recursive.Cache.Misses
	}
	return s
}

func (a *serverSrvAdapter) GetShardedCache() *cache.ShardedCache {
	return a.s.GetCache()
}

func (a *serverSrvAdapter) GetAdminStats() admin.AdminSrvStats {
	raw := a.s.GetStats()
	return admin.AdminSrvStats{
		Queries:    raw.Queries,
		UDPQueries: raw.UDPQueries,
		TCPQueries: raw.TCPQueries,
		Errors:     raw.Errors,
		NXDomain:   raw.NXDOMAIN,
	}
}

func (a *serverSrvAdapter) GetTsigKeyRing() *tsig.KeyRing {
	return a.s.GetTsigKeyRing()
}

func (a *serverSrvAdapter) GetRRL() *rrl.Limiter {
	return a.s.GetRRL()
}

func (a *serverSrvAdapter) GetZoneNames() []string {
	return a.s.GetZoneNames()
}

var (
	udpAddr       = flag.String("udp", ":5353", "UDP listen address")
	tcpAddr       = flag.String("tcp", ":5353", "TCP listen address")
	udpListeners  = flag.Int("listeners", runtime.NumCPU(), "Number of UDP listeners (SO_REUSEPORT)")
	zoneFile      = flag.String("zone", "", "Zone file to load (optional)")
	zoneFormat    = flag.String("format", "dnszone", "Zone file format (dnszone, bind)")
	recursive     = flag.Bool("recursive", true, "Enable recursive resolver")
	authoritative = flag.Bool("authoritative", false, "Enable authoritative server")
	// Deduplication handled in previous lines

	configFile = flag.String("config", "", "Path to YAML configuration file")
	stats      = flag.Bool("stats", true, "Print statistics periodically")
	darkApiKey = flag.String("darkapi-key", "", "API Key for darkapi.io threat intelligence")
)

func main() {
	flag.Parse()

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                                                              ║")
	fmt.Println("║              DNSScienced - Production DNS Server             ║")
	fmt.Println("║                                                              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Create server config
	cfg := server.DefaultConfig()
	var loadedCfg *config.Config

	// Load config file if specified
	if *configFile != "" {
		fmt.Printf("Loading configuration from %s\n", *configFile)
		var err error
		loadedCfg, err = config.Load(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}
		config.ApplyRuntime(loadedCfg.Runtime)
		fmt.Printf("Runtime concurrency: GOMAXPROCS=%d\n", runtime.GOMAXPROCS(0))
		// Merge loaded config into default config
		// For now, we just replace the server config section entirely
		// A proper merge should look at which fields were set, but since we are unmarshaling
		// entire structs, we can just take the loaded struct if it's not zero-value.
		// However, config.Load starts with defaults? No, we implemented it to decode into defaults there?
		// Wait, let's restart. config.Load returns a *config.Config which CONTAINS server.Config.
		// So we should take cfg = loadedCfg.Server.
		cfg = loadedCfg.Server
		if err := wireResolverForwarding(&cfg.RecursiveConfig, loadedCfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error configuring resolver forwarding: %v\n", err)
			os.Exit(1)
		}

		// Initialize defensive features if configured
		if hasDefensiveFeatures(loadedCfg.Defensive) {
			defensiveMgr, err := defensive.New(loadedCfg.Defensive)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing defensive features: %v\n", err)
				os.Exit(1)
			}
			cfg.DefensiveManager = defensiveMgr
		}

		// Wire per-zone allow_transfer CIDRs from zone config into server config.
		// config.Config.Zones holds AllowTransfer; server.Config.ZoneTransferCIDRs
		// carries them to the AXFR handler. Wired here to avoid import cycle.
		wireZoneTransferPolicies(&cfg, loadedCfg.Zones)

		// Wire per-zone allow_update CIDRs from zone config into server config.
		// Same pattern as ZoneTransferCIDRs; wired here to avoid import cycle.
		// Empty AllowUpdate slice is passed as-is; server.New() intercepts empty → nil (deny all per D-15).
		if len(loadedCfg.Zones) > 0 {
			cfg.ZoneUpdateCIDRs = make(map[string][]string, len(loadedCfg.Zones))
			cfg.ZoneUpdateTSIGKeys = make(map[string][]string, len(loadedCfg.Zones))
			for _, zc := range loadedCfg.Zones {
				zoneName := strings.ToLower(dns.Fqdn(zc.Name))
				cfg.ZoneUpdateCIDRs[zoneName] = zc.AllowUpdate
				cfg.ZoneUpdateTSIGKeys[zoneName] = zc.UpdateTSIGKeys
			}
		}

		// Wire per-zone persist paths for RFC 2136 dynamic update write-back (D-11, D-13).
		// Only zones with persist_updates=true get a path entry; all others persist in-memory only (D-12).
		if len(loadedCfg.Zones) > 0 {
			persistPaths := make(map[string]string)
			for _, zc := range loadedCfg.Zones {
				if zc.PersistUpdates != nil && *zc.PersistUpdates && zc.File != "" {
					zoneName := strings.ToLower(dns.Fqdn(zc.Name))
					persistPaths[zoneName] = zc.File
				}
			}
			if len(persistPaths) > 0 {
				cfg.PersistPaths = persistPaths
			}
		}

		// Wire TSIG keys from config into server config. server.Config.TsigKeys uses
		// yaml:"-" so it is not decoded from the server YAML section directly.
		// config.TsigKeyConfig and tsig.KeyConfig have identical fields.
		if len(loadedCfg.TsigKeys) > 0 {
			cfg.TsigKeys = make([]tsig.KeyConfig, len(loadedCfg.TsigKeys))
			for i, kc := range loadedCfg.TsigKeys {
				cfg.TsigKeys[i] = tsig.KeyConfig{
					Name:      kc.Name,
					Algorithm: kc.Algorithm,
					Secret:    kc.Secret,
				}
			}
		}
		notifyZones, err := buildPrimaryNotifyConfigs(loadedCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error configuring primary NOTIFY: %v\n", err)
			os.Exit(1)
		}
		cfg.PrimaryNotifyZones = notifyZones

		// Check if DHCP config was loaded
		if loadedCfg.DHCP.Enabled {
			fmt.Println("DHCP Configuration detected (Feature coming soon)")
		}
	}

	// CLI flags override config file
	if isFlagPassed("udp") {
		cfg.UDPAddr = *udpAddr
	}
	if isFlagPassed("tcp") {
		cfg.TCPAddr = *tcpAddr
	}
	if isFlagPassed("listeners") {
		cfg.UDPListeners = *udpListeners
	}
	if isFlagPassed("recursive") {
		cfg.EnableRecursive = *recursive
	}
	if isFlagPassed("authoritative") {
		cfg.EnableAuthoritative = *authoritative
	}
	if isFlagPassed("darkapi-key") {
		cfg.RecursiveConfig.CacheConfig.DarkAPIKey = *darkApiKey
	}
	if loadedCfg != nil && loadedCfg.Role != "" {
		loadedCfg.Server = cfg
		if err := loadedCfg.ApplyRoleProfile(); err != nil {
			fmt.Fprintf(os.Stderr, "Error validating deployment role after CLI overrides: %v\n", err)
			os.Exit(1)
		}
		cfg = loadedCfg.Server
	}

	fmt.Printf("Configuration:\n")
	if loadedCfg != nil && loadedCfg.Role != "" {
		fmt.Printf("  Role:               %s\n", loadedCfg.Role)
	}
	fmt.Printf("  UDP Address:      %s\n", cfg.UDPAddr)
	fmt.Printf("  TCP Address:      %s\n", cfg.TCPAddr)
	fmt.Printf("  UDP Listeners:    %d (SO_REUSEPORT)\n", cfg.UDPListeners)
	fmt.Printf("  CPU Cores:        %d\n", runtime.NumCPU())
	fmt.Printf("  Recursive:        %v\n", cfg.EnableRecursive)
	fmt.Printf("  Authoritative:    %v\n", cfg.EnableAuthoritative)
	fmt.Printf("  DNS Cookies:      %v\n", cfg.EnableCookies)
	fmt.Printf("  RRL:              %v\n", cfg.EnableRRL)
	fmt.Printf("  Experimental:     %v\n", cfg.Experimental.Enabled)
	if cfg.Experimental.IsAnyEnabled() {
		fmt.Printf("   └─ Active:       %d feature(s)\n", len(cfg.Experimental.EnabledFeatures()))
	}
	fmt.Println()

	// Log defensive DNS features if any are enabled
	if loadedCfg != nil {
		printDefensiveFeatures(loadedCfg.Defensive)
	}

	// Create server
	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
		os.Exit(1)
	}

	// Catalog reconciliation and admin RPCs share one structured control-plane
	// logger. Initialize it before secondary startup so initial catalog transfer
	// and validation decisions are auditable.
	var controlLogger *logging.Logger
	if loadedCfg != nil && (loadedCfg.Admin.Enabled || len(loadedCfg.CatalogZones) > 0) {
		logCfg := loadedCfg.Logging
		controlLogger, err = logging.NewLogger(logCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating control-plane logger: %v\n", err)
			os.Exit(1)
		}
	}

	// Attach event bus for real-time query streaming (256-event buffer).
	queryBus := eventbus.New(256)
	srv.SetBus(queryBus)

	// Load zone file if specified via CLI flag
	if *zoneFile != "" {
		fmt.Printf("Loading zone: %s (format: %s)\n", *zoneFile, *zoneFormat)
		if err := srv.LoadZone(*zoneFile, *zoneFormat); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading zone: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()
	}

	// Load explicit primary zone stanzas. Unsupported zone roles fail startup
	// rather than being silently ignored while the daemon appears healthy.
	if loadedCfg != nil && len(loadedCfg.Zones) > 0 {
		zonesLoaded, err := loadConfiguredZones(srv, loadedCfg.Zones)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configured zones: %v\n", err)
			os.Exit(1)
		}
		if zonesLoaded > 0 {
			srv.EnableAuthoritative()
			fmt.Printf("Loaded %d configured primary zone(s)\n\n", zonesLoaded)
		}
	}

	// Load zones from zones_dir if specified in config
	if loadedCfg != nil && loadedCfg.ZonesDir != "" {
		fmt.Printf("Loading zones from directory: %s\n", loadedCfg.ZonesDir)
		zonesLoaded, zonesFailedCount := loadZonesFromDir(srv, loadedCfg.ZonesDir)
		fmt.Printf("Loaded %d zones successfully", zonesLoaded)
		if zonesFailedCount > 0 {
			fmt.Printf(" (%d failed)", zonesFailedCount)
		}
		fmt.Println()

		// Enable authoritative mode if zones were loaded
		if zonesLoaded > 0 {
			srv.EnableAuthoritative()
			fmt.Println("Authoritative mode: ENABLED (zones loaded)")
		}
		fmt.Println()
	}

	// Load secondary zones before opening listeners. Initial transfer failure is
	// a startup failure so the daemon never advertises an empty secondary.
	var secondaryMgr *secondary.Manager
	var catalogRuntime *catalog.Runtime
	if loadedCfg != nil {
		secondaryConfigs, err := buildSecondaryConfigs(loadedCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error configuring secondary zones: %v\n", err)
			os.Exit(1)
		}
		var secondaryStore secondary.ZoneStore = srv
		if len(loadedCfg.CatalogZones) > 0 {
			sources, catalogTransfers, err := buildCatalogConfigs(loadedCfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error configuring catalog zones: %v\n", err)
				os.Exit(1)
			}
			reservedSecondaries := make([]string, 0, len(secondaryConfigs))
			for _, secondaryConfig := range secondaryConfigs {
				reservedSecondaries = append(reservedSecondaries, secondaryConfig.Name)
			}
			catalogRuntime, err = catalog.NewRuntime(
				srv,
				sources,
				loadedCfg.CatalogStateFile,
				reservedSecondaries,
				catalog.NewLoggingAuditSink(controlLogger),
			)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading catalog state: %v\n", err)
				os.Exit(1)
			}
			catalogConfigs, err := catalogRuntime.CatalogSecondaryConfigs(catalogTransfers)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error configuring catalog transfers: %v\n", err)
				os.Exit(1)
			}
			secondaryConfigs = append(secondaryConfigs, catalogConfigs...)
			secondaryStore = catalogRuntime
		}
		if len(secondaryConfigs) > 0 {
			secondaryMgr, err = secondary.NewManager(secondaryStore, nil, secondaryConfigs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating secondary manager: %v\n", err)
				os.Exit(1)
			}
			if catalogRuntime != nil {
				if err := catalogRuntime.AttachController(secondaryMgr); err != nil {
					fmt.Fprintf(os.Stderr, "Error restoring catalog members: %v\n", err)
					os.Exit(1)
				}
			}
			srv.SetSOANotifyHandler(secondaryMgr)
			if err := secondaryMgr.Start(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "Error loading secondary zones: %v\n", err)
				os.Exit(1)
			}
			srv.EnableAuthoritative()
			fmt.Printf("Loaded %d secondary/catalog zone(s)\n\n", len(secondaryConfigs))
		}
	}

	if loadedCfg != nil &&
		(loadedCfg.Role == config.RoleLocalRoot || loadedCfg.Role == config.RolePublicRoot) {
		if err := srv.ValidateRootAuthoritativeZone(); err != nil {
			fmt.Fprintf(os.Stderr, "Root role conformance check failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Start DNS server
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("DNS server started successfully!")
	fmt.Println()

	// Start admin gRPC server if enabled
	var grpcSrv *grpc.Server
	var grpcListener net.Listener
	var configHolder *grpcserver.ConfigHolder
	if loadedCfg != nil && loadedCfg.Admin.Enabled {
		fmt.Printf("Starting admin gRPC API on %s\n", loadedCfg.Admin.Listen)

		// Locate the compiler binary next to the daemon binary.
		compileBin := filepath.Join(filepath.Dir(os.Args[0]), "dnsscienced-compile")

		grpcCfg := grpcserver.Config{
			ListenAddr:   loadedCfg.Admin.Listen,
			APIKeys:      loadedCfg.Admin.APIKeys,
			TLSCertFile:  loadedCfg.Admin.TLSCertFile,
			TLSKeyFile:   loadedCfg.Admin.TLSKeyFile,
			TLSClientCAs: loadedCfg.Admin.TLSClientCAs,
		}

		// adminSvc is captured from the Register closure and used post-construction
		// to wire the ConnRegistry (chicken-and-egg: connReg isn't available until after
		// grpcserver.New returns, but Register runs inside New).
		var adminSvc *admin.Service
		grpcDeps := grpcserver.Deps{
			Register: func(s *grpc.Server) {
				adminSvc = registry.RegisterAll(s, &serverSrvAdapter{srv}, loadedCfg.ZonesDir, compileBin, nil, srv.GetDSYNCNotifier(), controlLogger, queryBus, catalogRuntime)
			},
			Unary:  []grpc.UnaryServerInterceptor{middleware.AuditUnaryInterceptor(controlLogger)},
			Stream: []grpc.StreamServerInterceptor{middleware.AuditStreamInterceptor(controlLogger)},
		}

		var connReg *grpcserver.ConnRegistry
		grpcSrv, grpcListener, connReg, configHolder, err = grpcserver.New(grpcCfg, grpcDeps)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating gRPC server: %v\n", err)
			os.Exit(1)
		}
		// Wire connReg into adminSvc post-construction (ADMIN-CONN-01).
		if adminSvc != nil && connReg != nil {
			adminSvc.SetConnRegistry(connReg)
		}

		// Start gRPC server in background
		go func() {
			fmt.Printf("Admin gRPC API listening on %s\n", loadedCfg.Admin.Listen)
			if err := grpcSrv.Serve(grpcListener); err != nil {
				fmt.Fprintf(os.Stderr, "gRPC server error: %v\n", err)
			}
		}()
		fmt.Println()
	}

	// Start stats printer if enabled
	if *stats {
		go printStats(srv)
	}

	// Wait for shutdown signal. SIGHUP triggers a full config reload per D-09.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

sigloop:
	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			// D-09: Full config reload (not just API keys). D-11: atomic swap via ConfigHolder.
			if *configFile == "" {
				fmt.Println("SIGHUP received but no config file is configured; ignoring")
				continue
			}
			reloaded, err := config.Load(*configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "SIGHUP: failed to parse config: %v; keeping current config\n", err)
				continue
			}
			if err := srv.ReloadRPZ(reloaded.Server.RPZ); err != nil {
				fmt.Fprintf(os.Stderr, "SIGHUP: RPZ reload failed: %v; keeping current policies\n", err)
				continue
			}
			if configHolder != nil {
				newGrpcCfg := grpcserver.Config{
					ListenAddr:   reloaded.Admin.Listen,
					APIKeys:      reloaded.Admin.APIKeys,
					TLSCertFile:  reloaded.Admin.TLSCertFile,
					TLSKeyFile:   reloaded.Admin.TLSKeyFile,
					TLSClientCAs: reloaded.Admin.TLSClientCAs,
				}
				if err := configHolder.Reload(newGrpcCfg); err != nil {
					fmt.Fprintf(os.Stderr, "SIGHUP: admin config reload failed: %v; RPZ reload applied\n", err)
					continue
				}
			}
			loadedCfg = reloaded
			fmt.Printf("SIGHUP: configuration reloaded (%d RPZ zones, %d admin keys)\n",
				len(reloaded.Server.RPZ.Zones), len(reloaded.Admin.APIKeys))
		case syscall.SIGINT, syscall.SIGTERM:
			fmt.Println()
			break sigloop
		}
	}

	// Graceful shutdown
	fmt.Println("Shutting down...")

	// Stop gRPC server if running
	if grpcSrv != nil {
		fmt.Println("Stopping admin gRPC API...")
		grpcSrv.GracefulStop()
	}

	if secondaryMgr != nil {
		secondaryMgr.Close()
	}

	// Stop DNS server
	if err := srv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping server: %v\n", err)
		os.Exit(1)
	}
}

func loadConfiguredZones(srv *server.Server, zones []config.ZoneConfig) (int, error) {
	loaded := 0
	for _, zc := range zones {
		kind := strings.ToLower(strings.TrimSpace(zc.Type))
		if kind == "" {
			kind = "primary"
		}
		if kind == "secondary" {
			if len(zc.Masters) == 0 {
				return loaded, fmt.Errorf("zone %s: secondary zone requires masters", zc.Name)
			}
			continue
		}
		if kind == "forward" {
			if len(zc.Forwarders) == 0 {
				return loaded, fmt.Errorf("zone %s: forward zone requires forwarders", zc.Name)
			}
			continue
		}
		if kind != "primary" {
			return loaded, fmt.Errorf("zone %s: type %q is not implemented", zc.Name, kind)
		}
		if zc.File == "" {
			return loaded, fmt.Errorf("zone %s: primary zone requires file", zc.Name)
		}
		if zc.DNSSECSigning != nil && zc.DNSSECSigning.Enabled {
			return loaded, fmt.Errorf("zone %s: authoritative DNSSEC signing is not implemented", zc.Name)
		}
		z, err := zone.ParseZoneFile(zc.File, zone.DefaultConfig())
		if err != nil {
			return loaded, fmt.Errorf("zone %s: parse %s: %w", zc.Name, zc.File, err)
		}
		configuredOrigin := strings.ToLower(dns.Fqdn(zc.Name))
		if strings.ToLower(z.Origin) != configuredOrigin {
			return loaded, fmt.Errorf("zone %s: file declares origin %s", configuredOrigin, z.Origin)
		}
		if zc.VerifyZONEMD {
			if err := zone.VerifyZONEMD(z); err != nil {
				return loaded, fmt.Errorf("zone %s: %w", configuredOrigin, err)
			}
		}
		if err := srv.AddZone(z); err != nil {
			return loaded, fmt.Errorf("zone %s: %w", configuredOrigin, err)
		}
		loaded++
	}
	return loaded, nil
}

func wireResolverForwarding(resolverConfig *resolver.Config, cfg *config.Config) error {
	if resolverConfig.ConditionalForwarders == nil {
		resolverConfig.ConditionalForwarders = make(map[string][]string)
	}
	if resolverConfig.ForwardZoneModes == nil {
		resolverConfig.ForwardZoneModes = make(map[string]string)
	}
	for configuredSuffix, servers := range cfg.Forwarders {
		suffix := ""
		if strings.TrimSpace(configuredSuffix) != "" {
			suffix = strings.ToLower(dns.Fqdn(configuredSuffix))
		}
		if suffix == "" {
			if len(resolverConfig.Forwarders) > 0 {
				return fmt.Errorf("duplicate global forwarders")
			}
			resolverConfig.Forwarders = append([]string(nil), servers...)
			continue
		}
		if _, exists := resolverConfig.ConditionalForwarders[suffix]; exists {
			return fmt.Errorf("duplicate forwarder suffix %q", configuredSuffix)
		}
		resolverConfig.ConditionalForwarders[suffix] = append([]string(nil), servers...)
	}
	for _, zoneConfig := range cfg.Zones {
		if strings.ToLower(strings.TrimSpace(zoneConfig.Type)) != "forward" {
			continue
		}
		suffix := strings.ToLower(dns.Fqdn(zoneConfig.Name))
		if _, exists := resolverConfig.ConditionalForwarders[suffix]; exists {
			return fmt.Errorf("duplicate forwarder suffix %s", suffix)
		}
		resolverConfig.ConditionalForwarders[suffix] = append([]string(nil), zoneConfig.Forwarders...)
		mode := zoneConfig.ForwardMode
		if mode == "" {
			mode = resolver.ForwardModeOnly
		}
		resolverConfig.ForwardZoneModes[suffix] = mode
	}
	return nil
}

func buildPrimaryNotifyConfigs(cfg *config.Config) (map[string]primarynotify.ZoneConfig, error) {
	keys := make(map[string]config.TsigKeyConfig, len(cfg.TsigKeys))
	for _, key := range cfg.TsigKeys {
		keys[strings.ToLower(dns.Fqdn(key.Name))] = key
	}

	result := make(map[string]primarynotify.ZoneConfig)
	for _, zc := range cfg.Zones {
		kind := strings.ToLower(strings.TrimSpace(zc.Type))
		if kind == "" {
			kind = "primary"
		}
		if kind != "primary" || len(zc.AlsoNotify) == 0 {
			continue
		}
		notifyCfg := primarynotify.ZoneConfig{
			Targets:       append([]string(nil), zc.AlsoNotify...),
			AllowUnsigned: zc.AllowUnsignedNotify,
			Timeout:       zc.NotifyTimeout,
			RetryBackoff:  zc.NotifyRetryBackoff,
			Attempts:      zc.NotifyAttempts,
		}
		if zc.NotifyTSIGKey != "" {
			keyName := strings.ToLower(dns.Fqdn(zc.NotifyTSIGKey))
			key, ok := keys[keyName]
			if !ok {
				return nil, fmt.Errorf("zone %s: notify_tsig_key %q is not defined", zc.Name, zc.NotifyTSIGKey)
			}
			notifyCfg.TSIGKey = key.Name
			notifyCfg.TSIGAlgorithm = key.Algorithm
		} else if !zc.AllowUnsignedNotify {
			return nil, fmt.Errorf(
				"zone %s: notify_tsig_key is required when also_notify is configured; set allow_unsigned_notify only for legacy secondaries",
				zc.Name,
			)
		}
		result[strings.ToLower(dns.Fqdn(zc.Name))] = notifyCfg
	}
	return result, nil
}

func buildSecondaryConfigs(cfg *config.Config) ([]secondary.Config, error) {
	keys := make(map[string]config.TsigKeyConfig, len(cfg.TsigKeys))
	for _, key := range cfg.TsigKeys {
		keys[strings.ToLower(dns.Fqdn(key.Name))] = key
	}

	var result []secondary.Config
	for _, zc := range cfg.Zones {
		if strings.ToLower(strings.TrimSpace(zc.Type)) != "secondary" {
			continue
		}
		secondaryCfg := secondary.Config{
			Name:                  zc.Name,
			Masters:               append([]string(nil), zc.Masters...),
			TransferSource:        zc.TransferSource,
			AllowUnsignedTransfer: zc.AllowUnsignedTransfer,
			RefreshInterval:       zc.RefreshInterval,
			MinRefreshTime:        zc.MinRefreshTime,
			MaxRefreshTime:        zc.MaxRefreshTime,
			MinRetryTime:          zc.MinRetryTime,
			MaxRetryTime:          zc.MaxRetryTime,
			MaxTransferRecords:    zc.MaxTransferRecords,
			MaxTransferBytes:      zc.MaxTransferBytes,
			AllowAXFRFallback:     true,
		}
		transferTLS, err := buildTransferTLS("zone "+zc.Name, zc.TransferTLS)
		if err != nil {
			return nil, err
		}
		secondaryCfg.TransferTLS = transferTLS
		if zc.AllowAXFRFallback != nil {
			secondaryCfg.AllowAXFRFallback = *zc.AllowAXFRFallback
		}
		if zc.TransferTSIGKey != "" {
			keyName := strings.ToLower(dns.Fqdn(zc.TransferTSIGKey))
			key, ok := keys[keyName]
			if !ok {
				return nil, fmt.Errorf("zone %s: transfer_tsig_key %q is not defined", zc.Name, zc.TransferTSIGKey)
			}
			secondaryCfg.TransferKey = &secondary.TransferKey{
				Name:      key.Name,
				Algorithm: key.Algorithm,
				Secret:    key.Secret,
			}
		} else if !zc.AllowUnsignedTransfer {
			return nil, fmt.Errorf(
				"zone %s: transfer_tsig_key is required for secure secondary operation; set allow_unsigned_transfer: true only for a legacy primary",
				zc.Name,
			)
		}
		result = append(result, secondaryCfg)
	}
	return result, nil
}

func wireZoneTransferPolicies(cfg *server.Config, zones []config.ZoneConfig) {
	if len(zones) == 0 {
		return
	}
	cfg.ZoneTransferCIDRs = make(map[string][]string, len(zones))
	cfg.ZoneTransferTLSOnly = make(map[string]bool, len(zones))
	cfg.ZoneAllowAXFRFallback = make(map[string]bool, len(zones))
	for _, zoneConfig := range zones {
		zoneName := strings.ToLower(dns.Fqdn(zoneConfig.Name))
		cfg.ZoneTransferCIDRs[zoneName] = append([]string(nil), zoneConfig.AllowTransfer...)
		cfg.ZoneTransferTLSOnly[zoneName] = zoneConfig.TransferTLSOnly
		allowFallback := true
		if zoneConfig.AllowAXFRFallback != nil {
			allowFallback = *zoneConfig.AllowAXFRFallback
		}
		cfg.ZoneAllowAXFRFallback[zoneName] = allowFallback
	}
}

func buildCatalogConfigs(cfg *config.Config) (
	[]catalog.SourceConfig,
	map[string]secondary.Config,
	error,
) {
	keys := make(map[string]config.TsigKeyConfig, len(cfg.TsigKeys))
	for _, key := range cfg.TsigKeys {
		keys[strings.ToLower(dns.Fqdn(key.Name))] = key
	}

	sources := make([]catalog.SourceConfig, 0, len(cfg.CatalogZones))
	transfers := make(map[string]secondary.Config, len(cfg.CatalogZones))
	for _, configured := range cfg.CatalogZones {
		name := strings.ToLower(dns.Fqdn(configured.Name))
		transfer, err := catalogTransferConfig(name, configured.CatalogTransferConfig, keys)
		if err != nil {
			return nil, nil, err
		}
		defaults, err := catalogTransferConfig(name+" member default", configured.MemberDefaults, keys)
		if err != nil {
			return nil, nil, err
		}
		groups := make(map[string]secondary.Config, len(configured.Groups))
		for group, groupConfig := range configured.Groups {
			resolved, err := catalogTransferConfig(name+" group "+group, groupConfig, keys)
			if err != nil {
				return nil, nil, err
			}
			groups[group] = resolved
		}
		sources = append(sources, catalog.SourceConfig{
			Name:                      name,
			Defaults:                  defaults,
			Groups:                    groups,
			MemberAllowSuffixes:       append([]string(nil), configured.MemberAllowSuffixes...),
			MemberDenySuffixes:        append([]string(nil), configured.MemberDenySuffixes...),
			MaxMembers:                configured.MaxMembers,
			MaxReconcileActions:       configured.MaxReconcileActions,
			ReconcileActionsPerMinute: configured.ReconcileActionsPerMinute,
			ReconcileActionBurst:      configured.ReconcileActionBurst,
			DryRun:                    configured.DryRun,
			ApprovalRequiredAbove:     configured.ApprovalRequiredAbove,
			ApprovedSerial:            configured.ApprovedSerial,
		})
		transfers[name] = transfer
	}
	return sources, transfers, nil
}

func catalogTransferConfig(
	label string,
	configured config.CatalogTransferConfig,
	keys map[string]config.TsigKeyConfig,
) (secondary.Config, error) {
	result := secondary.Config{
		Masters:               append([]string(nil), configured.Masters...),
		TransferSource:        configured.TransferSource,
		AllowUnsignedTransfer: configured.AllowUnsignedTransfer,
		RefreshInterval:       configured.RefreshInterval,
		MinRefreshTime:        configured.MinRefreshTime,
		MaxRefreshTime:        configured.MaxRefreshTime,
		MinRetryTime:          configured.MinRetryTime,
		MaxRetryTime:          configured.MaxRetryTime,
		MaxTransferRecords:    configured.MaxTransferRecords,
		MaxTransferBytes:      configured.MaxTransferBytes,
		AllowAXFRFallback:     true,
	}
	transferTLS, err := buildTransferTLS(label, configured.TransferTLS)
	if err != nil {
		return secondary.Config{}, err
	}
	result.TransferTLS = transferTLS
	if configured.AllowAXFRFallback != nil {
		result.AllowAXFRFallback = *configured.AllowAXFRFallback
	}
	if configured.TransferTSIGKey != "" {
		keyName := strings.ToLower(dns.Fqdn(configured.TransferTSIGKey))
		key, ok := keys[keyName]
		if !ok {
			return secondary.Config{}, fmt.Errorf("%s: transfer_tsig_key %q is not defined", label, configured.TransferTSIGKey)
		}
		result.TransferKey = &secondary.TransferKey{
			Name:      key.Name,
			Algorithm: key.Algorithm,
			Secret:    key.Secret,
		}
	} else if !configured.AllowUnsignedTransfer {
		return secondary.Config{}, fmt.Errorf(
			"%s: transfer_tsig_key is required; unsigned catalog/member transfers require explicit allow_unsigned_transfer",
			label,
		)
	}
	if len(result.Masters) == 0 {
		return secondary.Config{}, fmt.Errorf("%s: at least one master is required", label)
	}
	return result, nil
}

func buildTransferTLS(label string, configured *config.TransferTLSConfig) (*tls.Config, error) {
	if configured == nil {
		return nil, nil
	}
	serverName := strings.TrimSpace(configured.ServerName)
	if serverName == "" {
		return nil, fmt.Errorf("%s: transfer_tls.server_name is required", label)
	}
	if (configured.CertFile == "") != (configured.KeyFile == "") {
		return nil, fmt.Errorf("%s: transfer_tls.cert_file and key_file must be configured together", label)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		NextProtos: []string{"dot"},
	}
	if configured.CAFile != "" {
		caPEM, err := os.ReadFile(configured.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%s: read transfer TLS CA file: %w", label, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("%s: transfer TLS CA file contains no certificates", label)
		}
		tlsConfig.RootCAs = roots
	}
	if configured.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(configured.CertFile, configured.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("%s: load transfer TLS client certificate: %w", label, err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

// loadZonesFromDir scans a directory for source and compiled zone files. A
// source file is parsed even when no precompiled .dzc sibling exists.
func loadZonesFromDir(srv *server.Server, dir string) (int, int) {
	loaded := 0
	failed := 0

	// Read directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading zones directory %s: %v\n", dir, err)
		return 0, 0
	}

	processed := make(map[string]bool)
	// Prefer source files: ParseZoneFile automatically selects an up-to-date
	// compiled sibling and otherwise parses the source.
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()
		ext := strings.ToLower(filepath.Ext(filename))
		if ext != ".dnszone" && ext != ".zone" && ext != ".bind" {
			continue
		}
		base := strings.TrimSuffix(filename, filepath.Ext(filename))
		if processed[base] {
			continue
		}
		processed[base] = true
		z, err := zone.ParseZoneFile(filepath.Join(dir, filename), zone.DefaultConfig())
		if err != nil {
			fmt.Printf("  Error: Failed to load zone %s: %v\n", filename, err)
			failed++
			continue
		}
		if err := srv.AddZone(z); err != nil {
			fmt.Printf("  Error: Failed to add zone %s: %v\n", filename, err)
			failed++
			continue
		}
		loaded++
	}

	// Load compiled-only zones that had no source sibling.
	for _, entry := range entries {
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".dzc" {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		if processed[base] {
			continue
		}
		z, err := zone.LoadCompiledZone(filepath.Join(dir, entry.Name()))
		if err != nil {
			fmt.Printf("  Error: Failed to load compiled zone %s: %v\n", entry.Name(), err)
			failed++
			continue
		}
		if err := srv.AddZone(z); err != nil {
			fmt.Printf("  Error: Failed to add zone %s: %v\n", entry.Name(), err)
			failed++
			continue
		}
		loaded++
	}

	return loaded, failed
}

func printStats(srv *server.Server) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastQueries := uint64(0)
	lastTime := time.Now()

	for range ticker.C {
		stats := srv.GetStats()
		now := time.Now()
		elapsed := now.Sub(lastTime).Seconds()

		// Calculate QPS
		qps := float64(stats.Queries-lastQueries) / elapsed

		fmt.Printf("═══════════════════════════════════════════════════════════\n")
		fmt.Printf("Statistics (%.1fs interval):\n", elapsed)
		fmt.Printf("  Queries:    %10d  (%.0f qps)\n", stats.Queries, qps)
		fmt.Printf("  Answers:    %10d\n", stats.Answers)
		fmt.Printf("  Errors:     %10d\n", stats.Errors)
		fmt.Printf("  NXDOMAIN:   %10d\n", stats.NXDOMAIN)
		if stats.XoTConnections.Active != 0 ||
			stats.XoTConnections.Accepted != 0 ||
			stats.XoTConnections.Rejected != 0 {
			fmt.Printf("  XoT TCP:    %10d active  (%d accepted, %d rejected)\n",
				stats.XoTConnections.Active,
				stats.XoTConnections.Accepted,
				stats.XoTConnections.Rejected,
			)
		}

		if stats.Recursive != nil {
			fmt.Printf("\nRecursive Resolver:\n")
			fmt.Printf("  Cache Hits:   %10d  (%.1f%% hit rate)\n",
				stats.Recursive.Cache.Hits,
				stats.Recursive.Cache.HitRate*100)
			fmt.Printf("  Cache Misses: %10d\n", stats.Recursive.Cache.Misses)
			fmt.Printf("  Cache Size:   %10d entries\n", stats.Recursive.Cache.Size)
			fmt.Printf("  Workers:      %10d  (%d busy, %.1f%% utilization)\n",
				stats.Recursive.Pool.Workers,
				stats.Recursive.Pool.BusyWorkers,
				stats.Recursive.Pool.Utilization)
			fmt.Printf("  Worker Queue: %10d / %d  (%d rejected, %d timed out)\n",
				stats.Recursive.Pool.QueueDepth,
				stats.Recursive.Pool.QueueSize,
				stats.Recursive.Pool.Rejected,
				stats.Recursive.Pool.TimedOut)
		}

		if stats.RRL != nil {
			fmt.Printf("\nRate Limiting:\n")
			fmt.Printf("  Allowed:  %10d\n", stats.RRL.Allowed)
			fmt.Printf("  Dropped:  %10d  (%.1f%%)\n",
				stats.RRL.Dropped,
				stats.RRL.DropRate*100)
			fmt.Printf("  Slipped:  %10d\n", stats.RRL.Slipped)
		}

		fmt.Printf("═══════════════════════════════════════════════════════════\n\n")

		lastQueries = stats.Queries
		lastTime = now
	}
}

// isFlagPassed checks if a flag was passed on the command line
func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// hasDefensiveFeatures checks if any defensive features are enabled
func hasDefensiveFeatures(cfg defensive.Config) bool {
	return cfg.Blackhole.Enabled ||
		cfg.EDNS.Enabled ||
		cfg.QueryLogging.Enabled ||
		cfg.Cookies.RequireServerCookie ||
		(cfg.RRsetOrder.Method != "" && cfg.RRsetOrder.Method != "none") ||
		cfg.StaleAnswers.Enabled ||
		cfg.FetchQuotas.Enabled ||
		len(cfg.Views) > 0
}

// printDefensiveFeatures prints enabled defensive DNS features
func printDefensiveFeatures(cfg defensive.Config) {
	features := []string{}

	// Check each defensive feature
	if cfg.Blackhole.Enabled {
		features = append(features, fmt.Sprintf("Blackhole ACL (%d CIDRs, action=%s)", len(cfg.Blackhole.CIDRs), cfg.Blackhole.Action))
	}

	if cfg.EDNS.Enabled {
		features = append(features, fmt.Sprintf("EDNS Controls (UDP size=%d, max=%d)", cfg.EDNS.UDPSize, cfg.EDNS.MaxUDPSize))
	}

	if cfg.Cookies.RequireServerCookie {
		strictness := "permissive"
		if cfg.Cookies.StrictValidation {
			strictness = "strict"
		}
		features = append(features, fmt.Sprintf("Cookie Policy (require=%v, %s)", cfg.Cookies.RequireServerCookie, strictness))
	}

	if !cfg.Compression.Enabled {
		features = append(features, "Compression Disabled")
	} else if cfg.Compression.NoCaseCompress {
		features = append(features, "Compression (no-case)")
	}

	if cfg.QueryLogging.Enabled {
		features = append(features, fmt.Sprintf("Query Logging (%s, categories=%v)", cfg.QueryLogging.LogFile, cfg.QueryLogging.Categories))
	}

	if cfg.RRsetOrder.Method != "" && cfg.RRsetOrder.Method != "none" {
		features = append(features, fmt.Sprintf("RRset Ordering (%s)", cfg.RRsetOrder.Method))
	}

	if cfg.StaleAnswers.Enabled {
		features = append(features, fmt.Sprintf("Stale Answers (max=%s)", cfg.StaleAnswers.MaxStaleTime))
	}

	if cfg.FetchQuotas.Enabled {
		features = append(features, fmt.Sprintf("Fetch Quotas (server=%d, zone=%d)", cfg.FetchQuotas.FetchesPerServer, cfg.FetchQuotas.FetchesPerZone))
	}

	if len(cfg.Views) > 0 {
		features = append(features, fmt.Sprintf("Views/Split-Horizon (%d views)", len(cfg.Views)))
	}

	// Print features if any are enabled
	if len(features) > 0 {
		fmt.Println("Defensive DNS Features:")
		for _, feature := range features {
			fmt.Printf("  • %s\n", feature)
		}
		fmt.Println()
	}
}
