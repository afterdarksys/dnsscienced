package main

import (
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

	"github.com/dnsscience/dnsscienced/api/grpc/registry"
	grpcserver "github.com/dnsscience/dnsscienced/api/grpc/server"
	"github.com/dnsscience/dnsscienced/internal/config"
	"github.com/dnsscience/dnsscienced/internal/defensive"
	"github.com/dnsscience/dnsscienced/internal/server"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"google.golang.org/grpc"
)

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
		// Merge loaded config into default config
		// For now, we just replace the server config section entirely
		// A proper merge should look at which fields were set, but since we are unmarshaling
		// entire structs, we can just take the loaded struct if it's not zero-value.
		// However, config.Load starts with defaults? No, we implemented it to decode into defaults there?
		// Wait, let's restart. config.Load returns a *config.Config which CONTAINS server.Config.
		// So we should take cfg = loadedCfg.Server.
		cfg = loadedCfg.Server

		// Initialize defensive features if configured
		if hasDefensiveFeatures(loadedCfg.Defensive) {
			defensiveMgr, err := defensive.New(loadedCfg.Defensive)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error initializing defensive features: %v\n", err)
				os.Exit(1)
			}
			cfg.DefensiveManager = defensiveMgr
		}

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

	fmt.Printf("Configuration:\n")
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

	// Load zone file if specified via CLI flag
	if *zoneFile != "" {
		fmt.Printf("Loading zone: %s (format: %s)\n", *zoneFile, *zoneFormat)
		if err := srv.LoadZone(*zoneFile, *zoneFormat); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading zone: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()
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
	if loadedCfg != nil && loadedCfg.Admin.Enabled {
		fmt.Printf("Starting admin gRPC API on %s\n", loadedCfg.Admin.Listen)

		grpcCfg := grpcserver.Config{
			ListenAddr: loadedCfg.Admin.Listen,
		}

		grpcDeps := grpcserver.Deps{
			Register: func(s *grpc.Server) {
				registry.RegisterAll(s)
			},
		}

		var err error
		grpcSrv, grpcListener, err = grpcserver.New(grpcCfg, grpcDeps)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating gRPC server: %v\n", err)
		} else {
			// Start gRPC server in background
			go func() {
				fmt.Printf("Admin gRPC API listening on %s\n", loadedCfg.Admin.Listen)
				if err := grpcSrv.Serve(grpcListener); err != nil {
					fmt.Fprintf(os.Stderr, "gRPC server error: %v\n", err)
				}
			}()
		}
		fmt.Println()
	}

	// Start stats printer if enabled
	if *stats {
		go printStats(srv)
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	fmt.Println()

	// Graceful shutdown
	fmt.Println("Shutting down...")

	// Stop gRPC server if running
	if grpcSrv != nil {
		fmt.Println("Stopping admin gRPC API...")
		grpcSrv.GracefulStop()
	}

	// Stop DNS server
	if err := srv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping server: %v\n", err)
		os.Exit(1)
	}
}

// loadZonesFromDir scans a directory and loads all .dzc (compiled) zone files
// Falls back to .dnszone (YAML) files if .dzc loading fails
func loadZonesFromDir(srv *server.Server, dir string) (int, int) {
	loaded := 0
	failed := 0

	// Read directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading zones directory %s: %v\n", dir, err)
		return 0, 0
	}

	// Process all .dzc files
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if !strings.HasSuffix(filename, ".dzc") {
			continue
		}

		zonePath := filepath.Join(dir, filename)
		zoneName := strings.TrimSuffix(filename, ".dzc")

		// Try loading compiled zone
		z, err := zone.LoadCompiledZone(zonePath)
		if err != nil {
			fmt.Printf("  Warning: Failed to load compiled zone %s: %v\n", filename, err)

			// Try YAML failback
			yamlPath := filepath.Join(dir, zoneName+".dnszone")
			if _, statErr := os.Stat(yamlPath); statErr == nil {
				fmt.Printf("  Attempting YAML failback for %s...\n", zoneName)
				z, err = zone.ParseDNSZone(yamlPath, zone.DefaultConfig())
				if err != nil {
					fmt.Printf("  Error: YAML failback also failed for %s: %v\n", zoneName, err)
					failed++
					continue
				}
				fmt.Printf("  Success: Loaded %s from YAML failback\n", zoneName)
			} else {
				failed++
				continue
			}
		}

		// Add zone to server
		if err := srv.AddZone(z); err != nil {
			fmt.Printf("  Error: Failed to add zone %s: %v\n", zoneName, err)
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

		if stats.Recursive != nil {
			fmt.Printf("\nRecursive Resolver:\n")
			fmt.Printf("  Cache Hits:   %10d  (%.1f%% hit rate)\n",
				stats.Recursive.Cache.Hits,
				stats.Recursive.Cache.HitRate*100)
			fmt.Printf("  Cache Misses: %10d\n", stats.Recursive.Cache.Misses)
			fmt.Printf("  Cache Size:   %10d entries\n", stats.Recursive.Cache.Size)
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
