package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/dnsscience/dnsscienced/internal/config"
	"github.com/dnsscience/dnsscienced/internal/server"
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

	// Load config file if specified
	if *configFile != "" {
		fmt.Printf("Loading configuration from %s\n", *configFile)
		loadedCfg, err := config.Load(*configFile)
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
	fmt.Println()

	// Create server
	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
		os.Exit(1)
	}

	// Load zone file if specified
	if *zoneFile != "" {
		fmt.Printf("Loading zone: %s (format: %s)\n", *zoneFile, *zoneFormat)
		if err := srv.LoadZone(*zoneFile, *zoneFormat); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading zone: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()
	}

	// Start server
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("DNS server started successfully!")
	fmt.Println()

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
	if err := srv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping server: %v\n", err)
		os.Exit(1)
	}
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
