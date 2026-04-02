package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	addr = flag.String("addr", "localhost:9091", "Admin API address")
	timeout = flag.Duration("timeout", 10*time.Second, "Request timeout")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DNSScienced Admin CLI\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <command> [args...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nCommands:\n")
		fmt.Fprintf(os.Stderr, "  cache flush [all|name|domain|tld] [value]  Flush cache entries\n")
		fmt.Fprintf(os.Stderr, "  cache stats                                 Show cache statistics\n")
		fmt.Fprintf(os.Stderr, "  cache purge <pattern>                       Purge by pattern\n")
		fmt.Fprintf(os.Stderr, "  zone refresh <name>                         Refresh a specific zone\n")
		fmt.Fprintf(os.Stderr, "  zone list                                   List all zones\n")
		fmt.Fprintf(os.Stderr, "  zone reload                                 Reload all zones\n")
		fmt.Fprintf(os.Stderr, "  logging enable|disable                      Control query logging\n")
		fmt.Fprintf(os.Stderr, "  logging status                              Show logging status\n")
		fmt.Fprintf(os.Stderr, "  ratelimit set <rps>                         Set rate limit\n")
		fmt.Fprintf(os.Stderr, "  ratelimit status                            Show rate limit status\n")
		fmt.Fprintf(os.Stderr, "  server status                               Show server status\n")
		fmt.Fprintf(os.Stderr, "  server metrics                              Show server metrics\n")
		fmt.Fprintf(os.Stderr, "  server shutdown [grace-seconds]             Shutdown server\n")
		fmt.Fprintf(os.Stderr, "  connections list                            List active connections\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Flush entire cache\n")
		fmt.Fprintf(os.Stderr, "  %s cache flush all\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Flush cache for specific domain\n")
		fmt.Fprintf(os.Stderr, "  %s cache flush name example.com\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Flush all entries under domain\n")
		fmt.Fprintf(os.Stderr, "  %s cache flush domain example.com\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Flush entire TLD\n")
		fmt.Fprintf(os.Stderr, "  %s cache flush tld com\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Show cache stats\n")
		fmt.Fprintf(os.Stderr, "  %s cache stats\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Reload all zones\n")
		fmt.Fprintf(os.Stderr, "  %s zone reload\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Show server status\n")
		fmt.Fprintf(os.Stderr, "  %s server status\n\n", os.Args[0])
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	// Connect to admin API
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to admin API: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewAdminServiceClient(conn)

	// Parse command
	command := flag.Arg(0)
	subcommand := ""
	if flag.NArg() > 1 {
		subcommand = flag.Arg(1)
	}

	switch command {
	case "cache":
		handleCacheCommand(ctx, client, subcommand, flag.Args()[2:])
	case "zone":
		handleZoneCommand(ctx, client, subcommand, flag.Args()[2:])
	case "logging":
		handleLoggingCommand(ctx, client, subcommand, flag.Args()[2:])
	case "ratelimit":
		handleRateLimitCommand(ctx, client, subcommand, flag.Args()[2:])
	case "server":
		handleServerCommand(ctx, client, subcommand, flag.Args()[2:])
	case "connections":
		handleConnectionsCommand(ctx, client, subcommand, flag.Args()[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

func handleCacheCommand(ctx context.Context, client pb.AdminServiceClient, subcommand string, args []string) {
	switch subcommand {
	case "flush":
		if len(args) < 1 {
			fmt.Fprintf(os.Stderr, "Usage: cache flush [all|name|domain|tld|negative|expired] [value]\n")
			os.Exit(1)
		}

		req := &pb.AdminFlushCacheRequest{}

		switch args[0] {
		case "all":
			req.Type = pb.AdminFlushCacheRequest_ALL
		case "name":
			if len(args) < 2 {
				fmt.Fprintf(os.Stderr, "Name required for 'name' flush\n")
				os.Exit(1)
			}
			req.Type = pb.AdminFlushCacheRequest_BY_NAME
			req.Name = args[1]
		case "domain":
			if len(args) < 2 {
				fmt.Fprintf(os.Stderr, "Domain required for 'domain' flush\n")
				os.Exit(1)
			}
			req.Type = pb.AdminFlushCacheRequest_BY_DOMAIN
			req.Name = args[1]
		case "tld":
			if len(args) < 2 {
				fmt.Fprintf(os.Stderr, "TLD required for 'tld' flush\n")
				os.Exit(1)
			}
			req.Type = pb.AdminFlushCacheRequest_BY_TLD
			req.Name = args[1]
		case "negative":
			req.Type = pb.AdminFlushCacheRequest_NEGATIVE_ONLY
		case "expired":
			req.Type = pb.AdminFlushCacheRequest_EXPIRED_ONLY
		default:
			fmt.Fprintf(os.Stderr, "Unknown flush type: %s\n", args[0])
			os.Exit(1)
		}

		resp, err := client.FlushCache(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Flushed %d cache entries\n", resp.EntriesFlushed)
		fmt.Printf("%s\n", resp.Message)

	case "stats":
		resp, err := client.GetCacheStats(ctx, &emptypb.Empty{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Cache Statistics:\n")
		fmt.Printf("  Entries:     %d\n", resp.Size)
		fmt.Printf("  Memory:      %d bytes (%.2f MB)\n", resp.MemoryBytes, float64(resp.MemoryBytes)/1024/1024)
		fmt.Printf("  Max Memory:  %d bytes (%.2f MB)\n", resp.MaxMemory, float64(resp.MaxMemory)/1024/1024)
		fmt.Printf("  Hits:        %d\n", resp.Hits)
		fmt.Printf("  Misses:      %d\n", resp.Misses)
		fmt.Printf("  Hit Rate:    %.2f%%\n", resp.HitRate*100)
		fmt.Printf("  Evictions:   %d\n", resp.Evictions)
		fmt.Printf("  Expirations: %d\n", resp.Expirations)

	case "purge":
		if len(args) < 1 {
			fmt.Fprintf(os.Stderr, "Usage: cache purge <pattern>\n")
			os.Exit(1)
		}

		req := &pb.AdminPurgeCacheRequest{
			Pattern: args[0],
			Regex:   false, // Use glob by default
		}

		resp, err := client.PurgeCache(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Purged %d cache entries matching pattern: %s\n", resp.EntriesPurged, args[0])
		if len(resp.Samples) > 0 {
			fmt.Printf("Sample entries:\n")
			for _, sample := range resp.Samples {
				fmt.Printf("  - %s\n", sample)
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown cache subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleZoneCommand(ctx context.Context, client pb.AdminServiceClient, subcommand string, args []string) {
	switch subcommand {
	case "refresh":
		if len(args) < 1 {
			fmt.Fprintf(os.Stderr, "Usage: zone refresh <name>\n")
			os.Exit(1)
		}

		req := &pb.AdminRefreshZoneRequest{
			ZoneName: args[0],
			Force:    false,
		}

		resp, err := client.RefreshZone(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if resp.Refreshed {
			fmt.Printf("Zone %s refreshed successfully\n", args[0])
			fmt.Printf("Records loaded: %d\n", resp.RecordsLoaded)
		} else {
			fmt.Printf("Failed to refresh zone: %s\n", resp.Message)
		}

	case "list":
		resp, err := client.ListZones(ctx, &emptypb.Empty{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Loaded Zones (%d):\n", len(resp.Zones))
		for _, zone := range resp.Zones {
			fmt.Printf("  %-30s  Records: %6d  Compiled: %v\n",
				zone.Name, zone.RecordCount, zone.Compiled)
		}

	case "reload":
		resp, err := client.ReloadZones(ctx, &emptypb.Empty{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Reloaded %d zones\n", resp.ZonesReloaded)
		if len(resp.FailedZones) > 0 {
			fmt.Printf("Failed zones:\n")
			for _, zone := range resp.FailedZones {
				fmt.Printf("  - %s\n", zone)
			}
		}
		fmt.Printf("%s\n", resp.Message)

	default:
		fmt.Fprintf(os.Stderr, "Unknown zone subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleLoggingCommand(ctx context.Context, client pb.AdminServiceClient, subcommand string, args []string) {
	switch subcommand {
	case "enable", "disable":
		req := &pb.AdminSetQueryLoggingRequest{
			Enabled: subcommand == "enable",
		}

		resp, err := client.SetQueryLogging(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if resp.Success {
			fmt.Printf("Query logging %sd\n", subcommand)
		} else {
			fmt.Printf("Failed to %s query logging: %s\n", subcommand, resp.Message)
		}

	case "status":
		resp, err := client.GetQueryLoggingStatus(ctx, &emptypb.Empty{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Query Logging Status:\n")
		fmt.Printf("  Enabled:        %v\n", resp.Enabled)
		fmt.Printf("  Log Path:       %s\n", resp.LogPath)
		fmt.Printf("  Format:         %s\n", resp.Format)
		fmt.Printf("  Queries Logged: %d\n", resp.QueriesLogged)
		fmt.Printf("  Log Size:       %d bytes\n", resp.LogSizeBytes)

	default:
		fmt.Fprintf(os.Stderr, "Unknown logging subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleRateLimitCommand(ctx context.Context, client pb.AdminServiceClient, subcommand string, args []string) {
	switch subcommand {
	case "status":
		resp, err := client.GetRateLimitStatus(ctx, &emptypb.Empty{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Rate Limiting Status:\n")
		fmt.Printf("  Enabled:            %v\n", resp.Enabled)
		fmt.Printf("  Responses/sec:      %d\n", resp.ResponsesPerSecond)
		fmt.Printf("  Errors/sec:         %d\n", resp.ErrorsPerSecond)
		fmt.Printf("  NXDOMAINs/sec:      %d\n", resp.NxdomainsPerSecond)
		fmt.Printf("  Total Dropped:      %d\n", resp.TotalDropped)
		fmt.Printf("  Total Slipped:      %d\n", resp.TotalSlipped)

	default:
		fmt.Fprintf(os.Stderr, "Unknown ratelimit subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleServerCommand(ctx context.Context, client pb.AdminServiceClient, subcommand string, args []string) {
	switch subcommand {
	case "status":
		resp, err := client.GetServerStatus(ctx, &emptypb.Empty{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Server Status:\n")
		fmt.Printf("  Version:     %s\n", resp.Version)
		fmt.Printf("  Uptime:      %s\n", formatDuration(time.Duration(resp.UptimeSeconds)*time.Second))
		fmt.Printf("  Healthy:     %v\n", resp.Healthy)
		fmt.Printf("  Goroutines:  %d\n", resp.Goroutines)
		fmt.Printf("  Memory:      %.2f MB\n", float64(resp.MemoryBytes)/1024/1024)
		fmt.Printf("  Zones:       %d\n", resp.ZonesLoaded)
		fmt.Printf("\nComponents:\n")
		for _, comp := range resp.Components {
			status := "✓"
			if !comp.Healthy {
				status = "✗"
			}
			fmt.Printf("  %s %-15s  %s\n", status, comp.Name, comp.Message)
		}

	case "metrics":
		resp, err := client.GetMetrics(ctx, &emptypb.Empty{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Server Metrics:\n")
		fmt.Printf("  Total Queries:      %d\n", resp.QueriesTotal)
		fmt.Printf("  UDP Queries:        %d\n", resp.QueriesUdp)
		fmt.Printf("  TCP Queries:        %d\n", resp.QueriesTcp)
		fmt.Printf("  Cache Hits:         %d\n", resp.CacheHits)
		fmt.Printf("  Cache Misses:       %d\n", resp.CacheMisses)
		fmt.Printf("  Upstream Failures:  %d\n", resp.UpstreamFailures)
		fmt.Printf("  Avg Latency:        %.2f ms\n", resp.AvgLatencyMs)
		fmt.Printf("  P99 Latency:        %.2f ms\n", resp.P99LatencyMs)

	case "shutdown":
		gracePeriod := int32(5)
		if len(args) > 0 {
			fmt.Sscanf(args[0], "%d", &gracePeriod)
		}

		req := &pb.AdminShutdownRequest{
			GracePeriodSeconds: gracePeriod,
		}

		resp, err := client.ShutdownServer(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if resp.Success {
			fmt.Printf("%s\n", resp.Message)
		} else {
			fmt.Fprintf(os.Stderr, "Shutdown failed: %s\n", resp.Message)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown server subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleConnectionsCommand(ctx context.Context, client pb.AdminServiceClient, subcommand string, args []string) {
	switch subcommand {
	case "list":
		req := &pb.AdminListConnectionsRequest{
			Protocol: "",
			Limit:    100,
		}

		resp, err := client.ListConnections(ctx, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Active Connections (%d total):\n", resp.TotalCount)
		for _, conn := range resp.Connections {
			fmt.Printf("  %s  %s:%d  %-5s  Queries: %d  Duration: %s\n",
				conn.Id,
				conn.ClientIp,
				conn.ClientPort,
				strings.ToUpper(conn.Protocol),
				conn.QueriesServed,
				formatDuration(time.Since(conn.ConnectedAt.AsTime())))
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown connections subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
