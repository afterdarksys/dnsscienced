// dnsscienced-admin — CLI for the dnsscienced gRPC admin API.
//
// Talks to:
//   - ManagementService  (zone + record CRUD)
//   - ZoneService        (UpdateRecords, GetRecords)
//   - ServerService      (status, stats)
//   - CacheService       (flush, stats)
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	mgmtpb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb/mgmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
	addr    = flag.String("addr", "localhost:9091", "gRPC admin API address (host:port)")
	apiKey  = flag.String("key", "", "API key (Bearer token)")
	timeout = flag.Duration("timeout", 15*time.Second, "Request timeout")

	// TLS / mTLS: the server requires both a client certificate and the API key.
	tlsCA      = flag.String("tls-ca", "", "PEM CA bundle that signed the server cert (required unless -insecure)")
	tlsCert    = flag.String("tls-cert", "", "client certificate for mTLS")
	tlsKey     = flag.String("tls-key", "", "client private key for mTLS")
	tlsServer  = flag.String("tls-server-name", "", "expected server name (SNI/cert CN); defaults to -addr host")
	insecureNo = flag.Bool("insecure", false, "DANGER: connect without TLS; sends the API key in cleartext")
)

// buildDialCreds returns the gRPC transport credentials for the admin connection.
// TLS (with mTLS when a client cert is supplied) is the default; -insecure is an
// explicit, loudly-warned opt-out that the operator must request.
func buildDialCreds() (credentials.TransportCredentials, error) {
	if *insecureNo {
		if *apiKey != "" {
			fmt.Fprintln(os.Stderr, "WARNING: -insecure sends your API key in CLEARTEXT over the network. Use TLS in production.")
		}
		return insecure.NewCredentials(), nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	// Server name for verification: explicit flag, else the host part of -addr.
	if *tlsServer != "" {
		tlsCfg.ServerName = *tlsServer
	} else if host := *addr; host != "" {
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		tlsCfg.ServerName = host
	}

	// Pin the server CA when provided (recommended); otherwise fall back to the
	// system trust store.
	if *tlsCA != "" {
		caPEM, err := os.ReadFile(*tlsCA)
		if err != nil {
			return nil, fmt.Errorf("read tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid CA certs in %s", *tlsCA)
		}
		tlsCfg.RootCAs = pool
	}

	// Client certificate for mTLS (the server uses RequireAndVerifyClientCert).
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			return nil, fmt.Errorf("both -tls-cert and -tls-key are required for mTLS")
		}
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(tlsCfg), nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `DNSScienced Admin CLI

Usage: %s [options] <command> [args...]

Options:
  -addr string            gRPC address (default "localhost:9091")
  -key  string            API key (Bearer token)
  -timeout dur            Request timeout (default 15s)
  -tls-ca file            CA bundle that signed the server cert (pin the server)
  -tls-cert / -tls-key    client cert + key for mTLS (server requires both)
  -tls-server-name name   expected server cert name (defaults to -addr host)
  -insecure               DANGER: no TLS; sends the API key in cleartext

By default the CLI connects over TLS. The server requires mTLS + API key, so a
typical call supplies -tls-ca, -tls-cert, -tls-key, and -key.

Zone management:
  zone list                              List all zones
  zone get <zone>                        Get zone details + records
  zone create <zone> <ns1> [ns2...]      Create a zone
  zone delete <zone>                     Delete a zone
  zone reload [zone...]                  Reload zone(s) from disk

Record management:
  record list <zone> [type]              List records in zone
  record add  <zone> <name> <type> <content> [ttl]   Add a record
  record del  <zone> <record-id>         Delete a record by ID
  record update <zone> <record-id> <type> <content> [ttl]

Dynamic update (ZoneService):
  update add    <zone> <name> <type> <data> [ttl]
  update delete <zone> <name> <type> [data]
  update replace <zone> <name> <type> <new-data> [old-data]

Server:
  server status      Server health + stats
  server reload      Reload config/zones

Cache:
  cache flush        Flush entire cache
  cache flush <zone> Flush cache for zone
  cache stats        Cache statistics

Examples:
  # List zones on ns1
  %s -addr 166.0.192.27:9091 -key $ADMIN_KEY zone list

  # Add a TXT record
  %s -addr 166.0.192.27:9091 -key $ADMIN_KEY record add itz.agency _waddr.ryan TXT "eip155:1:0xABC" 300

  # Dynamic update
  %s -addr 166.0.192.27:9091 update add itz.agency. _waddr.ryan.itz.agency. TXT "eip155:1:0xABC" 300

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *apiKey != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+*apiKey)
	}

	creds, err := buildDialCreds()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls setup: %v\n", err)
		os.Exit(1)
	}

	conn, err := grpc.DialContext(ctx, *addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect %s: %v\n", *addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	mgmt := mgmtpb.NewManagementServiceClient(conn)
	zone := pb.NewZoneServiceClient(conn)
	srv := pb.NewServerServiceClient(conn)
	cache := pb.NewCacheServiceClient(conn)

	cmd := flag.Arg(0)
	sub := ""
	if flag.NArg() > 1 {
		sub = flag.Arg(1)
	}
	args := flag.Args()[2:]

	switch cmd {
	case "zone":
		handleZone(ctx, mgmt, sub, args)
	case "record":
		handleRecord(ctx, mgmt, sub, args)
	case "update":
		handleUpdate(ctx, zone, sub, args)
	case "server":
		handleServer(ctx, srv, sub)
	case "cache":
		handleCache(ctx, cache, sub, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

// ── zone ─────────────────────────────────────────────────────────────────────

func handleZone(ctx context.Context, c mgmtpb.ManagementServiceClient, sub string, args []string) {
	switch sub {
	case "list":
		resp, err := c.ListZones(ctx, &mgmtpb.ListZonesRequest{})
		must(err)
		fmt.Printf("Zones (%d):\n", resp.Total)
		for _, z := range resp.Zones {
			fmt.Printf("  %-40s  records: %d  dnssec: %v\n", z.Domain, z.RecordCount, z.DnssecEnabled)
		}

	case "get":
		if len(args) < 1 {
			die("zone get <zone>")
		}
		resp, err := c.GetZone(ctx, &mgmtpb.GetZoneRequest{ZoneId: args[0]})
		must(err)
		z := resp.Zone
		fmt.Printf("Zone: %s\n", z.Domain)
		fmt.Printf("  NS: %v\n", z.Nameservers)
		if z.Soa != nil {
			fmt.Printf("  SOA: primary=%s serial=%d\n", z.Soa.PrimaryNs, z.Soa.Serial)
		}
		fmt.Printf("  Records: %d\n", z.RecordCount)
		fmt.Printf("  DNSSEC: %v\n", z.DnssecEnabled)

	case "create":
		if len(args) < 2 {
			die("zone create <zone> <ns1> [ns2...]")
		}
		resp, err := c.CreateZone(ctx, &mgmtpb.CreateZoneRequest{
			Domain:      args[0],
			Nameservers: args[1:],
		})
		must(err)
		fmt.Printf("Created zone %s  (ns: %v)\n", args[0], resp.Nameservers)

	case "delete":
		if len(args) < 1 {
			die("zone delete <zone>")
		}
		resp, err := c.DeleteZone(ctx, &mgmtpb.DeleteZoneRequest{ZoneId: args[0]})
		must(err)
		fmt.Println(resp.Message)

	case "reload":
		req := &mgmtpb.ReloadZonesRequest{}
		if len(args) > 0 {
			req.ZoneIds = args
		}
		resp, err := c.ReloadZones(ctx, req)
		must(err)
		fmt.Printf("Reloaded %d zone(s). %s\n", resp.ZonesReloaded, resp.Message)
		if resp.Error != "" {
			fmt.Fprintf(os.Stderr, "Errors: %s\n", resp.Error)
		}

	default:
		die("zone [list|get|create|delete|reload]")
	}
}

// ── record ───────────────────────────────────────────────────────────────────

func handleRecord(ctx context.Context, c mgmtpb.ManagementServiceClient, sub string, args []string) {
	switch sub {
	case "list":
		if len(args) < 1 {
			die("record list <zone> [type]")
		}
		req := &mgmtpb.ListRecordsRequest{ZoneId: args[0]}
		if len(args) > 1 {
			req.RecordType = args[1]
		}
		resp, err := c.ListRecords(ctx, req)
		must(err)
		fmt.Printf("Records in %s (%d):\n", args[0], resp.Total)
		for _, r := range resp.Records {
			fmt.Printf("  %-50s  %-6s  %5d  %s\n", r.Name, r.RecordType, r.Ttl, r.Content)
		}

	case "add":
		// record add <zone> <name> <type> <content> [ttl]
		if len(args) < 4 {
			die("record add <zone> <name> <type> <content> [ttl]")
		}
		ttl := int32(300)
		if len(args) > 4 {
			n, _ := strconv.Atoi(args[4])
			ttl = int32(n)
		}
		resp, err := c.CreateRecord(ctx, &mgmtpb.CreateRecordRequest{
			ZoneId: args[0],
			Record: &mgmtpb.DNSRecord{
				Name:       args[1],
				RecordType: strings.ToUpper(args[2]),
				Content:    args[3],
				Ttl:        ttl,
			},
		})
		must(err)
		fmt.Printf("Created record %s  (id: %s)\n", resp.Message, resp.RecordId)

	case "del", "delete":
		// record del <zone> <record-id>
		if len(args) < 2 {
			die("record del <zone> <record-id>")
		}
		resp, err := c.DeleteRecord(ctx, &mgmtpb.DeleteRecordRequest{
			ZoneId:   args[0],
			RecordId: args[1],
		})
		must(err)
		fmt.Println(resp.Message)

	case "update":
		// record update <zone> <record-id> <type> <content> [ttl]
		if len(args) < 4 {
			die("record update <zone> <record-id> <type> <content> [ttl]")
		}
		ttl := int32(300)
		if len(args) > 4 {
			n, _ := strconv.Atoi(args[4])
			ttl = int32(n)
		}
		resp, err := c.UpdateRecord(ctx, &mgmtpb.UpdateRecordRequest{
			ZoneId:   args[0],
			RecordId: args[1],
			Record: &mgmtpb.DNSRecord{
				RecordType: strings.ToUpper(args[2]),
				Content:    args[3],
				Ttl:        ttl,
			},
		})
		must(err)
		fmt.Println(resp.Message)

	default:
		die("record [list|add|del|update]")
	}
}

// ── update (ZoneService dynamic DNS) ─────────────────────────────────────────

func handleUpdate(ctx context.Context, c pb.ZoneServiceClient, sub string, args []string) {
	// update add    <zone> <name> <type> <data> [ttl]
	// update delete <zone> <name> <type> [data]
	// update replace <zone> <name> <type> <new-data> [old-data]
	if len(args) < 3 {
		die("update <add|delete|replace> <zone> <name> <type> [data...]")
	}

	zone := args[0]
	name := args[1]
	rtype := strings.ToUpper(args[2])
	data := ""
	if len(args) > 3 {
		data = args[3]
	}
	ttl := uint32(300)
	if len(args) > 4 {
		n, _ := strconv.Atoi(args[4])
		ttl = uint32(n)
	}

	var op pb.UpdateOperation
	switch sub {
	case "add":
		op = pb.UpdateOperation_UPDATE_OPERATION_ADD
	case "delete", "del":
		op = pb.UpdateOperation_UPDATE_OPERATION_DELETE
	case "replace":
		op = pb.UpdateOperation_UPDATE_OPERATION_REPLACE
	default:
		die("update [add|delete|replace]")
	}

	upd := &pb.RecordUpdate{
		Operation: op,
		Name:      name,
		Type:      rtype,
		Ttl:       ttl,
		Data:      data,
	}
	if sub == "replace" && len(args) > 4 {
		upd.OldData = args[4]
	}

	resp, err := c.UpdateRecords(ctx, &pb.UpdateRecordsRequest{
		ZoneName:        zone,
		Updates:         []*pb.RecordUpdate{upd},
		IncrementSerial: true,
	})
	must(err)

	fmt.Printf("Applied: %d  Failed: %d  Serial: %d\n", resp.Applied, resp.Failed, resp.NewSerial)
	for _, r := range resp.Results {
		status := "ok"
		if !r.Success {
			status = "FAIL: " + r.Error
		}
		fmt.Printf("  %s %s %s → %s\n", r.Update.Name, r.Update.Type, r.Update.Data, status)
	}
}

// ── server ────────────────────────────────────────────────────────────────────

func handleServer(ctx context.Context, c pb.ServerServiceClient, sub string) {
	switch sub {
	case "status", "":
		resp, err := c.GetStatus(ctx, &pb.GetStatusRequest{IncludeResources: true})
		must(err)
		s := resp.Server
		fmt.Printf("Server: %s  version: %s  uptime: %s\n",
			s.Hostname, s.Version, fmtUptime(s.UptimeSeconds))
		if resp.Health != nil {
			fmt.Printf("Health: %s\n", resp.Health.Status)
		}

	case "reload":
		resp, err := c.Reload(ctx, &pb.ReloadRequest{})
		must(err)
		fmt.Printf("Success: %v  %s\n", resp.Success, resp.Message)

	default:
		die("server [status|reload]")
	}
}

// ── cache ─────────────────────────────────────────────────────────────────────

func handleCache(ctx context.Context, c pb.CacheServiceClient, sub string, args []string) {
	switch sub {
	case "flush":
		req := &pb.FlushCacheRequest{Scope: pb.FlushCacheRequest_FLUSH_SCOPE_ALL}
		if len(args) > 0 {
			req.Scope = pb.FlushCacheRequest_FLUSH_SCOPE_DOMAIN
			req.Domain = args[0]
		}
		resp, err := c.Flush(ctx, req)
		must(err)
		fmt.Printf("Flushed %d entries.\n", resp.EntriesRemoved)

	case "stats":
		resp, err := c.GetStats(ctx, &pb.GetCacheStatsRequest{})
		must(err)
		if resp.Stats != nil {
			fmt.Printf("Cache: entries=%d  size=%d bytes  hit_rate=%.1f%%\n",
				resp.Stats.Entries, resp.Stats.SizeBytes, resp.Stats.HitRate*100)
		}

	default:
		die("cache [flush|stats]")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func die(msg string) {
	fmt.Fprintf(os.Stderr, "usage: %s\n", msg)
	os.Exit(1)
}

func fmtUptime(secs int64) string {
	d := time.Duration(secs) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
