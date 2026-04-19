package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/dnsscience/dnsscienced/api/grpc/middleware"
	"github.com/dnsscience/dnsscienced/api/grpc/registry"
	"github.com/dnsscience/dnsscienced/api/grpc/server"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func main() {
cfgPath := flag.String("config", "", "Path to YAML config file")
listen := flag.String("listen", "", "gRPC listen address (overrides config)")
metricsListen := flag.String("metrics-listen", "", "Prometheus metrics listen address (overrides config)")
apiKeys := flag.String("api-keys", "", "Comma-separated API keys (overrides config)")
cert := flag.String("tls-cert", "", "TLS certificate file (overrides config)")
key := flag.String("tls-key", "", "TLS private key file (overrides config)")
flag.Parse()

// Load config file if provided
var fileCfg *ConfigFile
if *cfgPath != "" {
	c, err := LoadConfig(*cfgPath)
	if err != nil { log.Fatalf("load config: %v", err) }
	fileCfg = c
}

// Resolve effective settings (flags override config, then defaults)
eListen := ":8443"
eMetrics := ":9090"
eAPIKeys := []string{}
eCert := ""
eKey := ""
if fileCfg != nil {
	if fileCfg.Listen != "" { eListen = fileCfg.Listen }
	if fileCfg.MetricsListen != "" { eMetrics = fileCfg.MetricsListen }
	if len(fileCfg.APIKeys) > 0 { eAPIKeys = append(eAPIKeys, fileCfg.APIKeys...) }
	if fileCfg.TLSCert != "" { eCert = fileCfg.TLSCert }
	if fileCfg.TLSKey != "" { eKey = fileCfg.TLSKey }
}
if *listen != "" { eListen = *listen }
if *metricsListen != "" { eMetrics = *metricsListen }
if *apiKeys != "" { eAPIKeys = append(eAPIKeys, *apiKeys) }
if *cert != "" { eCert = *cert }
if *key != "" { eKey = *key }

	// Start metrics HTTP server
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
log.Printf("metrics listening on %s", eMetrics)
if err := http.ListenAndServe(eMetrics, mux); err != nil {
			log.Printf("metrics server error: %v", err)
		}
	}()

cfg := server.Config{ListenAddr: eListen, TLSCertFile: eCert, TLSKeyFile: eKey, APIKeys: eAPIKeys}
	deps := server.Deps{
		Register: func(s *grpc.Server) {},
		Unary:    []grpc.UnaryServerInterceptor{middleware.UnaryLoggingMetrics()},
		Stream:   []grpc.StreamServerInterceptor{middleware.StreamLoggingMetrics()},
	}
	// register services
	deps.Register = func(s *grpc.Server) {
		// health and reflection
		h := health.NewServer()
		healthpb.RegisterHealthServer(s, h)
		reflection.Register(s)
		registry.RegisterAll(s, &registry.NoopSrvAdapter{}, "", "")
	}

	gs, ln, err := server.New(cfg, deps)
	if err != nil { log.Fatalf("server: %v", err) }
	log.Printf("gRPC listening on %s", ln.Addr())
	if err := gs.Serve(ln); err != nil { log.Fatalf("serve: %v", err) }
}
