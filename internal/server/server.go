package server

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"strings"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/cookie"
	"github.com/dnsscience/dnsscienced/internal/defensive"
	"github.com/dnsscience/dnsscienced/internal/dsync"
	"github.com/dnsscience/dnsscienced/internal/engine"
	"github.com/dnsscience/dnsscienced/internal/eventbus"
	"github.com/dnsscience/dnsscienced/internal/experimental"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
	"github.com/dnsscience/dnsscienced/internal/pool"
	"github.com/dnsscience/dnsscienced/internal/primarynotify"
	"github.com/dnsscience/dnsscienced/internal/protective"
	"github.com/dnsscience/dnsscienced/internal/reputation"
	"github.com/dnsscience/dnsscienced/internal/resolver"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/transport"
	"github.com/dnsscience/dnsscienced/internal/tsig"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// Config holds DNS server configuration
type Config struct {
	// Listen addresses
	UDPAddr string              `yaml:"udp_addr"`
	TCPAddr string              `yaml:"tcp_addr"`
	DoH     transport.DoHConfig `yaml:"doh"`
	DoT     transport.DoTConfig `yaml:"dot"`
	XoT     XoTConfig           `yaml:"xot"`

	// Number of UDP listeners (SO_REUSEPORT)
	// Set to runtime.NumCPU() for maximum performance
	UDPListeners int `yaml:"udp_listeners"`

	// Enable recursive resolver
	EnableRecursive       bool            `yaml:"enable_recursive"`
	RecursionAllowedCIDRs []string        `yaml:"recursion_allowed_cidrs"`
	RecursiveConfig       resolver.Config `yaml:"recursive"`

	// Enable authoritative server
	EnableAuthoritative bool                  `yaml:"enable_authoritative"`
	Zones               map[string]*zone.Zone `yaml:"-"` // Zones are loaded separately or via a different config mechanism

	// Security features
	EnableCookies bool          `yaml:"enable_cookies"`
	CookieConfig  cookie.Config `yaml:"cookies"`

	EnableRRL bool       `yaml:"enable_rrl"`
	RRLConfig rrl.Config `yaml:"rrl"`

	// Defensive DNS manager (set separately to avoid import cycle)
	DefensiveManager *defensive.Manager `yaml:"-"`

	// DNS Firewall (dnsfirewalld)
	Firewall firewalld.Config `yaml:"firewall"`

	// Response Policy Zones. Policies are loaded atomically at startup and can
	// be reloaded with ReloadRPZ.
	RPZ RPZConfig `yaml:"rpz"`

	// QueryComplexity rejects unusually expensive query combinations before
	// authoritative, policy, or recursive work.
	QueryComplexity QueryComplexityConfig `yaml:"query_complexity"`

	// ClientReputation progressively reduces the admission rate for clients
	// that send suspicious or policy-blocked traffic.
	ClientReputation reputation.Config `yaml:"client_reputation"`

	// Experimental IETF draft protocols
	Experimental experimental.Config `yaml:"experimental"`

	// TSIG keys for authenticated transfers/updates (set by main.go from config.TsigKeys).
	// Populated externally after config load — not decoded from server yaml section directly.
	// Conversion from config.TsigKeyConfig to tsig.KeyConfig happens at config load time.
	TsigKeys []tsig.KeyConfig `yaml:"-"`

	// ZoneTransferCIDRs maps zone FQDN origin to CIDR strings allowed to AXFR.
	// Populated by main.go from config.ZoneConfig.AllowTransfer.
	// Empty/absent = deny all (D-01).
	ZoneTransferCIDRs     map[string][]string `yaml:"-"`
	ZoneTransferTLSOnly   map[string]bool     `yaml:"-"`
	ZoneAllowAXFRFallback map[string]bool     `yaml:"-"`

	// ZoneUpdateCIDRs maps zone FQDN origin to CIDR strings allowed to send RFC 2136 UPDATE.
	// Populated by main.go from config.ZoneConfig.AllowUpdate.
	// Empty/absent = deny all (D-15).
	ZoneUpdateCIDRs map[string][]string `yaml:"-"`

	// ZoneUpdateTSIGKeys maps zone FQDN origin to TSIG key names authorized to
	// send RFC 2136 UPDATE. Empty/absent = deny all.
	ZoneUpdateTSIGKeys map[string][]string `yaml:"-"`

	// PersistPaths maps zone FQDN origin to the .dnszone file path for write-back
	// after a successful RFC 2136 UPDATE (D-11, D-13).
	// Populated by main.go from config.ZoneConfig.PersistUpdates + File.
	// Zones absent from this map use in-memory-only updates (D-12).
	PersistPaths map[string]string `yaml:"-"`

	// PrimaryNotifyZones is populated from primary zone stanzas. Workers are
	// fixed and zones are deterministically routed to preserve ordering.
	PrimaryNotifyWorkers int                                 `yaml:"primary_notify_workers"`
	PrimaryNotifyZones   map[string]primarynotify.ZoneConfig `yaml:"-"`

	// DSYNC configures inbound RFC 9859 NOTIFY(CDS/CSYNC) handling.
	DSYNC DSYNCConfig `yaml:"dsync"`

	// Performance tuning
	ReadTimeout   time.Duration                 `yaml:"read_timeout"`
	WriteTimeout  time.Duration                 `yaml:"write_timeout"`
	IdleTimeout   time.Duration                 `yaml:"idle_timeout"` // TCP only
	TCPProtection transport.TCPProtectionConfig `yaml:"tcp_protection"`

	// UDP buffer sizes
	UDPReadBuffer  int `yaml:"udp_read_buffer"`
	UDPWriteBuffer int `yaml:"udp_write_buffer"`
}

// DSYNCConfig configures inbound RFC 9859 NOTIFY handling.
type DSYNCConfig struct {
	// Enabled: accept and process inbound NOTIFY(CDS/CSYNC) messages.
	Enabled bool `yaml:"enabled"`

	// RateLimitPerMin: max NOTIFY messages processed per source IP per minute.
	// Default: 5 (per D-13: 5 NOTIFY/min per source IP).
	RateLimitPerMin int `yaml:"rate_limit_per_min"`

	// Burst: token bucket burst size. Default: 10.
	Burst int `yaml:"burst"`

	// Resolver is the DNS resolver address used for outbound _dsync discovery queries
	// (e.g., "8.8.8.8:53"). Must NOT be the server's own listen address.
	// Default: "8.8.8.8:53".
	Resolver string `yaml:"resolver"`

	// AllowedSources is the list of CIDRs/IPs permitted to send inbound
	// NOTIFY(CDS/CSYNC) messages. Empty = accept all sources (open).
	// Strongly recommended to restrict to your parent zone operator's IPs.
	AllowedSources []string `yaml:"allowed_sources,omitempty"`
}

// DefaultConfig returns default server configuration
func DefaultConfig() Config {
	rcfg := resolver.DefaultConfig()
	rcfg.CacheConfig.ShardCount = 256
	rcfg.CacheConfig.MaxEntries = 100000
	rcfg.Workers = 1000
	rcfg.QueryTimeout = 5 * time.Second
	rcfg.MaxIterations = 20

	return Config{
		UDPAddr:      ":53",
		TCPAddr:      ":53",
		UDPListeners: runtime.NumCPU(),

		// Recursion is opt-in. When enabled without an explicit ACL, New limits it
		// to loopback clients so a default deployment cannot become an open resolver.
		EnableRecursive:       false,
		RecursionAllowedCIDRs: []string{"127.0.0.0/8", "::1/128"},
		RecursiveConfig:       rcfg,

		EnableAuthoritative: false,
		Zones:               make(map[string]*zone.Zone),

		EnableCookies: true,
		CookieConfig: cookie.Config{
			Enabled: true,
		},

		EnableRRL: true,
		RRLConfig: rrl.DefaultConfig(),

		Experimental:     experimental.DefaultConfig(),
		QueryComplexity:  defaultQueryComplexityConfig(),
		ClientReputation: reputation.DefaultConfig(),

		ReadTimeout:   5 * time.Second,
		WriteTimeout:  5 * time.Second,
		IdleTimeout:   60 * time.Second,
		TCPProtection: transport.DefaultTCPProtectionConfig(),

		UDPReadBuffer:  8 * 1024 * 1024, // 8MB
		UDPWriteBuffer: 8 * 1024 * 1024, // 8MB
	}
}

// Server is the main DNS server
type Server struct {
	cfg Config

	// zonesMu protects concurrent reads and writes to cfg.Zones (CR-01).
	// Acquire RLock for reads (lookups in handleAuthoritative, handleUpdate).
	// Acquire Lock for writes (atomic swap in handleUpdate, AddZone, RemoveZone).
	zonesMu sync.RWMutex

	// Components
	recursive        *resolver.Recursive
	recursionACL     *engine.ACL
	cookies          *cookie.Manager
	rrl              *rrl.Limiter
	defensive        *defensive.Manager
	reputation       *reputation.Limiter
	protective       *protective.Engine
	firewall         *firewalld.Firewall
	rpz              atomic.Pointer[engine.RPZAggregate]
	tsigKeyRing      *tsig.KeyRing
	dsyncHandler     *dsync.Handler
	dsyncNotifier    *dsync.DSYNCNotifier
	zoneTransferACLs map[string]*dsync.SourceACL    // Per-zone transfer ACLs. nil entry = deny all (D-01).
	zoneUpdateACLs   map[string]*dsync.SourceACL    // Per-zone update ACLs.  nil entry = deny all (D-15).
	zoneUpdateKeys   map[string]map[string]struct{} // Per-zone TSIG identities. nil entry = deny all.
	primaryNotifier  *primarynotify.Notifier
	soaNotifyMu      sync.RWMutex
	soaNotifyHandler SOANotifyHandler
	ixfrJournal      *zone.Journal
	persistPaths     map[string]string // Per-zone file paths for persist_updates write-back (D-11).
	persistMu        sync.Mutex        // Stable linearization boundary for all zone-map mutations and durable UPDATE commits.

	// Event bus for real-time query streaming
	bus *eventbus.Bus

	// DNS servers (one per listener for SO_REUSEPORT)
	udpServers []*dns.Server
	tcpServer  *dns.Server
	tcpLimiter *transport.LimitedListener
	dohServer  *transport.DoHListener
	dotServer  *transport.DoTListener
	xotServer  *dns.Server
	xotTLS     *tls.Config
	xotLimiter *transport.LimitedListener

	// Statistics
	queries  atomic.Uint64
	answers  atomic.Uint64
	errors   atomic.Uint64
	nxdomain atomic.Uint64

	// Transport-level counters
	udpQueries         atomic.Uint64
	tcpQueries         atomic.Uint64
	complexityRejected atomic.Uint64

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new DNS server
func New(cfg Config) (*Server, error) {
	if cfg.UDPListeners == 0 {
		cfg.UDPListeners = runtime.NumCPU()
	}
	if cfg.UDPListeners < 1 || cfg.UDPListeners > 65536 {
		return nil, fmt.Errorf("udp_listeners must be zero (auto) or between 1 and 65536 (got %d)", cfg.UDPListeners)
	}
	if err := cfg.TCPProtection.Validate(); err != nil {
		return nil, err
	}
	complexityConfig, err := normalizeQueryComplexityConfig(cfg.QueryComplexity)
	if err != nil {
		return nil, err
	}
	cfg.QueryComplexity = complexityConfig
	clientReputation, err := reputation.New(cfg.ClientReputation)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		cfg:         cfg,
		ctx:         ctx,
		cancel:      cancel,
		ixfrJournal: zone.NewJournal(100),
		reputation:  clientReputation,
	}

	// Initialize recursive resolver if enabled
	if cfg.EnableRecursive {
		allowedCIDRs := cfg.RecursionAllowedCIDRs
		if len(allowedCIDRs) == 0 {
			allowedCIDRs = []string{"127.0.0.0/8", "::1/128"}
		}
		s.recursionACL = engine.NewACL(false)
		for _, cidr := range allowedCIDRs {
			if err := s.recursionACL.AllowNet(cidr); err != nil {
				cancel()
				return nil, fmt.Errorf("recursion_allowed_cidrs %q: %w", cidr, err)
			}
		}

		var err error
		s.recursive, err = resolver.NewRecursive(cfg.RecursiveConfig)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("init recursive resolver: %w", err)
		}
	}

	// Initialize cookies if enabled
	if cfg.EnableCookies {
		var err error
		s.cookies, err = cookie.NewManager(cfg.CookieConfig)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("init cookies: %w", err)
		}
	}

	// Log experimental features if enabled
	if cfg.Experimental.IsAnyEnabled() {
		features := cfg.Experimental.EnabledFeatures()
		fmt.Printf("⚠️  Experimental Features Enabled (%d):\n", len(features))
		for _, feature := range features {
			fmt.Printf("   • %s\n", feature)
		}
		fmt.Println()
	}

	// Initialize Protective DNS if enabled
	if cfg.Experimental.ProtectiveDNS.Enabled {
		var err error
		s.protective, err = protective.NewEngine(cfg.Experimental.ProtectiveDNS)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("init protective DNS: %w", err)
		}
		fmt.Printf("🛡️  Protective DNS enabled (strategy: %s, blocklist size: %d)\n",
			cfg.Experimental.ProtectiveDNS.Strategy,
			s.protective.GetBlocklistStats().TotalEntries)
	}

	// Initialize DNS Firewall if enabled
	if cfg.Firewall.Enabled {
		var err error
		s.firewall, err = firewalld.New(cfg.Firewall)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("init firewalld: %w", err)
		}
	}

	// Start live threat feed poller when firewall is enabled and feed_url is configured.
	// StartFeed is a no-op when FeedURL is empty (D-09), so the nil and empty-URL guards
	// are both handled inside StartFeed itself.
	if s.firewall != nil {
		s.firewall.StartFeed(s.ctx, &s.wg)
	}

	if err := s.ReloadRPZ(cfg.RPZ); err != nil {
		cancel()
		return nil, fmt.Errorf("init RPZ: %w", err)
	}

	// Initialize RRL if enabled
	if cfg.EnableRRL {
		s.rrl = rrl.NewLimiter(cfg.RRLConfig)
	}

	// Initialize DSYNC inbound handler if enabled (RFC 9859)
	if cfg.DSYNC.Enabled {
		rpm := cfg.DSYNC.RateLimitPerMin
		if rpm <= 0 {
			rpm = 5 // default: 5 NOTIFY/min per source IP (per D-13)
		}
		burst := cfg.DSYNC.Burst
		if burst <= 0 {
			burst = 10
		}
		rps := float64(rpm) / 60.0
		// Create DSYNC Prometheus metrics first so they can be passed to constructors,
		// eliminating the data race window between worker goroutine start and SetMetrics.
		dsyncMetrics := dsync.NewDSYNCMetrics()

		limiter := dsync.NewNotifyLimiter(rps, burst)
		sourceACL, aclErr := dsync.NewSourceACL(cfg.DSYNC.AllowedSources)
		if aclErr != nil {
			return nil, fmt.Errorf("dsync allowed_sources: %w", aclErr)
		}
		if len(cfg.DSYNC.AllowedSources) == 0 {
			// Warn operators that all sources are accepted when no ACL is configured.
			// Set allowed_sources in the dsync config to restrict to known parent IPs.
			zerolog.Ctx(context.Background()).Warn().Msg("DSYNC enabled with no allowed_sources — accepting NOTIFY from any source IP")
		}
		s.dsyncHandler = dsync.NewHandler(limiter, sourceACL, zerolog.Nop(), dsyncMetrics)

		// Create outbound DSYNC notifier (RFC 9859 sender).
		// PropagationDelay defaults to 60s per RFC 9859 recommendation.
		// Resolver defaults to 8.8.8.8:53 if not configured.
		dsyncResolver := cfg.DSYNC.Resolver
		if dsyncResolver == "" {
			dsyncResolver = "8.8.8.8:53"
		}
		s.dsyncNotifier = dsync.NewDSYNCNotifier(dsyncResolver, 60*time.Second, zerolog.Nop(), dsyncMetrics)

		// Webhook: per-zone config (ZoneDSYNCConfig.WebhookURL) — not available at
		// server-level DSYNCConfig. Per-zone webhook wiring requires zone iteration
		// which is not implemented yet. For now, SetWebhook is called only if a
		// future global webhook_url is added to DSYNCConfig.
	}

	// Set defensive manager if provided
	s.defensive = cfg.DefensiveManager

	// Initialize TSIG key ring unconditionally — empty ring is valid.
	// This allows AddTsigKey gRPC to bootstrap keys even when none are in startup config.
	s.tsigKeyRing, _ = tsig.NewKeyRing(nil)

	if len(cfg.TsigKeys) > 0 {
		for _, kc := range cfg.TsigKeys {
			if err := s.tsigKeyRing.Add(kc); err != nil {
				cancel()
				return nil, fmt.Errorf("init TSIG key ring: add key %q: %w", kc.Name, err)
			}
		}
	}

	// Build per-zone transfer ACLs from ZoneTransferCIDRs.
	// D-01: zones with no entry or empty CIDR list get nil ACL = deny all.
	//
	// NOTE: NewSourceACL(emptySlice) returns allowAll=true (correct for DSYNC
	// notify sources, where an empty list means "accept from anywhere").  For
	// AXFR we want the opposite: an empty allow_transfer list means deny all.
	// We therefore intercept the empty-list case here and store nil explicitly,
	// never passing an empty slice to NewSourceACL.  Any future call site that
	// needs deny-all-on-empty semantics MUST do the same check before calling
	// NewSourceACL, or use a purpose-built constructor.
	s.zoneTransferACLs = make(map[string]*dsync.SourceACL)
	for zoneName, cidrs := range cfg.ZoneTransferCIDRs {
		if len(cidrs) == 0 {
			s.zoneTransferACLs[zoneName] = nil // deny-all: no allow_transfer configured
			continue
		}
		acl, err := dsync.NewSourceACL(cidrs)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("zone %s allow_transfer: %w", zoneName, err)
		}
		s.zoneTransferACLs[zoneName] = acl
	}

	// Build per-zone update ACLs from ZoneUpdateCIDRs.
	// D-15: zones with no entry or empty CIDR list get nil ACL = deny all.
	// CRITICAL: Do NOT pass empty slice to NewSourceACL — it returns allowAll=true.
	// Empty AllowUpdate = no UPDATE allowed (secure-by-default, mirrors AXFR pattern).
	s.zoneUpdateACLs = make(map[string]*dsync.SourceACL)
	for zoneName, cidrs := range cfg.ZoneUpdateCIDRs {
		if len(cidrs) == 0 {
			s.zoneUpdateACLs[zoneName] = nil // deny-all: no allow_update configured
			continue
		}
		acl, err := dsync.NewSourceACL(cidrs)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("zone %s allow_update: %w", zoneName, err)
		}
		s.zoneUpdateACLs[zoneName] = acl
	}

	// Build per-zone UPDATE key authorization independently from TSIG
	// authentication. A valid key proves identity; this map grants that identity
	// permission to mutate one specific zone.
	configuredKeys := s.tsigKeyRing.Algorithms()
	s.zoneUpdateKeys = make(map[string]map[string]struct{})
	for zoneName, keyNames := range cfg.ZoneUpdateTSIGKeys {
		if len(keyNames) == 0 {
			continue
		}
		allowed := make(map[string]struct{}, len(keyNames))
		for _, keyName := range keyNames {
			normalized := strings.ToLower(dns.Fqdn(strings.TrimSpace(keyName)))
			if normalized == "." {
				cancel()
				return nil, fmt.Errorf("zone %s update_tsig_keys contains an empty key name", zoneName)
			}
			if _, ok := configuredKeys[normalized]; !ok {
				cancel()
				return nil, fmt.Errorf("zone %s update_tsig_keys references undefined key %q", zoneName, keyName)
			}
			allowed[normalized] = struct{}{}
		}
		s.zoneUpdateKeys[strings.ToLower(dns.Fqdn(zoneName))] = allowed
	}

	for zoneName, notifyCfg := range cfg.PrimaryNotifyZones {
		if notifyCfg.TSIGKey == "" {
			continue
		}
		keyName := strings.ToLower(dns.Fqdn(notifyCfg.TSIGKey))
		configuredAlgorithm, ok := configuredKeys[keyName]
		if !ok {
			cancel()
			return nil, fmt.Errorf("zone %s notify_tsig_key references undefined key %q", zoneName, notifyCfg.TSIGKey)
		}
		if notifyCfg.TSIGAlgorithm == "" {
			notifyCfg.TSIGAlgorithm = configuredAlgorithm
			cfg.PrimaryNotifyZones[zoneName] = notifyCfg
		} else if dns.CanonicalName(notifyCfg.TSIGAlgorithm) != configuredAlgorithm {
			cancel()
			return nil, fmt.Errorf(
				"zone %s notify_tsig_key %q algorithm %q does not match configured algorithm %q",
				zoneName,
				notifyCfg.TSIGKey,
				notifyCfg.TSIGAlgorithm,
				configuredAlgorithm,
			)
		}
	}
	if len(cfg.PrimaryNotifyZones) > 0 {
		var err error
		s.primaryNotifier, err = primarynotify.New(primarynotify.Config{
			Workers: cfg.PrimaryNotifyWorkers,
			Zones:   cfg.PrimaryNotifyZones,
		}, s.tsigKeyRing, func(zoneName, target string, err error) {
			zerolog.Ctx(context.Background()).Warn().
				Str("zone", zoneName).
				Str("target", target).
				Err(err).
				Msg("RFC 1996 NOTIFY delivery failed")
		})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("init primary notify: %w", err)
		}
	}

	// Wire per-zone persist paths from config (D-11, D-12).
	// Main.go populates cfg.PersistPaths with zones that have persist_updates=true.
	// Zones absent from the map use in-memory-only updates.
	s.persistPaths = cfg.PersistPaths

	// Create UDP servers (SO_REUSEPORT)
	for i := 0; i < cfg.UDPListeners; i++ {
		udpServer := &dns.Server{
			Addr:      cfg.UDPAddr,
			Net:       "udp",
			ReusePort: true, // SO_REUSEPORT magic!
			Handler:   dns.HandlerFunc(s.handleDNS),

			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,

			UDPSize:      4096,
			TsigProvider: s.tsigKeyRing,
		}

		s.udpServers = append(s.udpServers, udpServer)
	}

	// Create TCP server
	s.tcpServer = &dns.Server{
		Addr:    cfg.TCPAddr,
		Net:     "tcp",
		Handler: dns.HandlerFunc(s.handleDNS),

		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout: func() time.Duration {
			return cfg.IdleTimeout
		},
		MaxTCPQueries: cfg.TCPProtection.MaxQueriesPerConnection,
		TsigProvider:  s.tsigKeyRing,
	}

	if cfg.DoH.Enabled {
		var err error
		s.dohServer, err = transport.NewDoHListener(cfg.DoH, s)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("init DNS-over-HTTPS listener: %w", err)
		}
	}
	if cfg.DoT.Enabled {
		var err error
		s.dotServer, err = transport.NewDoTListener(cfg.DoT, s)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("init DNS-over-TLS listener: %w", err)
		}
	}
	if cfg.XoT.Enabled {
		var err error
		s.xotTLS, err = loadXoTTLSConfig(cfg.XoT)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("init XFR-over-TLS listener: %w", err)
		}
		s.xotServer = &dns.Server{
			Net:          "tcp-tls",
			Handler:      dns.HandlerFunc(s.handleXoT),
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout: func() time.Duration {
				return cfg.IdleTimeout
			},
			MaxTCPQueries: cfg.TCPProtection.MaxQueriesPerConnection,
			TsigProvider:  s.tsigKeyRing,
		}
	}

	return s, nil
}

// Start starts all DNS listeners
func (s *Server) Start() error {
	if s.cfg.TCPAddr != "" {
		baseListener, err := net.Listen("tcp", s.cfg.TCPAddr)
		if err != nil {
			return fmt.Errorf("listen TCP DNS: %w", err)
		}
		listener, err := transport.NewLimitedListener(baseListener, s.cfg.TCPProtection)
		if err != nil {
			_ = baseListener.Close()
			return fmt.Errorf("protect TCP DNS listener: %w", err)
		}
		s.tcpServer.Listener = listener
		if limited, ok := listener.(*transport.LimitedListener); ok {
			s.tcpLimiter = limited
		}
	}
	closeTCPListener := func() {
		if s.tcpServer.Listener != nil {
			_ = s.tcpServer.Listener.Close()
			s.tcpServer.Listener = nil
			s.tcpLimiter = nil
		}
	}
	closeXoTListener := func() {
		if s.xotServer != nil && s.xotServer.Listener != nil {
			_ = s.xotServer.Listener.Close()
			s.xotServer.Listener = nil
			s.xotLimiter = nil
		}
	}
	if s.xotServer != nil {
		baseListener, err := net.Listen("tcp", xotAddress(s.cfg.XoT))
		if err != nil {
			closeTCPListener()
			return fmt.Errorf("listen XFR-over-TLS: %w", err)
		}
		listener, err := transport.NewLimitedListener(baseListener, s.cfg.TCPProtection)
		if err != nil {
			_ = baseListener.Close()
			closeTCPListener()
			return fmt.Errorf("protect XFR-over-TLS listener: %w", err)
		}
		if limited, ok := listener.(*transport.LimitedListener); ok {
			s.xotLimiter = limited
		}
		s.xotServer.Listener = tls.NewListener(listener, s.xotTLS)
	}
	if s.dohServer != nil {
		if err := s.dohServer.Start(); err != nil {
			closeXoTListener()
			closeTCPListener()
			return fmt.Errorf("start DNS-over-HTTPS listener: %w", err)
		}
	}
	if s.dotServer != nil {
		if err := s.dotServer.Start(); err != nil {
			if s.dohServer != nil {
				_ = s.dohServer.Stop()
			}
			closeXoTListener()
			closeTCPListener()
			return fmt.Errorf("start DNS-over-TLS listener: %w", err)
		}
	}
	if s.primaryNotifier != nil {
		if err := s.primaryNotifier.Start(s.ctx); err != nil {
			if s.dohServer != nil {
				_ = s.dohServer.Stop()
			}
			if s.dotServer != nil {
				_ = s.dotServer.Stop()
			}
			closeXoTListener()
			closeTCPListener()
			return fmt.Errorf("start primary notify: %w", err)
		}
	}
	// Start UDP listeners (SO_REUSEPORT)
	for i, udpServer := range s.udpServers {
		i := i
		udpServer := udpServer

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()

			fmt.Printf("UDP listener %d started on %s (SO_REUSEPORT)\n", i, s.cfg.UDPAddr)

			if err := udpServer.ListenAndServe(); err != nil {
				fmt.Printf("UDP listener %d error: %v\n", i, err)
			}
		}()
	}

	// Start the pre-bound, admission-limited TCP listener.
	if s.tcpServer.Listener != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()

			fmt.Printf("TCP listener started on %s\n", s.cfg.TCPAddr)

			if err := s.tcpServer.ActivateAndServe(); err != nil {
				fmt.Printf("TCP listener error: %v\n", err)
			}
		}()
	}
	if s.xotServer != nil && s.xotServer.Listener != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			fmt.Printf("XFR-over-TLS listener started on %s\n", xotAddress(s.cfg.XoT))
			if err := s.xotServer.ActivateAndServe(); err != nil {
				fmt.Printf("XFR-over-TLS listener error: %v\n", err)
			}
		}()
	}

	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	fmt.Println("Shutting down DNS server...")

	// Cancel context
	s.cancel()
	if s.dohServer != nil {
		if err := s.dohServer.Stop(); err != nil {
			fmt.Printf("Error shutting down DNS-over-HTTPS listener: %v\n", err)
		}
	}
	if s.dotServer != nil {
		if err := s.dotServer.Stop(); err != nil {
			fmt.Printf("Error shutting down DNS-over-TLS listener: %v\n", err)
		}
	}
	if s.xotServer != nil && s.xotServer.Listener != nil {
		if err := s.xotServer.Shutdown(); err != nil {
			fmt.Printf("Error shutting down XFR-over-TLS listener: %v\n", err)
		}
	}

	// Shutdown all UDP servers
	for i, udpServer := range s.udpServers {
		if err := udpServer.Shutdown(); err != nil {
			fmt.Printf("Error shutting down UDP listener %d: %v\n", i, err)
		}
	}

	// Shutdown TCP server
	if s.tcpServer.Listener != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			fmt.Printf("Error shutting down TCP listener: %v\n", err)
		}
	}

	// Wait for all goroutines
	s.wg.Wait()

	// Close components
	if s.recursive != nil {
		s.recursive.Close()
	}
	if s.rrl != nil {
		s.rrl.Close()
	}
	if s.defensive != nil {
		s.defensive.Close()
	}
	if s.protective != nil {
		s.protective.Shutdown()
	}
	if s.firewall != nil {
		s.firewall.Shutdown()
	}

	// Stop the DSYNC notifier worker goroutine.
	if s.dsyncNotifier != nil {
		s.dsyncNotifier.Close()
	}
	if s.primaryNotifier != nil {
		s.primaryNotifier.Close()
	}

	fmt.Println("DNS server stopped")
	return nil
}

// GetFirewall returns the live firewall instance, or nil if firewall is disabled in config.
func (s *Server) GetFirewall() *firewalld.Firewall {
	return s.firewall
}

// GetCache returns the recursive resolver's DNS cache, or nil if recursive is disabled.
func (s *Server) GetCache() *cache.ShardedCache {
	if s.recursive == nil {
		return nil
	}
	return s.recursive.GetCache()
}

// Prefetch forces a recursive cache refresh for an admin-requested question.
func (s *Server) Prefetch(ctx context.Context, name string, qtype, qclass uint16) error {
	if s.recursive == nil {
		return fmt.Errorf("recursive resolver is disabled")
	}
	return s.recursive.Prefetch(ctx, name, qtype, qclass)
}

// tsigSecretMap returns the TsigSecret map for dns.Server, or nil if no keys configured.
func (s *Server) tsigSecretMap() map[string]string {
	if s.tsigKeyRing == nil {
		return nil
	}
	return s.tsigKeyRing.TsigSecretMap()
}

// GetTsigKeyRing returns the server's TSIG key ring (may be nil if no keys configured).
func (s *Server) GetTsigKeyRing() *tsig.KeyRing {
	return s.tsigKeyRing
}

// GetRRL returns the rate-limit limiter (may be nil if RRL is disabled in config).
func (s *Server) GetRRL() *rrl.Limiter {
	return s.rrl
}

// GetDSYNCNotifier returns the DSYNC outbound notifier (may be nil if DSYNC is disabled).
func (s *Server) GetDSYNCNotifier() *dsync.DSYNCNotifier {
	return s.dsyncNotifier
}

// SetBus attaches an event bus for real-time query streaming.
// Must be called before Serve().
func (s *Server) SetBus(b *eventbus.Bus) {
	s.bus = b
}

// GetEventBus returns the server's event bus (may be nil if not configured).
func (s *Server) GetEventBus() *eventbus.Bus {
	return s.bus
}

// HandleDNS adapts the core DNS handler to encrypted transports. The source
// address is preserved so recursion, update, transfer, firewall, and RRL ACLs
// behave exactly as they do on port 53.
func (s *Server) HandleDNS(ctx context.Context, req *dns.Msg, remoteAddr net.Addr) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("nil DNS request")
	}
	w := &messageResponseWriter{remoteAddr: remoteAddr}
	// The encrypted transport adapters do not currently retain the original
	// TSIG wire image. Fail closed for signed operations rather than treating an
	// unverified signature as valid.
	if req.IsTsig() != nil {
		w.tsigStatus = fmt.Errorf("TSIG verification unavailable on encrypted transport")
	}
	s.handleDNS(w, req)
	if w.msg == nil {
		return nil, fmt.Errorf("DNS request produced no response")
	}
	return w.msg, nil
}

type messageResponseWriter struct {
	remoteAddr net.Addr
	msg        *dns.Msg
	tsigStatus error
}

func (w *messageResponseWriter) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (w *messageResponseWriter) RemoteAddr() net.Addr { return w.remoteAddr }
func (w *messageResponseWriter) Close() error         { return nil }
func (w *messageResponseWriter) TsigStatus() error    { return w.tsigStatus }
func (w *messageResponseWriter) TsigTimersOnly(bool)  {}
func (w *messageResponseWriter) Hijack()              {}
func (w *messageResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg.Copy()
	return nil
}
func (w *messageResponseWriter) Write(p []byte) (int, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(p); err != nil {
		return 0, err
	}
	w.msg = msg
	return len(p), nil
}

// writeMsg avoids the allocation in dns.ResponseWriter.WriteMsg for ordinary
// unsigned responses. Signed responses stay on WriteMsg so the library retains
// its TSIG MAC chaining and signing behavior.
func writeMsg(w dns.ResponseWriter, msg *dns.Msg) error {
	if _, encryptedAdapter := w.(*messageResponseWriter); encryptedAdapter || msg.IsTsig() != nil {
		return w.WriteMsg(msg)
	}
	buf := pool.GetPackBuffer(msg)
	defer pool.PutBuffer(buf)
	wire, err := msg.PackBuffer(buf)
	if err != nil {
		return err
	}
	_, err = w.Write(wire)
	return err
}

// handleDNS is the main DNS query handler
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.queries.Add(1)

	// Transport split counter
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		s.udpQueries.Add(1)
	} else {
		s.tcpQueries.Add(1)
	}

	// Get client IP
	var clientIP net.IP
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP
	}

	// RFC 9859: dispatch NOTIFY opcode before query processing.
	// This must be FIRST — before pool.GetMessage, before defensive checks.
	if r.Opcode == dns.OpcodeNotify {
		if len(r.Question) != 1 {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeFormatError
			writeMsg(w, m) //nolint:errcheck
			return
		}
		if r.Question[0].Qtype == dns.TypeSOA {
			if clientIP == nil || r.Question[0].Qclass != dns.ClassINET {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Rcode = dns.RcodeRefused
				writeMsg(w, m) //nolint:errcheck
				return
			}
			if r.IsTsig() != nil && w.TsigStatus() != nil {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Rcode = dns.RcodeNotAuth
				writeMsg(w, m) //nolint:errcheck
				return
			}
			var tsigName string
			if requestTSIG := r.IsTsig(); requestTSIG != nil {
				tsigName = requestTSIG.Hdr.Name
			}
			s.soaNotifyMu.RLock()
			handler := s.soaNotifyHandler
			s.soaNotifyMu.RUnlock()

			m := new(dns.Msg)
			m.SetReply(r)
			if requestTSIG := r.IsTsig(); requestTSIG != nil {
				m.SetTsig(requestTSIG.Hdr.Name, requestTSIG.Algorithm, requestTSIG.Fudge, time.Now().Unix())
			}
			if handler == nil {
				m.Rcode = dns.RcodeNotImplemented
			} else if err := handler.HandleNotify(s.ctx, r.Question[0].Name, clientIP, tsigName); err != nil {
				m.Rcode = dns.RcodeRefused
			}
			writeMsg(w, m) //nolint:errcheck
			return
		}
		// RFC 9859 DSYNC notifications use CDS or CSYNC.
		if r.Question[0].Qtype != dns.TypeCDS && r.Question[0].Qtype != dns.TypeCSYNC {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeNotImplemented
			writeMsg(w, m) //nolint:errcheck
			return
		}
		// Guard against unknown transport types that leave clientIP nil.
		// An unknown address type cannot be rate-limited or ACL-checked safely.
		if clientIP == nil {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeRefused
			writeMsg(w, m) //nolint:errcheck
			return
		}
		if s.dsyncHandler != nil {
			s.dsyncHandler.HandleInbound(w, r, clientIP)
		} else {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeNotImplemented
			writeMsg(w, m) //nolint:errcheck
		}
		return
	}

	// RFC 5936/1995: dispatch AXFR and IXFR before pool.GetMessage() — zone
	// transfers stream multiple messages and must NOT use the pooled
	// single-response path.  Both types are routed through handleAXFR so they
	// receive the same TSIG-presence, TSIG-validity, and ACL guard chain.
	// (IXFR without incremental state falls back to a full AXFR response, which
	// handleAXFR already produces.)
	if len(r.Question) > 0 &&
		(r.Question[0].Qtype == dns.TypeAXFR || r.Question[0].Qtype == dns.TypeIXFR) {
		if clientIP == nil {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeRefused
			writeMsg(w, m) //nolint:errcheck
			return
		}
		s.handleAXFR(w, r, clientIP)
		return
	}

	// RFC 2136: dispatch UPDATE opcode before pool.GetMessage() — UPDATE modifies
	// zones and must NOT use the pooled single-response path.
	if r.Opcode == dns.OpcodeUpdate {
		if clientIP == nil {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeRefused
			writeMsg(w, m) //nolint:errcheck
			return
		}
		s.handleUpdate(w, r, clientIP)
		return
	}

	// Set up query event emission. emitQuery publishes a QueryEvent to the bus
	// (no-op when bus is nil). Called before each response write in the normal path.
	queryStart := time.Now()
	queryProto := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		queryProto = "tcp"
	}
	queryDomain := ""
	queryQType := ""
	if len(r.Question) > 0 {
		queryDomain = r.Question[0].Name
		queryQType = dns.TypeToString[r.Question[0].Qtype]
	}
	emitQuery := func(rcode int, zoneName string) {
		if s.bus == nil {
			return
		}
		prefix := ""
		if clientIP != nil {
			octets := strings.Split(clientIP.String(), ".")
			if len(octets) >= 3 {
				prefix = strings.Join(octets[:3], ".") + ".0"
			} else {
				prefix = clientIP.String()
			}
		}
		s.bus.Publish(s.ctx, eventbus.TopicQuery, eventbus.QueryEvent{
			Domain:       queryDomain,
			QType:        queryQType,
			Verdict:      dns.RcodeToString[rcode],
			Zone:         zoneName,
			ClientPrefix: prefix,
			Protocol:     queryProto,
			LatencyUs:    time.Since(queryStart).Microseconds(),
			Timestamp:    time.Now().UnixNano(),
		})
	}

	// Check blackhole/ACL first
	if s.defensive != nil {
		if block, action := s.defensive.CheckBlackhole(clientIP); block {
			if action == "drop" {
				// Silent drop - no response
				return
			} else if action == "refused" {
				// Send REFUSED response
				m := pool.GetMessage()
				defer pool.PutMessage(m)
				m.SetReply(r)
				m.Rcode = dns.RcodeRefused
				emitQuery(m.Rcode, "")
				writeMsg(w, m)
				return
			}
		}
	}

	// Apply adaptive admission before allocating a pooled response or running
	// policy/authoritative/recursive work. Control-plane opcodes are dispatched
	// above and retain their dedicated authentication and rate limits.
	if s.reputation != nil && !s.reputation.Allow(clientIP, time.Now()) {
		if s.reputation.Action() == "refused" {
			m := pool.GetMessage()
			defer pool.PutMessage(m)
			m.SetReply(r)
			m.Rcode = dns.RcodeRefused
			s.errors.Add(1)
			emitQuery(m.Rcode, "")
			writeMsg(w, m) //nolint:errcheck
		}
		return
	}

	// Create response message
	m := pool.GetMessage()
	defer pool.PutMessage(m)

	m.SetReply(r)
	recursionAllowed := s.cfg.EnableRecursive && s.recursionACL != nil && clientIP != nil && s.recursionACL.IsAllowed(clientIP)
	m.RecursionAvailable = recursionAllowed

	// Apply compression controls
	if s.defensive != nil {
		s.defensive.ApplyCompression(m)
	} else {
		m.Compress = true
	}

	// Validate query
	if len(r.Question) != 1 {
		s.observeClient(clientIP, reputation.SignalProtocol)
		m.Rcode = dns.RcodeFormatError
		s.errors.Add(1)
		emitQuery(m.Rcode, "")
		writeMsg(w, m)
		return
	}
	if r.Opcode != dns.OpcodeQuery {
		s.observeClient(clientIP, reputation.SignalProtocol)
		m.Rcode = dns.RcodeNotImplemented
		s.errors.Add(1)
		emitQuery(m.Rcode, "")
		writeMsg(w, m) //nolint:errcheck
		return
	}
	if r.Question[0].Qclass != dns.ClassINET {
		s.observeClient(clientIP, reputation.SignalProtocol)
		m.Rcode = dns.RcodeRefused
		s.errors.Add(1)
		emitQuery(m.Rcode, "")
		writeMsg(w, m) //nolint:errcheck
		return
	}

	// RFC 6891 §6.1.3: this server only implements EDNS version 0. A request
	// that advertises a higher EDNS VERSION in its OPT record MUST be answered
	// with RCODE BADVERS and an OPT RR advertising our supported version (0),
	// with no answer/authority/additional data beyond that OPT.
	if reqOpt := r.IsEdns0(); reqOpt != nil && reqOpt.Version() > 0 {
		s.observeClient(clientIP, reputation.SignalProtocol)
		m.Rcode = dns.RcodeBadVers
		respOpt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  4096,
			},
		}
		respOpt.SetVersion(0)
		m.Extra = append(m.Extra, respOpt)
		s.errors.Add(1)
		emitQuery(m.Rcode, "")
		writeMsg(w, m)
		return
	}

	question := r.Question[0]
	if s.cfg.QueryComplexity.Enabled &&
		queryComplexityScore(r, s.cfg.QueryComplexity) > s.cfg.QueryComplexity.MaxScore {
		s.observeClient(clientIP, reputation.SignalComplexity)
		m.Rcode = dns.RcodeRefused
		s.errors.Add(1)
		s.complexityRejected.Add(1)
		queryComplexityRejectedTotal.Inc()
		emitQuery(m.Rcode, "")
		writeMsg(w, m) //nolint:errcheck
		return
	}

	// Log query if enabled
	if s.defensive != nil {
		s.defensive.LogQuery("queries", clientIP, question.Name, question.Qtype, dns.RcodeSuccess)
	}

	// Check Protective DNS (malicious domain blocking)
	if s.protective != nil {
		result, err := s.protective.CheckQuery(question.Name, clientIP)
		if err == nil && result.Blocked {
			s.observeClient(clientIP, reputation.SignalPolicy)
			// Domain is blocked - rewrite response
			blockedResp := s.protective.RewriteResponse(r, result)

			// Check RRL before sending
			if s.shouldRateLimit(blockedResp, clientIP) {
				// Drop or slip
				return
			}

			s.answers.Add(1)
			if blockedResp.Rcode == dns.RcodeNameError {
				s.nxdomain.Add(1)
			}

			emitQuery(blockedResp.Rcode, "")
			writeMsg(w, blockedResp)
			return
		}
	}

	// Check DNS Firewall
	if s.firewall != nil {
		d := s.firewall.Check(r, clientIP)
		switch d.Verdict {
		case firewalld.VerdictDrop:
			s.observeClient(clientIP, reputation.SignalPolicy)
			return
		case firewalld.VerdictNXDomain, firewalld.VerdictRewrite:
			s.observeClient(clientIP, reputation.SignalPolicy)
			resp := s.firewall.Apply(r, d)
			if resp != nil {
				if s.shouldRateLimit(resp, clientIP) {
					return
				}
				s.answers.Add(1)
				if resp.Rcode == dns.RcodeNameError {
					s.nxdomain.Add(1)
				}
				emitQuery(resp.Rcode, "")
				writeMsg(w, resp)
				return
			}
		case firewalld.VerdictRedirect:
			s.observeClient(clientIP, reputation.SignalPolicy)
			resp := s.firewall.Redirect(r, d)
			if s.shouldRateLimit(resp, clientIP) {
				return
			}
			s.answers.Add(1)
			if resp.Rcode == dns.RcodeNameError {
				s.nxdomain.Add(1)
			}
			emitQuery(resp.Rcode, "")
			writeMsg(w, resp)
			return
		}
	}

	if matched, drop, rule := s.applyRPZ(r, m); matched {
		s.observeClient(clientIP, reputation.SignalPolicy)
		if drop {
			return
		}
		if s.shouldRateLimit(m, clientIP) {
			return
		}
		s.answers.Add(1)
		if m.Rcode == dns.RcodeNameError {
			s.nxdomain.Add(1)
		}
		emitQuery(m.Rcode, rule.Zone)
		writeMsg(w, m) //nolint:errcheck
		return
	}

	var responseClientCookie [8]byte
	var responseServerCookie [16]byte
	haveResponseCookie := false

	// Check DNS cookies if enabled
	if s.cfg.EnableCookies && s.cookies != nil {
		// Extract cookies from request
		var clientCookie [8]byte
		// Server cookie is the 16-byte RFC 9018 layout (version+reserved+
		// timestamp+hash); a full client-supplied cookie is 8+16 = 24 bytes.
		var serverCookie [16]byte

		opt := r.IsEdns0()
		if opt != nil {
			for _, option := range opt.Option {
				if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
					decoded, err := hex.DecodeString(cookie.Cookie)
					if err != nil {
						break
					}
					if len(decoded) >= 8 {
						copy(clientCookie[:], decoded[:8])
					}
					if len(decoded) >= 24 {
						copy(serverCookie[:], decoded[8:24])
					}
					break
				}
			}
		}

		// Validate if we have a server cookie
		valid := false
		hasServerCookie := serverCookie != [16]byte{}
		if hasServerCookie {
			valid = s.cookies.ValidateServerCookie(clientCookie, serverCookie, clientIP) == nil
		}

		// Apply defensive cookie policy
		cookieValid := true
		if s.defensive != nil {
			cookieValid = s.defensive.ValidateCookie(hasServerCookie, valid)
		} else if !valid && s.cfg.CookieConfig.RequireValid && hasServerCookie {
			cookieValid = false
		}

		if !cookieValid {
			// Send BADCOOKIE response
			m.Rcode = dns.RcodeBadCookie

			// Generate new server cookie
			newServerCookie, _ := s.cookies.GenerateServerCookie(clientCookie, clientIP)
			s.addCookieToResponse(m, clientCookie, newServerCookie)

			s.errors.Add(1)
			emitQuery(m.Rcode, "")
			writeMsg(w, m)
			return
		}

		// Save the successful response cookie. It is attached to the actual
		// authoritative or recursive response below, rather than the base message
		// whose Extra section may be replaced during dispatch.
		if clientCookie != [8]byte{} {
			newServerCookie, _ := s.cookies.GenerateServerCookie(clientCookie, clientIP)
			responseClientCookie = clientCookie
			responseServerCookie = newServerCookie
			haveResponseCookie = true
		}
	}

	// Try authoritative first
	if s.cfg.EnableAuthoritative {
		if resp, ok := s.handleAuthoritative(r, clientIP); ok {
			// Check RRL before sending
			if s.shouldRateLimit(resp, clientIP) {
				// Drop or slip
				return
			}

			s.answers.Add(1)
			if resp.Rcode == dns.RcodeNameError {
				s.nxdomain.Add(1)
			}

			// Copy to response
			m.Answer = resp.Answer
			m.Ns = resp.Ns
			m.Extra = resp.Extra
			if haveResponseCookie {
				s.addCookieToResponse(m, responseClientCookie, responseServerCookie)
			}
			m.Rcode = resp.Rcode
			m.Authoritative = resp.Authoritative
			// RFC 1034 §4.3.1: authoritative servers MUST NOT set RA.
			// The base message has RA set from the initial RecursionAvailable assignment;
			// clear it here so authoritative responses are strictly conformant.
			m.RecursionAvailable = false

			// Apply defensive features to response
			if s.defensive != nil {
				// Order RRsets
				m.Answer = s.defensive.OrderRRset(m.Answer)

				// Apply EDNS controls
				s.defensive.ApplyEDNSControls(m, r)

				// Log response
				s.defensive.LogQuery("responses", clientIP, question.Name, question.Qtype, m.Rcode)
			}

			emitQuery(m.Rcode, "")
			writeMsg(w, m)
			return
		}
	}

	// Try recursive
	if s.cfg.EnableRecursive && s.recursive != nil {
		// RFC 1034 section 4.3.1: recursion is performed only when RD is set.
		// Recursion is additionally restricted to the configured client ACL so
		// binding :53 on a public interface cannot create an open resolver.
		if !r.RecursionDesired || !recursionAllowed {
			m.Rcode = dns.RcodeRefused
			s.errors.Add(1)
			emitQuery(m.Rcode, "")
			writeMsg(w, m) //nolint:errcheck
			return
		}
		resp, err := s.recursive.Resolve(s.ctx, r, clientIP)
		if err != nil {
			m.Rcode = dns.RcodeServerFailure
			s.errors.Add(1)

			// Log error if enabled
			if s.defensive != nil {
				s.defensive.LogQuery("errors", clientIP, question.Name, question.Qtype, dns.RcodeServerFailure)
			}

			emitQuery(m.Rcode, "")
			writeMsg(w, m)
			return
		}

		// Check RRL before sending
		if s.shouldRateLimit(resp, clientIP) {
			// Drop or slip
			return
		}

		s.answers.Add(1)
		if resp.Rcode == dns.RcodeNameError {
			s.nxdomain.Add(1)
		}

		// Apply defensive features to recursive response
		if s.defensive != nil {
			// Order RRsets
			resp.Answer = s.defensive.OrderRRset(resp.Answer)

			// Apply EDNS controls
			s.defensive.ApplyEDNSControls(resp, r)

			// Log response
			s.defensive.LogQuery("responses", clientIP, question.Name, question.Qtype, resp.Rcode)
		}
		if haveResponseCookie {
			s.addCookieToResponse(resp, responseClientCookie, responseServerCookie)
		}

		emitQuery(resp.Rcode, "")
		writeMsg(w, resp)
		return
	}

	// No handlers available
	m.Rcode = dns.RcodeRefused
	s.errors.Add(1)
	emitQuery(m.Rcode, "")
	writeMsg(w, m)
}

// handleAuthoritative checks authoritative zones
func (s *Server) handleAuthoritative(r *dns.Msg, clientIP net.IP) (*dns.Msg, bool) {
	if len(r.Question) == 0 {
		return nil, false
	}

	question := r.Question[0]
	qname := question.Name
	qtype := question.Qtype

	// Find matching zone (RLock protects concurrent map read, CR-01)
	var matchedZone *zone.Zone
	matchedName := ""

	s.zonesMu.RLock()
	for zoneName, z := range s.cfg.Zones {
		if dns.IsSubDomain(zoneName, qname) {
			if len(zoneName) > len(matchedName) {
				matchedZone = z
				matchedName = zoneName
			}
		}
	}
	s.zonesMu.RUnlock()

	if matchedZone == nil {
		return nil, false
	}

	// Build response. This message escapes the function, so it must not come
	// from the shared pool unless ownership is explicitly returned by the caller.
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false
	if qtype == dns.TypeANY {
		m.Answer = []dns.RR{&dns.HINFO{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 0},
			Cpu: "RFC8482",
			Os:  "",
		}}
		return m, true
	}

	// A delegation NS RRset below the apex creates a zone cut. Answer DS at the
	// cut from the parent zone; all other names/types at or below it are referrals.
	if cut, nsRecords := matchedZone.FindDelegation(qname); cut != "" &&
		!(strings.EqualFold(qname, cut) && qtype == dns.TypeDS) {
		m.Authoritative = false
		m.Ns = append(m.Ns, nsRecords...)
		for _, rr := range nsRecords {
			ns, ok := rr.(*dns.NS)
			if !ok || !dns.IsSubDomain(matchedZone.Origin, ns.Ns) {
				continue
			}
			m.Extra = append(m.Extra, matchedZone.ExactRecords(ns.Ns, dns.TypeA)...)
			m.Extra = append(m.Extra, matchedZone.ExactRecords(ns.Ns, dns.TypeAAAA)...)
		}
		return m, true
	}

	// Get records
	records := matchedZone.GetRecords(qname, qtype)

	// RFC 1034 §3.6.2: a CNAME record must be returned for a query of ANY
	// type at that owner name, since the name is an alias. Without this,
	// queries for A/AAAA/etc. at a CNAME-only name incorrectly return NODATA
	// instead of the CNAME, breaking resolution for any client that doesn't
	// query the exact CNAME type (i.e. every real-world client).
	if len(records) == 0 && qtype != dns.TypeCNAME {
		if cnameRecords := matchedZone.GetRecords(qname, dns.TypeCNAME); len(cnameRecords) > 0 {
			records = cnameRecords
		}
	}

	if len(records) > 0 {
		m.Answer = records
	} else {
		// NODATA: name exists but no records of this type → NOERROR + empty answer
		// NXDOMAIN: name does not exist in the zone → RcodeNameError
		if matchedZone.HasName(qname) {
			m.Rcode = dns.RcodeSuccess
		} else {
			m.Rcode = dns.RcodeNameError
		}
		// Add SOA in authority for both NXDOMAIN and NODATA (RFC 2308)
		if matchedZone.SOA != nil {
			m.Ns = []dns.RR{matchedZone.SOA}
		}
	}

	return m, true
}

// shouldRateLimit checks if response should be rate limited
func (s *Server) shouldRateLimit(m *dns.Msg, clientIP net.IP) bool {
	if !s.cfg.EnableRRL || s.rrl == nil {
		return false
	}

	if len(m.Question) == 0 {
		return false
	}

	question := m.Question[0]
	category := rrl.CategorizeResponse(m.Rcode, len(m.Answer), len(m.Ns))

	action := s.rrl.Check(clientIP, question.Name, question.Qtype, category)

	switch action {
	case rrl.ActionDrop:
		s.observeClient(clientIP, reputation.SignalRateLimited)
		return true // Drop response

	case rrl.ActionSlip:
		s.observeClient(clientIP, reputation.SignalRateLimited)
		// Send truncated response (TC bit set)
		m.Truncated = true
		m.Answer = nil
		m.Ns = nil
		m.Extra = nil
		return false // Send TC response

	default:
		return false // Allow
	}
}

func (s *Server) observeClient(clientIP net.IP, signal reputation.Signal) {
	if s.reputation != nil {
		s.reputation.Observe(clientIP, signal, time.Now())
	}
}

// Stats returns server statistics
type Stats struct {
	Queries  uint64
	Answers  uint64
	Errors   uint64
	NXDOMAIN uint64

	// Transport-level counters
	UDPQueries         uint64
	TCPQueries         uint64
	ComplexityRejected uint64

	ClientReputation reputation.Stats
	TCPConnections   transport.TCPConnectionStats
	XoTConnections   transport.TCPConnectionStats

	Recursive     *resolver.Stats
	RRL           *rrl.Stats
	PrimaryNotify *primarynotify.Stats
}

// GetStats returns current statistics
func (s *Server) GetStats() Stats {
	stats := Stats{
		Queries:            s.queries.Load(),
		Answers:            s.answers.Load(),
		Errors:             s.errors.Load(),
		NXDOMAIN:           s.nxdomain.Load(),
		UDPQueries:         s.udpQueries.Load(),
		TCPQueries:         s.tcpQueries.Load(),
		ComplexityRejected: s.complexityRejected.Load(),
	}
	if s.reputation != nil {
		stats.ClientReputation = s.reputation.Stats()
	}
	if s.tcpLimiter != nil {
		stats.TCPConnections = s.tcpLimiter.Stats()
	}
	if s.xotLimiter != nil {
		stats.XoTConnections = s.xotLimiter.Stats()
	}

	if s.recursive != nil {
		resolverStats := s.recursive.GetStats()
		stats.Recursive = &resolverStats
	}

	if s.rrl != nil {
		rrlStats := s.rrl.GetStats()
		stats.RRL = &rrlStats
	}
	if s.primaryNotifier != nil {
		notifyStats := s.primaryNotifier.Stats()
		stats.PrimaryNotify = &notifyStats
	}

	return stats
}

// LoadZone loads a zone from file
func (s *Server) LoadZone(filename, format string) error {
	var z *zone.Zone
	var err error

	cfg := zone.DefaultConfig()

	switch format {
	case "dnszone", "yaml":
		z, err = zone.ParseDNSZone(filename, cfg)
	case "bind", "rfc1035":
		// Extract origin from filename or require it?
		// For now, extract from zone name in file
		z, err = zone.ParseBIND(filename, "", cfg)
	default:
		return fmt.Errorf("unknown zone format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("parse zone %s: %w", filename, err)
	}

	if err := s.AddZone(z); err != nil {
		return err
	}

	fmt.Printf("Loaded zone: %s (%d records)\n", z.Name, z.GetStats().Records)

	return nil
}

// AddZone adds a zone to the server
func (s *Server) AddZone(z *zone.Zone) error {
	if z == nil {
		return fmt.Errorf("zone is nil")
	}

	if err := z.Validate(); err != nil {
		return fmt.Errorf("zone validation failed: %w", err)
	}

	s.persistMu.Lock()
	s.zonesMu.RLock()
	previous := s.cfg.Zones[z.Origin]
	s.zonesMu.RUnlock()
	if previous == nil {
		s.ixfrJournal.Reset(z.Origin)
	} else {
		s.ixfrJournal.Record(previous, z)
	}
	s.zonesMu.Lock()
	s.cfg.Zones[z.Origin] = z
	s.zonesMu.Unlock()
	s.persistMu.Unlock()
	if s.primaryNotifier != nil {
		_ = s.primaryNotifier.Notify(z.Origin, z.SOA)
	}
	return nil
}

// ApplyZoneBatch validates every replacement before atomically swapping the
// authoritative zone map. Readers observe either the complete old fleet or the
// complete new fleet.
func (s *Server) ApplyZoneBatch(upserts []*zone.Zone, removals []string) error {
	seen := make(map[string]struct{}, len(upserts))
	for _, z := range upserts {
		if z == nil {
			return fmt.Errorf("zone batch contains nil zone")
		}
		if err := z.Validate(); err != nil {
			return fmt.Errorf("zone %s validation failed: %w", z.Origin, err)
		}
		name := strings.ToLower(dns.Fqdn(z.Origin))
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("zone batch contains duplicate %s", name)
		}
		seen[name] = struct{}{}
	}
	normalizedRemovals := make([]string, 0, len(removals))
	removedSet := make(map[string]struct{}, len(removals))
	for _, removed := range removals {
		name := strings.ToLower(dns.Fqdn(removed))
		if _, duplicate := removedSet[name]; duplicate {
			continue
		}
		if _, replaced := seen[name]; replaced {
			return fmt.Errorf("zone batch both removes and replaces %s", name)
		}
		removedSet[name] = struct{}{}
		normalizedRemovals = append(normalizedRemovals, name)
	}

	s.persistMu.Lock()
	s.zonesMu.Lock()
	next := make(map[string]*zone.Zone, len(s.cfg.Zones)+len(upserts))
	for name, existing := range s.cfg.Zones {
		next[name] = existing
	}
	for _, name := range normalizedRemovals {
		delete(next, name)
		s.ixfrJournal.Reset(name)
	}
	for _, replacement := range upserts {
		name := strings.ToLower(dns.Fqdn(replacement.Origin))
		if previous := s.cfg.Zones[name]; previous == nil {
			s.ixfrJournal.Reset(name)
		} else {
			s.ixfrJournal.Record(previous, replacement)
		}
		next[name] = replacement
	}
	s.cfg.Zones = next
	s.zonesMu.Unlock()
	s.persistMu.Unlock()

	if s.primaryNotifier != nil {
		for _, replacement := range upserts {
			_ = s.primaryNotifier.Notify(replacement.Origin, replacement.SOA)
		}
	}
	return nil
}

// RemoveZone removes a zone from the server
func (s *Server) RemoveZone(origin string) {
	origin = strings.ToLower(dns.Fqdn(origin))
	s.persistMu.Lock()
	s.zonesMu.Lock()
	delete(s.cfg.Zones, origin)
	s.zonesMu.Unlock()
	s.ixfrJournal.Reset(origin)
	s.persistMu.Unlock()
}

// GetZone returns a zone by origin
func (s *Server) GetZone(origin string) *zone.Zone {
	s.zonesMu.RLock()
	z := s.cfg.Zones[origin]
	s.zonesMu.RUnlock()
	return z
}

// GetZoneNames returns the origin strings for all configured zones.
func (s *Server) GetZoneNames() []string {
	s.zonesMu.RLock()
	defer s.zonesMu.RUnlock()
	names := make([]string, 0, len(s.cfg.Zones))
	for origin := range s.cfg.Zones {
		names = append(names, origin)
	}
	return names
}

// EnableAuthoritative enables authoritative mode
func (s *Server) EnableAuthoritative() {
	s.cfg.EnableAuthoritative = true
}

// DisableAuthoritative disables authoritative mode
func (s *Server) DisableAuthoritative() {
	s.cfg.EnableAuthoritative = false
}

// addCookieToResponse adds DNS cookie to response
func (s *Server) addCookieToResponse(m *dns.Msg, clientCookie [8]byte, serverCookie [16]byte) {
	opt := m.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  4096,
			},
		}
		m.Extra = append(m.Extra, opt)
	}

	// Combine client (8) and server (16) cookies → 24-byte on-wire cookie.
	fullCookie := make([]byte, 24)
	copy(fullCookie[0:8], clientCookie[:])
	copy(fullCookie[8:24], serverCookie[:])

	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: hex.EncodeToString(fullCookie),
	})
}
