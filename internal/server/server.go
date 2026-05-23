package server

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/cookie"
	"github.com/dnsscience/dnsscienced/internal/defensive"
	"github.com/dnsscience/dnsscienced/internal/dsync"
	"github.com/dnsscience/dnsscienced/internal/experimental"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
	"github.com/dnsscience/dnsscienced/internal/pool"
	"github.com/dnsscience/dnsscienced/internal/protective"
	"github.com/dnsscience/dnsscienced/internal/resolver"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/tsig"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// Config holds DNS server configuration
type Config struct {
	// Listen addresses
	UDPAddr string `yaml:"udp_addr"`
	TCPAddr string `yaml:"tcp_addr"`

	// Number of UDP listeners (SO_REUSEPORT)
	// Set to runtime.NumCPU() for maximum performance
	UDPListeners int `yaml:"udp_listeners"`

	// Enable recursive resolver
	EnableRecursive bool            `yaml:"enable_recursive"`
	RecursiveConfig resolver.Config `yaml:"recursive"`

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

	// Experimental IETF draft protocols
	Experimental experimental.Config `yaml:"experimental"`

	// TSIG keys for authenticated transfers/updates (set by main.go from config.TsigKeys).
	// Populated externally after config load — not decoded from server yaml section directly.
	// Conversion from config.TsigKeyConfig to tsig.KeyConfig happens at config load time.
	TsigKeys []tsig.KeyConfig `yaml:"-"`

	// ZoneTransferCIDRs maps zone FQDN origin to CIDR strings allowed to AXFR.
	// Populated by main.go from config.ZoneConfig.AllowTransfer.
	// Empty/absent = deny all (D-01).
	ZoneTransferCIDRs map[string][]string `yaml:"-"`

	// DSYNC configures inbound RFC 9859 NOTIFY(CDS/CSYNC) handling.
	DSYNC DSYNCConfig `yaml:"dsync"`

	// Performance tuning
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"` // TCP only

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
	return Config{
		UDPAddr:      ":53",
		TCPAddr:      ":53",
		UDPListeners: runtime.NumCPU(),

		EnableRecursive: true,
		RecursiveConfig: resolver.Config{
			CacheConfig: cache.Config{
				ShardCount: 256,
				MaxEntries: 100000,
			},
			Workers:       1000,
			QueryTimeout:  5 * time.Second,
			MaxIterations: 20,
		},

		EnableAuthoritative: false,
		Zones:               make(map[string]*zone.Zone),

		EnableCookies: true,
		CookieConfig: cookie.Config{
			Enabled: true,
		},

		EnableRRL: true,
		RRLConfig: rrl.DefaultConfig(),

		Experimental: experimental.DefaultConfig(),

		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,

		UDPReadBuffer:  8 * 1024 * 1024, // 8MB
		UDPWriteBuffer: 8 * 1024 * 1024, // 8MB
	}
}

// Server is the main DNS server
type Server struct {
	cfg Config

	// Components
	recursive    *resolver.Recursive
	cookies      *cookie.Manager
	rrl          *rrl.Limiter
	defensive    *defensive.Manager
	protective   *protective.Engine
	firewall     *firewalld.Firewall
	tsigKeyRing      *tsig.KeyRing
	dsyncHandler     *dsync.Handler
	dsyncNotifier    *dsync.DSYNCNotifier
	zoneTransferACLs map[string]*dsync.SourceACL // Per-zone transfer ACLs. nil entry = deny all (D-01).

	// DNS servers (one per listener for SO_REUSEPORT)
	udpServers []*dns.Server
	tcpServer  *dns.Server

	// Statistics
	queries  atomic.Uint64
	answers  atomic.Uint64
	errors   atomic.Uint64
	nxdomain atomic.Uint64

	// Transport-level counters
	udpQueries atomic.Uint64
	tcpQueries atomic.Uint64

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new DNS server
func New(cfg Config) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize recursive resolver if enabled
	if cfg.EnableRecursive {
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
	s.zoneTransferACLs = make(map[string]*dsync.SourceACL)
	for zoneName, cidrs := range cfg.ZoneTransferCIDRs {
		if len(cidrs) == 0 {
			s.zoneTransferACLs[zoneName] = nil
			continue
		}
		acl, err := dsync.NewSourceACL(cidrs)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("zone %s allow_transfer: %w", zoneName, err)
		}
		s.zoneTransferACLs[zoneName] = acl
	}

	// Create UDP servers (SO_REUSEPORT)
	for i := 0; i < cfg.UDPListeners; i++ {
		udpServer := &dns.Server{
			Addr:      cfg.UDPAddr,
			Net:       "udp",
			ReusePort: true, // SO_REUSEPORT magic!
			Handler:   dns.HandlerFunc(s.handleDNS),

			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,

			UDPSize:    4096,
			TsigSecret: s.tsigSecretMap(), // populate for automatic TSIG verification
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
		TsigSecret:   s.tsigSecretMap(), // populate for automatic TSIG verification
	}

	return s, nil
}

// Start starts all DNS listeners
func (s *Server) Start() error {
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

	// Start TCP listener
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		fmt.Printf("TCP listener started on %s\n", s.cfg.TCPAddr)

		if err := s.tcpServer.ListenAndServe(); err != nil {
			fmt.Printf("TCP listener error: %v\n", err)
		}
	}()

	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	fmt.Println("Shutting down DNS server...")

	// Cancel context
	s.cancel()

	// Shutdown all UDP servers
	for i, udpServer := range s.udpServers {
		if err := udpServer.Shutdown(); err != nil {
			fmt.Printf("Error shutting down UDP listener %d: %v\n", i, err)
		}
	}

	// Shutdown TCP server
	if err := s.tcpServer.Shutdown(); err != nil {
		fmt.Printf("Error shutting down TCP listener: %v\n", err)
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
		// Guard against unknown transport types that leave clientIP nil.
		// An unknown address type cannot be rate-limited or ACL-checked safely.
		if clientIP == nil {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m) //nolint:errcheck
			return
		}
		if s.dsyncHandler != nil {
			s.dsyncHandler.HandleInbound(w, r, clientIP)
		} else {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeNotImplemented
			w.WriteMsg(m) //nolint:errcheck
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
			w.WriteMsg(m) //nolint:errcheck
			return
		}
		s.handleAXFR(w, r, clientIP)
		return
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
				w.WriteMsg(m)
				return
			}
		}
	}

	// Create response message
	m := pool.GetMessage()
	defer pool.PutMessage(m)

	m.SetReply(r)
	m.RecursionAvailable = s.cfg.EnableRecursive

	// Apply compression controls
	if s.defensive != nil {
		s.defensive.ApplyCompression(m)
	} else {
		m.Compress = true
	}

	// Validate query
	if len(r.Question) == 0 {
		m.Rcode = dns.RcodeFormatError
		s.errors.Add(1)
		w.WriteMsg(m)
		return
	}

	question := r.Question[0]

	// Log query if enabled
	if s.defensive != nil {
		s.defensive.LogQuery("queries", clientIP, question.Name, question.Qtype, dns.RcodeSuccess)
	}

	// Check Protective DNS (malicious domain blocking)
	if s.protective != nil {
		result, err := s.protective.CheckQuery(question.Name, clientIP)
		if err == nil && result.Blocked {
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

			w.WriteMsg(blockedResp)
			return
		}
	}

	// Check DNS Firewall
	if s.firewall != nil {
		d := s.firewall.Check(r, clientIP)
		switch d.Verdict {
		case firewalld.VerdictDrop:
			return
		case firewalld.VerdictNXDomain, firewalld.VerdictRewrite:
			resp := s.firewall.Apply(r, d)
			if resp != nil {
				if s.shouldRateLimit(resp, clientIP) {
					return
				}
				s.answers.Add(1)
				if resp.Rcode == dns.RcodeNameError {
					s.nxdomain.Add(1)
				}
				w.WriteMsg(resp)
				return
			}
		case firewalld.VerdictRedirect:
			resp := s.firewall.Redirect(r, d)
			if s.shouldRateLimit(resp, clientIP) {
				return
			}
			s.answers.Add(1)
			if resp.Rcode == dns.RcodeNameError {
				s.nxdomain.Add(1)
			}
			w.WriteMsg(resp)
			return
		}
	}

	// Check DNS cookies if enabled
	if s.cfg.EnableCookies && s.cookies != nil {
		// Extract cookies from request
		var clientCookie [8]byte
		var serverCookie [8]byte

		opt := r.IsEdns0()
		if opt != nil {
			for _, option := range opt.Option {
				if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
					copy(clientCookie[:], cookie.Cookie[:8])
					if len(cookie.Cookie) >= 16 {
						copy(serverCookie[:], cookie.Cookie[8:16])
					}
					break
				}
			}
		}

		// Validate if we have a server cookie
		valid := false
		hasServerCookie := serverCookie != [8]byte{}
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
			w.WriteMsg(m)
			return
		}

		// Add cookies to response
		if clientCookie != [8]byte{} {
			newServerCookie, _ := s.cookies.GenerateServerCookie(clientCookie, clientIP)
			s.addCookieToResponse(m, clientCookie, newServerCookie)
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
			m.Rcode = resp.Rcode
			m.Authoritative = true
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

			w.WriteMsg(m)
			return
		}
	}

	// Try recursive
	if s.cfg.EnableRecursive && s.recursive != nil {
		resp, err := s.recursive.Resolve(s.ctx, r, clientIP)
		if err != nil {
			m.Rcode = dns.RcodeServerFailure
			s.errors.Add(1)

			// Log error if enabled
			if s.defensive != nil {
				s.defensive.LogQuery("errors", clientIP, question.Name, question.Qtype, dns.RcodeServerFailure)
			}

			w.WriteMsg(m)
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

		w.WriteMsg(resp)
		return
	}

	// No handlers available
	m.Rcode = dns.RcodeRefused
	s.errors.Add(1)
	w.WriteMsg(m)
}

// handleAuthoritative checks authoritative zones
func (s *Server) handleAuthoritative(r *dns.Msg, clientIP net.IP) (*dns.Msg, bool) {
	if len(r.Question) == 0 {
		return nil, false
	}

	question := r.Question[0]
	qname := question.Name
	qtype := question.Qtype

	// Find matching zone
	var matchedZone *zone.Zone
	matchedName := ""

	for zoneName, z := range s.cfg.Zones {
		if dns.IsSubDomain(zoneName, qname) {
			if len(zoneName) > len(matchedName) {
				matchedZone = z
				matchedName = zoneName
			}
		}
	}

	if matchedZone == nil {
		return nil, false
	}

	// Build response
	m := pool.GetMessage()
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	// Get records
	records := matchedZone.GetRecords(qname, qtype)

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
		return true // Drop response

	case rrl.ActionSlip:
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

// Stats returns server statistics
type Stats struct {
	Queries  uint64
	Answers  uint64
	Errors   uint64
	NXDOMAIN uint64

	// Transport-level counters
	UDPQueries uint64
	TCPQueries uint64

	Recursive *resolver.Stats
	RRL       *rrl.Stats
}

// GetStats returns current statistics
func (s *Server) GetStats() Stats {
	stats := Stats{
		Queries:    s.queries.Load(),
		Answers:    s.answers.Load(),
		Errors:     s.errors.Load(),
		NXDOMAIN:   s.nxdomain.Load(),
		UDPQueries: s.udpQueries.Load(),
		TCPQueries: s.tcpQueries.Load(),
	}

	if s.recursive != nil {
		resolverStats := s.recursive.GetStats()
		stats.Recursive = &resolverStats
	}

	if s.rrl != nil {
		rrlStats := s.rrl.GetStats()
		stats.RRL = &rrlStats
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

	// Add to server
	s.cfg.Zones[z.Origin] = z

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

	s.cfg.Zones[z.Origin] = z
	return nil
}

// RemoveZone removes a zone from the server
func (s *Server) RemoveZone(origin string) {
	delete(s.cfg.Zones, origin)
}

// GetZone returns a zone by origin
func (s *Server) GetZone(origin string) *zone.Zone {
	return s.cfg.Zones[origin]
}

// GetZoneNames returns the origin strings for all configured zones.
func (s *Server) GetZoneNames() []string {
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
func (s *Server) addCookieToResponse(m *dns.Msg, clientCookie, serverCookie [8]byte) {
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

	// Combine client and server cookies
	fullCookie := make([]byte, 16)
	copy(fullCookie[0:8], clientCookie[:])
	copy(fullCookie[8:16], serverCookie[:])

	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: string(fullCookie),
	})
}
