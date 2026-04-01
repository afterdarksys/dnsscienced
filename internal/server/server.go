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
	"github.com/dnsscience/dnsscienced/internal/experimental"
	"github.com/dnsscience/dnsscienced/internal/pool"
	"github.com/dnsscience/dnsscienced/internal/resolver"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
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

	// Experimental IETF draft protocols
	Experimental experimental.Config `yaml:"experimental"`

	// Performance tuning
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"` // TCP only

	// UDP buffer sizes
	UDPReadBuffer  int `yaml:"udp_read_buffer"`
	UDPWriteBuffer int `yaml:"udp_write_buffer"`
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
	recursive *resolver.Recursive
	cookies   *cookie.Manager
	rrl       *rrl.Limiter

	// DNS servers (one per listener for SO_REUSEPORT)
	udpServers []*dns.Server
	tcpServer  *dns.Server

	// Statistics
	queries  atomic.Uint64
	answers  atomic.Uint64
	errors   atomic.Uint64
	nxdomain atomic.Uint64

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

	// Initialize RRL if enabled
	if cfg.EnableRRL {
		s.rrl = rrl.NewLimiter(cfg.RRLConfig)
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

			UDPSize: 4096,
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

	fmt.Println("DNS server stopped")
	return nil
}

// handleDNS is the main DNS query handler
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.queries.Add(1)

	// Get client IP
	var clientIP net.IP
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP
	}

	// Create response message
	m := pool.GetMessage()
	defer pool.PutMessage(m)

	m.SetReply(r)
	m.Compress = true
	m.RecursionAvailable = s.cfg.EnableRecursive

	// Validate query
	if len(r.Question) == 0 {
		m.Rcode = dns.RcodeFormatError
		s.errors.Add(1)
		w.WriteMsg(m)
		return
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
		if serverCookie != [8]byte{} {
			valid = s.cookies.ValidateServerCookie(clientCookie, serverCookie, clientIP) == nil
		}

		if !valid && s.cfg.CookieConfig.RequireValid && serverCookie != [8]byte{} {
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
		// Check for NXDOMAIN or NODATA
		// For now, just return NXDOMAIN
		m.Rcode = dns.RcodeNameError

		// Add SOA for negative response
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

	Recursive *resolver.Stats
	RRL       *rrl.Stats
}

// GetStats returns current statistics
func (s *Server) GetStats() Stats {
	stats := Stats{
		Queries:  s.queries.Load(),
		Answers:  s.answers.Load(),
		Errors:   s.errors.Load(),
		NXDOMAIN: s.nxdomain.Load(),
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
