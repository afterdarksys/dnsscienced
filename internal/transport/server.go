package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/engine"
	"github.com/miekg/dns"
)

// ServerConfig holds configuration for the DNS server.
type ServerConfig struct {
	// UDP/TCP listeners
	UDPAddr string // UDP listen address (e.g., ":53")
	TCPAddr string // TCP listen address (e.g., ":53")

	// Resolver
	Upstream string

	// Security
	Enable0x20      bool
	EnableScrubbing bool
	EnableQNAMEMin  bool

	// MinimalResponses strips the authority and additional sections from positive
	// answers, reducing response size and eliminating additional-section injection
	// vectors. Necessary NS + glue is preserved for referrals. (NSD minimal-responses)
	MinimalResponses bool

	// TCP connection limits
	MaxTCPConnections          int           // Maximum concurrent TCP connections (default: 1000)
	MaxTCPConnectionsPerClient int           // Maximum concurrent connections per client (default: 128)
	TCPAcceptRatePerSecond     int           // Completed handshakes admitted per second (default: 10000)
	TCPAcceptBurst             int           // Completed handshake burst (default: 20000)
	MaxTCPQueriesPerConnection int           // Maximum queries before closing a TCP connection (default: 100)
	TCPReadTimeout             time.Duration // TCP read timeout (default: 5s)
	TCPWriteTimeout            time.Duration // TCP write timeout (default: 5s)
	TCPIdleTimeout             time.Duration // TCP idle timeout (default: 30s)
}

// DefaultServerConfig returns a configuration with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		UDPAddr:                    ":53",
		TCPAddr:                    ":53",
		Upstream:                   "8.8.8.8:53",
		Enable0x20:                 true,
		EnableScrubbing:            true,
		EnableQNAMEMin:             true,
		MaxTCPConnections:          1000,
		MaxTCPConnectionsPerClient: 128,
		TCPAcceptRatePerSecond:     10000,
		TCPAcceptBurst:             20000,
		MaxTCPQueriesPerConnection: 100,
		TCPReadTimeout:             5 * time.Second,
		TCPWriteTimeout:            5 * time.Second,
		TCPIdleTimeout:             30 * time.Second,
	}
}

// Server is a complete DNS server with all security features.
type Server struct {
	mu sync.Mutex

	config   ServerConfig
	resolver *engine.Resolver
	acl      *engine.ACL
	limiter  *engine.RateLimiter
	rpz      *engine.RPZAggregate

	udpServer *dns.Server
	tcpServer *dns.Server
	running   bool

	// Goroutine lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	serverWg   sync.WaitGroup
	serverErrs chan error
}

// NewServer creates a new DNS server.
func NewServer(cfg ServerConfig) *Server {
	resolverCfg := engine.ResolverConfig{
		Upstream:        cfg.Upstream,
		Enable0x20:      cfg.Enable0x20,
		EnableScrubbing: cfg.EnableScrubbing,
		EnableQNAMEMin:  cfg.EnableQNAMEMin,
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:     cfg,
		resolver:   engine.NewResolverWithConfig(resolverCfg),
		acl:        engine.NewACL(true), // Default allow
		limiter:    engine.NewRateLimiter(engine.DefaultRateLimiterConfig()),
		rpz:        engine.NewRPZAggregate(),
		ctx:        ctx,
		cancel:     cancel,
		serverErrs: make(chan error, 2), // Buffer for UDP and TCP errors
	}
}

// SetACL sets the access control list.
func (s *Server) SetACL(acl *engine.ACL) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acl = acl
}

// SetRateLimiter sets the rate limiter.
func (s *Server) SetRateLimiter(rl *engine.RateLimiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limiter = rl
}

// AddRPZ adds an RPZ zone to the server.
func (s *Server) AddRPZ(rpz *engine.RPZ) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rpz.AddZone(rpz)
}

// Start starts the DNS server on UDP and TCP.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	// Create the DNS handler
	handler := dns.HandlerFunc(s.handleDNS)

	var tcpListener net.Listener
	if s.config.TCPAddr != "" {
		protection := DefaultTCPProtectionConfig()
		if s.config.MaxTCPConnections > 0 {
			protection.MaxConnections = s.config.MaxTCPConnections
		}
		if s.config.MaxTCPConnectionsPerClient > 0 {
			protection.MaxConnectionsPerClient = s.config.MaxTCPConnectionsPerClient
		} else if protection.MaxConnectionsPerClient > protection.MaxConnections {
			protection.MaxConnectionsPerClient = protection.MaxConnections
		}
		if s.config.TCPAcceptRatePerSecond > 0 {
			protection.AcceptRatePerSecond = s.config.TCPAcceptRatePerSecond
		}
		if s.config.TCPAcceptBurst > 0 {
			protection.AcceptBurst = s.config.TCPAcceptBurst
		}
		if s.config.MaxTCPQueriesPerConnection > 0 {
			protection.MaxQueriesPerConnection = s.config.MaxTCPQueriesPerConnection
		}
		s.config.MaxTCPQueriesPerConnection = protection.MaxQueriesPerConnection
		baseListener, err := net.Listen("tcp", s.config.TCPAddr)
		if err != nil {
			return fmt.Errorf("listen TCP DNS: %w", err)
		}
		tcpListener, err = NewLimitedListener(baseListener, protection)
		if err != nil {
			_ = baseListener.Close()
			return fmt.Errorf("protect TCP DNS listener: %w", err)
		}
	}

	// Start UDP server with timeouts
	if s.config.UDPAddr != "" {
		s.udpServer = &dns.Server{
			Addr:         s.config.UDPAddr,
			Net:          "udp",
			Handler:      handler,
			ReadTimeout:  s.config.TCPReadTimeout, // Apply same timeout to UDP
			WriteTimeout: s.config.TCPWriteTimeout,
			UDPSize:      4096, // Maximum UDP payload size
		}

		s.serverWg.Add(1)
		go func() {
			defer s.serverWg.Done()

			if err := s.udpServer.ListenAndServe(); err != nil {
				select {
				case s.serverErrs <- fmt.Errorf("UDP server error: %w", err):
				case <-s.ctx.Done():
					// Server is shutting down, ignore error
				default:
					// Error channel full, drop error
				}
			}
		}()
	}

	// Start TCP server with connection limits
	if s.config.TCPAddr != "" {
		s.tcpServer = &dns.Server{
			Listener:     tcpListener,
			Handler:      handler,
			ReadTimeout:  s.config.TCPReadTimeout,
			WriteTimeout: s.config.TCPWriteTimeout,
			IdleTimeout: func() time.Duration {
				return s.config.TCPIdleTimeout
			},
			MaxTCPQueries: s.config.MaxTCPQueriesPerConnection,
		}

		s.serverWg.Add(1)
		go func() {
			defer s.serverWg.Done()

			if err := s.tcpServer.ActivateAndServe(); err != nil {
				select {
				case s.serverErrs <- fmt.Errorf("TCP server error: %w", err):
				case <-s.ctx.Done():
					// Server is shutting down, ignore error
				default:
					// Error channel full, drop error
				}
			}
		}()
	}

	s.running = true
	return nil
}

// Stop stops the DNS server.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	// Cancel context to signal goroutines
	s.cancel()

	// Shutdown DNS servers
	if s.udpServer != nil {
		s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		s.tcpServer.Shutdown()
	}

	// Wait for server goroutines to complete
	s.serverWg.Wait()

	// Close error channel
	close(s.serverErrs)

	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	return nil
}

// Errors returns a channel that receives server errors
// Useful for monitoring server health
func (s *Server) Errors() <-chan error {
	return s.serverErrs
}

// handleDNS processes incoming DNS requests with panic recovery.
func (s *Server) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	// Panic recovery - prevent server crashes
	defer func() {
		if panicVal := recover(); panicVal != nil {
			// Log the panic with stack trace
			fmt.Printf("[PANIC] DNS handler panic: %v\n", panicVal)

			// Return SERVFAIL to client
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			w.WriteMsg(m)
		}
	}()

	// Check if server is shutting down
	select {
	case <-s.ctx.Done():
		// Server is shutting down, return SERVFAIL
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	default:
		// Continue processing
	}

	// Get client IP
	var clientIP net.IP
	switch addr := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		clientIP = addr.IP
	case *net.TCPAddr:
		clientIP = addr.IP
	}

	// 1. Access Control Check
	if !s.acl.IsAllowed(clientIP) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		appendEDE(m, 15, "Blocked by ACL") // 15 = Blocked
		w.WriteMsg(m)
		return
	}

	// 2. Rate Limiting Check
	if !s.limiter.Allow(clientIP) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		appendEDE(m, 15, "Rate Limited") // 15 = Blocked
		w.WriteMsg(m)
		return
	}

	// 3. DNS Type ANY Amplification & DLP Check
	if len(req.Question) > 0 {
		q := req.Question[0]

		if q.Qtype == dns.TypeANY {
			// RFC 8482: respond with a minimal HINFO record instead of NOTIMP.
			// This satisfies the protocol while preventing ANY-query amplification
			// (historically the largest amplification ratios in DNS). (NSD refuse-any)
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = []dns.RR{&dns.HINFO{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeHINFO,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Cpu: "RFC8482",
				Os:  "ANY obsoleted",
			}}
			w.WriteMsg(m)
			return
		}

		if len(q.Name) > 60 && engine.IsDataExfiltration(q.Name) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			appendEDE(m, 4, "Exfiltration Blocked") // 4 = Forged Answer
			w.WriteMsg(m)
			return
		}

		// 4. RPZ Check (pre-resolution)
		rule, action := s.rpz.Check(q.Name)
		if rule != nil && action != engine.RPZActionPassthru {
			m := s.handleRPZAction(req, rule, action)
			if m != nil {
				appendEDE(m, 17, "RPZ Filtered") // 17 = Filtered
				w.WriteMsg(m)
			}
			return
		}
	}

	// 4. Resolve the query (use server context for cancellation)
	resp, err := s.HandleDNS(s.ctx, req)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// 5. RPZ Check (post-resolution) - for answer-based policies
	// This allows blocking based on resolved IPs
	// TODO: Implement IP-based RPZ triggers

	// Minimal responses: strip authority + additional from positive answers to
	// reduce amplification and prevent additional-section poisoning. (NSD minimal-responses)
	if s.config.MinimalResponses && len(resp.Answer) > 0 {
		resp.Ns = nil
		resp.Extra = stripNonOPT(resp.Extra)
	}

	// Cap EDNS UDP payload size to 1232 bytes in all responses (DNS Flag Day 2020).
	if opt := resp.IsEdns0(); opt != nil && opt.UDPSize() > 1232 {
		opt.SetUDPSize(1232)
	}

	w.WriteMsg(resp)
}

// stripNonOPT removes all additional-section records except the OPT RR (EDNS0).
func stripNonOPT(extra []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}

// HandleDNS implements the Handler interface for DoT/DoH integration.
func (s *Server) HandleDNS(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		return m, nil
	}

	q := req.Question[0]

	result, err := s.resolver.Resolve(
		ctx,
		q.Name,
		dns.TypeToString[q.Qtype],
		dns.ClassToString[q.Qclass],
		req.IsEdns0() != nil,
		req.RecursionDesired,
		req.CheckingDisabled,
	)
	if err != nil {
		return nil, err
	}

	// Unpack the wire format response
	resp := new(dns.Msg)
	if err := resp.Unpack(result.Wire); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *Server) handleRPZAction(req *dns.Msg, rule *engine.RPZRule, action engine.RPZAction) *dns.Msg {
	m := new(dns.Msg)

	switch action {
	case engine.RPZActionNXDomain:
		m.SetRcode(req, dns.RcodeNameError)

	case engine.RPZActionNoData:
		m.SetRcode(req, dns.RcodeSuccess)

	case engine.RPZActionDrop:
		// Return nil to indicate drop - caller should not respond
		return nil

	case engine.RPZActionRewrite:
		m.SetRcode(req, dns.RcodeSuccess)
		if rule.RewriteTarget != "" && len(req.Question) > 0 {
			cname := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: rule.RewriteTarget,
			}
			m.Answer = append(m.Answer, cname)
		}

	default:
		// Shouldn't reach here for PASSTHRU or NONE
		m.SetRcode(req, dns.RcodeSuccess)
	}

	m.SetReply(req)
	return m
}

// appendEDE helper attaches RFC 8914 Extended DNS Error options
func appendEDE(m *dns.Msg, code uint16, msg string) {
	opt := m.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(4096)
		m.Extra = append(m.Extra, opt)
	}

	ede := new(dns.EDNS0_EDE)
	ede.InfoCode = code
	ede.ExtraText = msg
	opt.Option = append(opt.Option, ede)
}
