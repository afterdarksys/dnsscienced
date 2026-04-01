package transport

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/dnsscience/dnsscienced/internal/engine"
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
}

// DefaultServerConfig returns a configuration with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		UDPAddr:         ":53",
		TCPAddr:         ":53",
		Upstream:        "8.8.8.8:53",
		Enable0x20:      true,
		EnableScrubbing: true,
		EnableQNAMEMin:  true,
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
}

// NewServer creates a new DNS server.
func NewServer(cfg ServerConfig) *Server {
	resolverCfg := engine.ResolverConfig{
		Upstream:        cfg.Upstream,
		Enable0x20:      cfg.Enable0x20,
		EnableScrubbing: cfg.EnableScrubbing,
		EnableQNAMEMin:  cfg.EnableQNAMEMin,
	}

	return &Server{
		config:   cfg,
		resolver: engine.NewResolverWithConfig(resolverCfg),
		acl:      engine.NewACL(true), // Default allow
		limiter:  engine.NewRateLimiter(engine.DefaultRateLimiterConfig()),
		rpz:      engine.NewRPZAggregate(),
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

	// Start UDP server
	if s.config.UDPAddr != "" {
		s.udpServer = &dns.Server{
			Addr:    s.config.UDPAddr,
			Net:     "udp",
			Handler: handler,
		}
		go func() {
			if err := s.udpServer.ListenAndServe(); err != nil {
				// Log error
			}
		}()
	}

	// Start TCP server
	if s.config.TCPAddr != "" {
		s.tcpServer = &dns.Server{
			Addr:    s.config.TCPAddr,
			Net:     "tcp",
			Handler: handler,
		}
		go func() {
			if err := s.tcpServer.ListenAndServe(); err != nil {
				// Log error
			}
		}()
	}

	s.running = true
	return nil
}

// Stop stops the DNS server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	if s.udpServer != nil {
		s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		s.tcpServer.Shutdown()
	}

	s.running = false
	return nil
}

// handleDNS processes incoming DNS requests.
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
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
		m.SetRcode(r, dns.RcodeRefused)
		appendEDE(m, 15, "Blocked by ACL") // 15 = Blocked
		w.WriteMsg(m)
		return
	}

	// 2. Rate Limiting Check
	if !s.limiter.Allow(clientIP) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		appendEDE(m, 15, "Rate Limited") // 15 = Blocked
		w.WriteMsg(m)
		return
	}

	// 3. DNS Type ANY Amplification & DLP Check
	if len(r.Question) > 0 {
		q := r.Question[0]
		
		if q.Qtype == dns.TypeANY {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNotImplemented)
			appendEDE(m, 15, "ANY queries unsupported") // 15 = Blocked
			w.WriteMsg(m)
			return
		}

		if len(q.Name) > 60 && engine.IsDataExfiltration(q.Name) {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			appendEDE(m, 4, "Exfiltration Blocked") // 4 = Forged Answer
			w.WriteMsg(m)
			return
		}

		// 4. RPZ Check (pre-resolution)
		rule, action := s.rpz.Check(q.Name)
		if rule != nil && action != engine.RPZActionPassthru {
			m := s.handleRPZAction(r, rule, action)
			if m != nil {
				appendEDE(m, 17, "RPZ Filtered") // 17 = Filtered
				w.WriteMsg(m)
			}
			return
		}
	}

	// 4. Resolve the query
	resp, err := s.HandleDNS(context.Background(), r)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// 5. RPZ Check (post-resolution) - for answer-based policies
	// This allows blocking based on resolved IPs
	// TODO: Implement IP-based RPZ triggers

	w.WriteMsg(resp)
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
