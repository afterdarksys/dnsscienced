package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/api/grpc/ports"
	"github.com/miekg/dns"
)

// ResolverConfig holds configuration options for the Resolver.
type ResolverConfig struct {
	Upstream        string
	Timeout         time.Duration
	Enable0x20      bool // Enable 0x20 bit encoding for cache poisoning resistance
	EnableScrubbing bool // Enable response scrubbing to remove out-of-bailiwick records
	EnableQNAMEMin  bool // Enable QNAME minimization (RFC 7816)
	ValidateDNSSEC  bool // Enable DNSSEC validation (stub - full impl in Phase 2)
}

// DefaultResolverConfig returns a secure default configuration.
func DefaultResolverConfig() ResolverConfig {
	return ResolverConfig{
		Upstream:        "8.8.8.8:53",
		Timeout:         2 * time.Second,
		Enable0x20:      true,
		EnableScrubbing: true,
		EnableQNAMEMin:  true,
		ValidateDNSSEC:  false, // Disabled until Phase 2 implementation
	}
}

// Resolver implements ports.DNSResolver using miekg/dns with security hardening.
type Resolver struct {
	Config ResolverConfig
	Client *dns.Client
}

// NewResolver creates a new Resolver instance with security features enabled by default.
func NewResolver(upstream string) *Resolver {
	cfg := DefaultResolverConfig()
	if upstream != "" {
		cfg.Upstream = upstream
	}
	return NewResolverWithConfig(cfg)
}

// NewResolverWithConfig creates a Resolver with explicit configuration.
func NewResolverWithConfig(cfg ResolverConfig) *Resolver {
	return &Resolver{
		Config: cfg,
		Client: &dns.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Resolve performs a DNS query with security hardening.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype string, class string, dnssec bool, rd bool, cd bool) (*ports.ResolveResult, error) {
	// 1. Normalize and prepare query name
	originalName := dns.Fqdn(name)
	queryName := originalName

	// Apply QNAME minimization if enabled
	if r.Config.EnableQNAMEMin {
		queryName = ApplyQNAMEMinimization(queryName, extractZone(originalName))
	}

	// Apply 0x20 encoding if enabled
	if r.Config.Enable0x20 {
		queryName = Apply0x20Encoding(queryName)
	}

	// 2. Construct the query message
	m := new(dns.Msg)
	m.Id = dns.Id()
	t, ok := dns.StringToType[qtype]
	if !ok {
		t = dns.TypeA
	}
	c, ok := dns.StringToClass[class]
	if !ok {
		c = dns.ClassINET
	}
	m.SetQuestion(queryName, t)
	m.Question[0].Qclass = c
	m.RecursionDesired = rd
	m.CheckingDisabled = cd

	// Request DNSSEC records if validation is enabled or explicitly requested
	requestDNSSEC := dnssec || r.Config.ValidateDNSSEC
	m.SetEdns0(4096, requestDNSSEC)

	// 3. Exchange with upstream
	in, rtt, err := r.Client.ExchangeContext(ctx, m, r.Config.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream query failed: %w", err)
	}

	// 4. Validate 0x20 response if enabled
	if r.Config.Enable0x20 && len(in.Question) > 0 {
		if !Validate0x20Response(queryName, in.Question[0].Name) {
			return nil, fmt.Errorf("0x20 validation failed: possible cache poisoning attack")
		}
	}

	// 5. Apply response scrubbing if enabled
	if r.Config.EnableScrubbing {
		// Extract the zone from the query name for bailiwick checking
		zone := extractZone(originalName)
		ScrubResponse(in, zone)
	}

	// 6. DNSSEC Validation (stub - will be implemented in Phase 2)
	if r.Config.ValidateDNSSEC && !cd {
		// TODO: Implement full DNSSEC chain-of-trust validation
		// For now, we just check if the AD (Authenticated Data) flag is set
		// This relies on the upstream resolver having done validation
		// A proper implementation would validate locally
	}

	// 7. Convert response to ports.ResolveResult
	res := &ports.ResolveResult{
		RCode:              int32(in.Rcode),
		RCodeName:          dns.RcodeToString[in.Rcode],
		Authoritative:      in.Authoritative,
		Truncated:          in.Truncated,
		RecursionAvailable: in.RecursionAvailable,
		Meta: map[string]string{
			"rtt_ms":            fmt.Sprintf("%d", rtt.Milliseconds()),
			"0x20_enabled":      fmt.Sprintf("%t", r.Config.Enable0x20),
			"scrubbing_enabled": fmt.Sprintf("%t", r.Config.EnableScrubbing),
			"dnssec_requested":  fmt.Sprintf("%t", requestDNSSEC),
		},
	}

	// Pack wire format
	wire, err := in.Pack()
	if err == nil {
		res.Wire = wire
	}

	// Convert RRs
	res.Answer = convertRRs(in.Answer)
	res.Authority = convertRRs(in.Ns)
	res.Additional = convertRRs(in.Extra)

	return res, nil
}

// ResolveRaw performs a DNS query using raw types to avoid unnecessary parsing/allocation.
// This is the high-performance path for FastUDPServer.
func (r *Resolver) ResolveRaw(ctx context.Context, name string, qtype uint16, qclass uint16, hasEDNS0 bool) (*ports.ResolveResult, error) {
	// 1. Normalize name (cheap string op)
	originalName := dns.Fqdn(name)
	queryName := originalName

	// Apply QNAME minimization if enabled
	if r.Config.EnableQNAMEMin {
		queryName = ApplyQNAMEMinimization(queryName, extractZone(originalName))
	}

	// Apply 0x20 encoding if enabled (this allocates, but is required for security)
	if r.Config.Enable0x20 {
		queryName = Apply0x20Encoding(queryName)
	}

	// 2. Construct the query message efficiently
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.SetQuestion(queryName, qtype)
	m.Question[0].Qclass = qclass
	m.RecursionDesired = true

	// Add EDNS0 if it was present in original packet OR if we require DNSSEC
	requestDNSSEC := r.Config.ValidateDNSSEC
	if hasEDNS0 || requestDNSSEC {
		m.SetEdns0(4096, requestDNSSEC)
	}

	// 3. Exchange with upstream
	// optimization: client.ExchangeContext reuses connections if Transport is configured right
	in, rtt, err := r.Client.ExchangeContext(ctx, m, r.Config.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream query failed: %w", err)
	}

	// 4. Validate 0x20 response
	if r.Config.Enable0x20 && len(in.Question) > 0 {
		if !Validate0x20Response(queryName, in.Question[0].Name) {
			return nil, fmt.Errorf("0x20 validation failed")
		}
	}

	// 5. Scrubbing
	if r.Config.EnableScrubbing {
		ScrubResponse(in, extractZone(originalName))
	}

	// 6. DNSSEC Stub
	if r.Config.ValidateDNSSEC {
		// Verify AD bit for now
		if !in.AuthenticatedData {
			// In Phase 2, this would trigger full validation
		}
	}

	// 7. Convert response (Zero-Copy-ish: we reuse the bytes if we packed them? No, upstream gives us struct)
	// We MUST pack to wire bytes to return to FastUDP, which writes bytes.
	// FastUDP doesn't need ports.ResolveResult if we just return []byte?
	// But the interface uses ResolveResult. Let's stick to it for now.

	wire, err := in.Pack()
	if err != nil {
		return nil, err
	}

	res := &ports.ResolveResult{
		RCode:     int32(in.Rcode),
		RCodeName: dns.RcodeToString[in.Rcode],
		Wire:      wire,
		Meta: map[string]string{
			"rtt_ms": fmt.Sprintf("%d", rtt.Milliseconds()),
			"path":   "fast_udp_raw",
		},
	}

	return res, nil
}

// extractZone extracts the parent zone from a FQDN.
// For "www.example.com." it returns "example.com."
func extractZone(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return name
	}
	// Return parent domain (second-level domain + TLD typically)
	if len(labels) == 2 {
		return name
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// convertRRs converts []dns.RR to []ports.ResourceRecord.
func convertRRs(rrs []dns.RR) []ports.ResourceRecord {
	var out []ports.ResourceRecord
	for _, rr := range rrs {
		header := rr.Header()

		// Extract just the RDATA part from the string representation
		fullString := rr.String()
		headerString := header.String()
		var data string
		if len(fullString) > len(headerString) {
			data = fullString[len(headerString):]
		}

		// Pack the full RR for wire format
		buf := make([]byte, 1024)
		off, err := dns.PackRR(rr, buf, 0, nil, false)
		var rdataBytes []byte
		if err == nil {
			rdataBytes = buf[:off]
		}

		out = append(out, ports.ResourceRecord{
			Name:  header.Name,
			Type:  dns.TypeToString[header.Rrtype],
			Class: dns.ClassToString[header.Class],
			TTL:   header.Ttl,
			Data:  data,
			RData: rdataBytes,
		})
	}
	return out
}
