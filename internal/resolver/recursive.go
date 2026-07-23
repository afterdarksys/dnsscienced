package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/cookie"
	"github.com/dnsscience/dnsscienced/internal/dnssec"
	"github.com/dnsscience/dnsscienced/internal/engine"
	"github.com/dnsscience/dnsscienced/internal/packet"
	"github.com/dnsscience/dnsscienced/internal/pool"
	"github.com/dnsscience/dnsscienced/internal/random"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/worker"
	"github.com/miekg/dns"
)

var (
	// Root hints (simplified - real version would load from file)
	rootServers = []string{
		"198.41.0.4:53",     // a.root-servers.net
		"199.9.14.201:53",   // b.root-servers.net
		"192.33.4.12:53",    // c.root-servers.net
		"199.7.91.13:53",    // d.root-servers.net
		"192.203.230.10:53", // e.root-servers.net
		"192.5.5.241:53",    // f.root-servers.net
		"192.112.36.4:53",   // g.root-servers.net
		"198.97.190.53:53",  // h.root-servers.net
		"192.36.148.17:53",  // i.root-servers.net
		"192.58.128.30:53",  // j.root-servers.net
		"193.0.14.129:53",   // k.root-servers.net
		"199.7.83.42:53",    // l.root-servers.net
		"202.12.27.33:53",   // m.root-servers.net
	}

	ErrMaxIterations = errors.New("max iterations reached")
	ErrNoNameservers = errors.New("no nameservers available")
	ErrTimeout       = errors.New("query timeout")
)

// Config holds resolver configuration
type Config struct {
	// Cache configuration
	CacheConfig cache.Config `yaml:"cache"`

	// Worker pool for concurrent queries
	Workers int `yaml:"workers"`

	// Query timeout
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// Max iterations for iterative resolution
	MaxIterations int `yaml:"max_iterations"`

	// Enable DNS cookies
	EnableCookies bool          `yaml:"enable_cookies"`
	CookieConfig  cookie.Config `yaml:"cookies"`

	// Enable RRL
	EnableRRL bool       `yaml:"enable_rrl"`
	RRLConfig rrl.Config `yaml:"rrl"`

	// DNSSEC validation. When enabled the resolver validates responses before
	// caching them and sets DNSSECValidated / DNSSECBogus on each cache entry.
	// Required for AggressiveNSEC to function correctly.
	EnableDNSSEC bool                   `yaml:"enable_dnssec"`
	DNSSECConfig dnssec.ValidatorConfig `yaml:"dnssec"`

	// QNAMEMinimization enables RFC 7816 + RFC 9156 per-delegation query name rewriting.
	QNAMEMinimization bool `yaml:"qname_minimization"`

	// Enable0x20 enables DNS 0x20 query-name case randomization (draft-vixie-dnsext-dns0x20).
	// Outgoing iterative queries get randomized case; responses whose echoed question
	// name does not preserve that case are rejected as off-path spoofing attempts.
	Enable0x20 bool `yaml:"enable_0x20"`

	// EnableScrubbing enables bailiwick scrubbing of referral responses (RFC 5452).
	// Out-of-bailiwick NS delegations and glue records are dropped before they are
	// followed or cached, hardening against cache-poisoning via injected glue.
	EnableScrubbing bool `yaml:"enable_scrubbing"`

	// AggressiveNSEC enables RFC 8198 synthesis from cached NSEC/NSEC3 records.
	AggressiveNSEC bool `yaml:"aggressive_nsec"`

	// ServeStale enables RFC 8767 behavior: serve expired cache entries with TTL=0
	// when all upstream nameservers are unreachable.
	ServeStale bool `yaml:"serve_stale"`

	// StaleTTL is the maximum age past expiry that a stale record may be served.
	// Defaults to 24h. Wired into CacheConfig.MaxStaleTTL to avoid duplication (D-11).
	StaleTTL time.Duration `yaml:"stale_max_ttl"`
}

// Recursive implements a full recursive DNS resolver
type Recursive struct {
	cache      *cache.ShardedCache
	workerPool *worker.Pool
	cookies    *cookie.Manager
	rrl        *rrl.Limiter
	validator  *dnssec.Validator

	cfg Config

	// UDP client with randomized source port
	client *dns.Client
	roots  []string
}

// DefaultConfig returns an RFC-compliant default configuration with all three
// resolver features enabled (QNAME minimization, Aggressive NSEC, Serve Stale).
// Callers who want specific features off should start from DefaultConfig() and
// set individual flags to false. Config{} means "all features off".
func DefaultConfig() Config {
	return Config{
		QueryTimeout:      5 * time.Second,
		MaxIterations:     20,
		Workers:           100,
		QNAMEMinimization: true,
		AggressiveNSEC:    true,
		ServeStale:        true,
		StaleTTL:          24 * time.Hour,
		Enable0x20:        true,
		EnableScrubbing:   true,
		CacheConfig: cache.Config{
			// MinTTL 0 means "no floor" (matches applyTTLPolicy's `> 0` gate).
			// MaxTTL caps positive-response TTLs at 1 day (Unbound cache-max-ttl
			// default) so a malicious/misconfigured authoritative server cannot
			// pin a poisoned record in cache indefinitely via an oversized TTL
			// (e.g. TTL=4294967295 -> ~136 years without this ceiling).
			MinTTL: 0,
			MaxTTL: 86400 * time.Second,
		},
	}
}

// NewRecursive creates a new recursive resolver
func NewRecursive(cfg Config) (*Recursive, error) {
	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = 5 * time.Second
	}
	if cfg.MaxIterations == 0 {
		cfg.MaxIterations = 20
	}
	if cfg.Workers == 0 {
		cfg.Workers = 100
	}

	// Wire resolver feature flags into cache config (D-11: avoid duplication).
	if cfg.ServeStale {
		cfg.CacheConfig.ServeStale = true
		if cfg.StaleTTL > 0 {
			cfg.CacheConfig.MaxStaleTTL = cfg.StaleTTL
		} else {
			cfg.CacheConfig.MaxStaleTTL = 24 * time.Hour
		}
	}
	if cfg.AggressiveNSEC {
		cfg.CacheConfig.AggressiveNSEC = true
	}

	r := &Recursive{
		cache: cache.NewShardedCache(cfg.CacheConfig),
		workerPool: worker.NewPool(worker.Config{
			Workers:   cfg.Workers,
			QueueSize: cfg.Workers * 10,
		}),
		client: &dns.Client{
			Timeout: cfg.QueryTimeout,
			Net:     "udp",
		},
		cfg:   cfg,
		roots: append([]string(nil), rootServers...),
	}

	// Initialize cookies if enabled
	if cfg.EnableCookies {
		var err error
		r.cookies, err = cookie.NewManager(cfg.CookieConfig)
		if err != nil {
			return nil, fmt.Errorf("init cookies: %w", err)
		}
	}

	// Initialize RRL if enabled
	if cfg.EnableRRL {
		r.rrl = rrl.NewLimiter(cfg.RRLConfig)
	}

	// Initialize DNSSEC validator if enabled. The validator uses this resolver
	// as its upstream for DNSKEY/DS lookups (r implements dnssec.DNSResolver).
	if cfg.EnableDNSSEC {
		vcfg := cfg.DNSSECConfig
		if vcfg.MaxChainDepth == 0 {
			vcfg = dnssec.DefaultValidatorConfig()
		}
		v, err := dnssec.NewValidator(vcfg, r)
		if err != nil {
			return nil, fmt.Errorf("init dnssec validator: %w", err)
		}
		r.validator = v
	}

	// Register prefetch callback when prefetch is enabled.
	if cfg.CacheConfig.Prefetch {
		r.cache.SetPrefetchFunc(func(qname string, qtype, qclass uint16) {
			msg := new(dns.Msg)
			msg.SetQuestion(qname, qtype)
			// Best-effort background refresh; errors are silently discarded.
			_, _ = r.Resolve(context.Background(), msg, nil)
		})
	}

	return r, nil
}

// Query implements dnssec.DNSResolver so the DNSSEC validator can look up
// DNSKEY and DS records through this resolver's cache and iterative resolution.
func (r *Recursive) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	return r.Resolve(ctx, msg, nil)
}

// Resolve performs recursive resolution for a query
func (r *Recursive) Resolve(ctx context.Context, q *dns.Msg, clientIP net.IP) (*dns.Msg, error) {
	if len(q.Question) == 0 {
		return nil, errors.New("no question in query")
	}

	question := q.Question[0]

	// 1. Check cache first.
	cacheKey := packet.HashQuery(question.Name, question.Qtype, question.Qclass)
	if entry, ok := r.cache.Get(cacheKey); ok {
		// Bogus entries are quarantined: serve SERVFAIL so clients don't use
		// DNSSEC-invalid data, but avoid re-querying until BogusTTL expires.
		if entry.DNSSECBogus {
			m := new(dns.Msg)
			m.SetRcode(q, dns.RcodeServerFailure)
			return m, nil
		}

		resp := pool.GetMessage()
		defer pool.PutMessage(resp)
		if err := resp.Unpack(entry.Data); err == nil {
			resp.Id = q.Id
			resp.Question = append(resp.Question[:0], q.Question...)
			resp.RecursionDesired = q.RecursionDesired
			resp.CheckingDisabled = q.CheckingDisabled
			resp.RecursionAvailable = true
			if entry.DNSSECValidated {
				resp.AuthenticatedData = true
			}
			// RFC 8767 section 5: stale entries must be served with TTL=0 so
			// clients know the record is past its original expiry (D-08).
			ageCachedTTLs(resp, entry.ExpiresAt)
			return resp.Copy(), nil
		}
	}

	// 2. Aggressive NSEC synthesis (RFC 8198): answer from cached NSEC proofs
	// without hitting the network when the name is provably non-existent.
	// Guard on the resolver config flag rather than relying on the cache
	// layer's nil-nsecCache check, to decouple policy from implementation.
	if r.cfg.AggressiveNSEC {
		if synth := r.cache.SynthesizeNXDOMAIN(question.Name, question.Qtype, question.Qclass, q.Id); synth != nil {
			return synth, nil
		}
	}

	// 3. Cache miss — perform iterative resolution.
	resp, err := r.resolveIterative(ctx, question.Name, question.Qtype, question.Qclass)
	if err != nil {
		// Upstream failure: attempt stale cache lookup before SERVFAIL (RFC 8767, D-07 bug 2).
		if r.cfg.ServeStale {
			if staleEntry, ok := r.cache.Get(cacheKey); ok {
				staleResp := pool.GetMessage()
				if unpackErr := staleResp.Unpack(staleEntry.Data); unpackErr == nil {
					staleResp.Id = q.Id
					staleResp.RecursionAvailable = true
					// RFC 8767 section 5: rewrite TTL=0 on all RRs in stale response (D-08).
					for _, rr := range staleResp.Answer {
						rr.Header().Ttl = 0
					}
					for _, rr := range staleResp.Ns {
						rr.Header().Ttl = 0
					}
					for _, rr := range staleResp.Extra {
						if rr.Header().Rrtype != dns.TypeOPT {
							rr.Header().Ttl = 0
						}
					}
					result := staleResp.Copy()
					pool.PutMessage(staleResp)
					return result, nil
				}
				pool.PutMessage(staleResp)
			}
		}
		return nil, err
	}

	resp.Id = q.Id
	resp.Question = append(resp.Question[:0], q.Question...)
	resp.RecursionDesired = q.RecursionDesired
	resp.CheckingDisabled = q.CheckingDisabled
	resp.RecursionAvailable = true

	// RFC 1034 section 4.3.2: a recursive answer includes the alias chain and
	// continues resolving until it reaches the requested RR type or an error.
	resp, err = r.followAliases(ctx, resp, question.Name, question.Qtype, question.Qclass)
	if err != nil {
		return nil, err
	}
	resp.Id = q.Id
	resp.Question = append(resp.Question[:0], q.Question...)
	resp.RecursionDesired = q.RecursionDesired
	resp.CheckingDisabled = q.CheckingDisabled
	resp.RecursionAvailable = true

	// 4. DNS rebinding check: discard responses that map a public name to a
	// private IP (Unbound private-address). Never cache or serve such responses.
	if !r.cache.IsSafeResponse(resp, question.Name) {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeServerFailure)
		return m, nil
	}

	// 5. DNSSEC validation before caching.
	var dnssecValidated, dnssecBogus bool
	if r.validator != nil {
		result, validErr := r.validator.Validate(ctx, resp, question.Name, question.Qtype)
		if validErr != nil {
			// Validation error (network failure, chain depth, context cancellation):
			// return SERVFAIL rather than serving the response as if it were valid.
			// This prevents a transient validator failure from allowing bogus data through.
			m := new(dns.Msg)
			m.SetRcode(q, dns.RcodeServerFailure)
			return m, nil
		}
		if result != nil {
			dnssecValidated = result.Secure
			dnssecBogus = result.Bogus
			if result.Secure {
				resp.AuthenticatedData = true
			}
		}
	}

	// 6. Cache the response.
	ttl := getTTL(resp)
	if packed, err := resp.Pack(); err == nil {
		entry := &cache.Entry{
			Data:            packed,
			ExpiresAt:       time.Now().Add(time.Duration(ttl) * time.Second),
			OrigTTL:         ttl,
			QName:           question.Name,
			QType:           question.Qtype,
			QClass:          question.Qclass,
			DNSSECValidated: dnssecValidated,
			DNSSECBogus:     dnssecBogus,
		}

		// Build negative-cache entry metadata for NXDOMAIN / NODATA.
		if resp.Rcode == dns.RcodeNameError {
			entry.IsNegative = true
			entry.NegType = "NXDOMAIN"
		} else if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			entry.IsNegative = true
			entry.NegType = "NODATA"
		}

		r.cache.Set(cacheKey, entry)

		// Store NSEC records for aggressive synthesis if response was validated.
		// Use the zone from the authority section (SOA/NS owner), not the queried
		// name, so the zone membership check in SynthesizeNXDOMAIN works correctly.
		if dnssecValidated && entry.IsNegative {
			r.cache.StoreNSEC(resp, extractZoneFromResponse(resp))
		}
	}

	return resp, nil
}

// extractZoneFromResponse returns the zone name from the authority section of
// a DNS response. It prefers the SOA owner name (most authoritative) and falls
// back to the NS owner name. Returns "." if neither is found.
func extractZoneFromResponse(resp *dns.Msg) string {
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Hdr.Name
		}
	}
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			return ns.Hdr.Name
		}
	}
	return "."
}

const maxAliasChain = 16

// followAliases completes CNAME and DNAME chains while preserving the alias
// records already returned. The bound and seen set prevent loops and query
// amplification from malicious alias graphs.
func (r *Recursive) followAliases(ctx context.Context, initial *dns.Msg, qname string, qtype, qclass uint16) (*dns.Msg, error) {
	if qtype == dns.TypeCNAME || qtype == dns.TypeDNAME {
		return initial, nil
	}

	combined := initial.Copy()
	current := dns.Fqdn(strings.ToLower(qname))
	seen := map[string]struct{}{current: {}}
	for depth := 0; depth < maxAliasChain; depth++ {
		target, synthesized := aliasTarget(combined.Answer, current)
		if target == "" {
			return combined, nil
		}
		if synthesized != nil {
			combined.Answer = append(combined.Answer, synthesized)
		}
		target = dns.Fqdn(strings.ToLower(target))
		if _, exists := seen[target]; exists {
			return nil, fmt.Errorf("alias loop detected at %s", target)
		}
		seen[target] = struct{}{}

		next, err := r.resolveIterative(ctx, target, qtype, qclass)
		if err != nil {
			return nil, err
		}
		combined.Answer = append(combined.Answer, next.Answer...)
		combined.Ns = next.Ns
		combined.Extra = next.Extra
		combined.Rcode = next.Rcode
		current = target
	}
	return nil, fmt.Errorf("alias chain exceeds %d links", maxAliasChain)
}

func aliasTarget(answer []dns.RR, current string) (string, dns.RR) {
	for _, rr := range answer {
		if cname, ok := rr.(*dns.CNAME); ok && strings.EqualFold(cname.Hdr.Name, current) {
			return cname.Target, nil
		}
	}

	var best *dns.DNAME
	for _, rr := range answer {
		dname, ok := rr.(*dns.DNAME)
		if !ok || strings.EqualFold(dname.Hdr.Name, current) || !dns.IsSubDomain(dname.Hdr.Name, current) {
			continue
		}
		if best == nil || len(dname.Hdr.Name) > len(best.Hdr.Name) {
			best = dname
		}
	}
	if best == nil {
		return "", nil
	}
	prefix := current[:len(current)-len(best.Hdr.Name)]
	target := prefix + best.Target
	return target, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   current,
			Rrtype: dns.TypeCNAME,
			Class:  best.Hdr.Class,
			Ttl:    best.Hdr.Ttl,
		},
		Target: target,
	}
}

func ageCachedTTLs(msg *dns.Msg, expiresAt time.Time) {
	remaining := uint32(0)
	if d := time.Until(expiresAt); d > 0 {
		remaining = uint32(d / time.Second)
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl > remaining {
				rr.Header().Ttl = remaining
			}
		}
	}
}

// resolveIterative performs iterative resolution starting from root
func (r *Recursive) resolveIterative(ctx context.Context, qname string, qtype, qclass uint16) (*dns.Msg, error) {
	return r.resolveIterativeWithBudget(ctx, qname, qtype, qclass, r.cfg.MaxIterations)
}

func (r *Recursive) resolveIterativeWithBudget(ctx context.Context, qname string, qtype, qclass uint16, budget int) (*dns.Msg, error) {
	if budget <= 0 {
		return nil, ErrMaxIterations
	}
	nameservers := r.roots
	iterations := 0
	currentZone := "."

	for iterations < budget {
		iterations++

		// Compute minimized send name and type for this hop (D-02, D-03).
		sendName := qname
		sendType := qtype
		if r.cfg.QNAMEMinimization {
			sendName = engine.ApplyQNAMEMinimization(qname, currentZone)
			// RFC 9156: intermediate hops use qtype=A; final hop uses original qtype.
			if sendName != qname {
				sendType = dns.TypeA
			}
		}

		// Try each nameserver until one responds; this keeps server failover
		// within a single delegation separate from the iterative hop counter.
		var resp *dns.Msg
		var lastNSErr error
		for i, ns := range nameservers {
			var err error
			resp, err = r.queryNameserver(ctx, ns, sendName, sendType, qclass)
			if err != nil {
				lastNSErr = err
				if i == len(nameservers)-1 {
					return nil, fmt.Errorf("all nameservers failed: %w", lastNSErr)
				}
				continue
			}
			// QNAME minimization NODATA at intermediate hop (RFC 9156 section 4):
			// if minimized and answer is empty + NOERROR + no NS records, disable
			// minimization and re-issue full qname to this same nameserver.
			if r.cfg.QNAMEMinimization && sendName != qname &&
				len(resp.Answer) == 0 && resp.Rcode == dns.RcodeSuccess && len(resp.Ns) == 0 {
				resp, err = r.queryNameserver(ctx, ns, qname, qtype, qclass)
				if err != nil {
					lastNSErr = err
					if i == len(nameservers)-1 {
						return nil, fmt.Errorf("all nameservers failed: %w", lastNSErr)
					}
					continue
				}
				sendName = qname
				sendType = qtype
			}
			break // success
		}

		// A positive response to an intermediate minimized name is not the
		// answer to the original question. Continue revealing labels using the
		// same authoritative server (RFC 9156 section 3 step 6c).
		if len(resp.Answer) > 0 && sendName != qname {
			currentZone = dns.Fqdn(strings.ToLower(sendName))
			continue
		}

		// Check if we got an answer
		if len(resp.Answer) > 0 {
			return resp, nil
		}

		// Check for NXDOMAIN
		if resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}

		// Follow referral (NS records in Authority section).
		if len(resp.Ns) > 0 {
			// Collect NS records. When scrubbing is enabled, drop any delegation whose
			// owner is not in-bailiwick of the zone we just queried: a server
			// authoritative for currentZone may only delegate names beneath it
			// (RFC 5452). This blocks a poisoned referral that tries to redirect
			// resolution to an unrelated zone (e.g. a rogue .org server delegating
			// victim.com).
			var nsRecords []*dns.NS
			var nsNames []string
			for _, rr := range resp.Ns {
				ns, ok := rr.(*dns.NS)
				if !ok {
					continue
				}
				if r.cfg.EnableScrubbing && !engine.IsInBailiwick(ns.Header().Name, currentZone) {
					continue
				}
				nsRecords = append(nsRecords, ns)
				nsNames = append(nsNames, ns.Ns)
			}

			// Either no NS records, or all were scrubbed as out-of-bailiwick.
			if len(nsRecords) == 0 {
				return nil, ErrNoNameservers
			}

			// Delegation (child) zone is the NS RR owner name (the zone),
			// NOT ns.Ns (the nameserver hostname). Pitfall 5: must be FQDN.
			childZone := dns.Fqdn(strings.ToLower(nsRecords[0].Header().Name))

			// Harden glue: keep only A/AAAA whose owner is one of the delegated
			// nameservers AND in-bailiwick of the child zone. Out-of-bailiwick glue
			// — the classic cache-poisoning injection point — is discarded before
			// it is ever followed.
			glue := resp.Extra
			if r.cfg.EnableScrubbing {
				glue = engine.HardenGlue(resp.Extra, childZone, nsNames)
			}

			var newNameservers []string
			for _, ns := range nsRecords {
				nsIP := r.findGlue(glue, ns.Ns)
				if nsIP != "" {
					newNameservers = append(newNameservers, nsIP+":53")
				}
			}

			// No usable glue: resolve each NS target name to obtain addresses.
			// This handles out-of-zone nameservers (the common real-world case).
			// Each glue resolution uses a fresh sub-chain capped by the remaining
			// iteration budget to prevent unbounded recursion.
			if len(newNameservers) == 0 {
				for _, ns := range nsRecords {
					if iterations >= budget {
						break
					}
					remaining := budget - iterations
					glueResp, glueErr := r.resolveIterativeWithBudget(ctx, ns.Ns, dns.TypeA, qclass, remaining)
					if glueErr != nil {
						glueResp, glueErr = r.resolveIterativeWithBudget(ctx, ns.Ns, dns.TypeAAAA, qclass, remaining)
						if glueErr != nil {
							continue
						}
					}
					for _, arec := range glueResp.Answer {
						switch a := arec.(type) {
						case *dns.A:
							newNameservers = append(newNameservers, a.A.String()+":53")
						case *dns.AAAA:
							newNameservers = append(newNameservers, net.JoinHostPort(a.AAAA.String(), "53"))
						}
					}
				}
			}

			if len(newNameservers) == 0 {
				return nil, ErrNoNameservers
			}

			nameservers = newNameservers
			currentZone = childZone
			continue
		}

		// No answer, no referral - return what we have
		return resp, nil
	}

	return nil, ErrMaxIterations
}

// queryNameserver sends a query to a specific nameserver
func (r *Recursive) queryNameserver(ctx context.Context, ns string, qname string, qtype, qclass uint16) (*dns.Msg, error) {
	msg := pool.GetMessage()
	defer pool.PutMessage(msg)

	msg.Id = random.TransactionID()
	msg.RecursionDesired = false // Iterative queries don't set RD

	// 0x20 case randomization (draft-vixie-dnsext-dns0x20): send a mixed-case copy
	// of the name on the wire. A compliant authoritative server echoes the case
	// verbatim, giving an extra ~1 bit of entropy per letter against off-path
	// spoofing on top of the 16-bit txid and OS source port.
	wireName := qname
	if r.cfg.Enable0x20 {
		wireName = engine.Apply0x20Encoding(qname)
	}
	msg.Question = []dns.Question{{
		Name:   wireName,
		Qtype:  qtype,
		Qclass: qclass,
	}}
	// 1232 bytes: DNS Flag Day 2020 recommendation (IPv6 min MTU 1280 - 48 bytes headers).
	// Prevents IP fragmentation-based amplification attacks.
	msg.SetEdns0(1232, r.cfg.EnableDNSSEC)

	// Send query with timeout
	queryCtx, cancel := context.WithTimeout(ctx, r.cfg.QueryTimeout)
	defer cancel()

	resp, _, err := r.client.ExchangeContext(queryCtx, msg, ns)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		tcpClient := &dns.Client{Timeout: r.cfg.QueryTimeout, Net: "tcp"}
		resp, _, err = tcpClient.ExchangeContext(queryCtx, msg, ns)
		if err != nil {
			return nil, fmt.Errorf("TCP retry after truncated UDP response: %w", err)
		}
	}

	// Validate the 0x20 echo: a response that does not preserve the exact case we
	// sent is treated as a spoofed/off-path forgery and discarded.
	if r.cfg.Enable0x20 && len(resp.Question) > 0 {
		if !engine.Validate0x20Response(wireName, resp.Question[0].Name) {
			return nil, fmt.Errorf("0x20 case mismatch from %s: possible spoofed response", ns)
		}
		// Restore the canonical (caller-supplied) case so nothing downstream — cache
		// keys, answer matching, callers comparing against qname — sees the mixed case.
		resp.Question[0].Name = qname
	}

	return resp, nil
}

// findGlue looks for glue records (A/AAAA) for nsName in the supplied Additional
// records (already bailiwick-hardened by the caller when scrubbing is enabled).
// It prefers IPv4 (A) over IPv6 (AAAA) to avoid bare-IPv6 address formatting
// issues. The returned string is ready to pass to net.Dial (bracketed for IPv6).
func (r *Recursive) findGlue(extra []dns.RR, nsName string) string {
	var ipv6addr string
	for _, rr := range extra {
		switch record := rr.(type) {
		case *dns.A:
			if record.Hdr.Name == nsName {
				return record.A.String() // IPv4 — use immediately
			}
		case *dns.AAAA:
			if record.Hdr.Name == nsName && ipv6addr == "" {
				// Bracket IPv6 so net.Dial can parse "host:port" correctly.
				ipv6addr = "[" + record.AAAA.String() + "]"
			}
		}
	}
	return ipv6addr
}

// getTTL extracts the minimum TTL from a response.
// For negative responses (NXDOMAIN/NODATA), uses the SOA minimum field per RFC 2308
// rather than defaulting to 1 hour, which would over-cache negative results.
func getTTL(msg *dns.Msg) uint32 {
	// Negative response: use SOA-based TTL per RFC 2308.
	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl := soa.Minttl
				if soa.Hdr.Ttl < ttl {
					ttl = soa.Hdr.Ttl
				}
				if ttl < 10 {
					ttl = 10
				}
				if ttl > 10800 {
					ttl = 10800
				}
				return ttl
			}
		}
		return 300 // 5m default for negative responses with no SOA
	}

	// Positive response: minimum TTL across Answer section.
	minTTL := uint32(3600)
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	return minTTL
}

// GetCache returns the resolver's shared DNS cache.
func (r *Recursive) GetCache() *cache.ShardedCache {
	return r.cache
}

// Close stops the resolver
func (r *Recursive) Close() error {
	r.cache.Close()
	r.workerPool.Close()
	if r.rrl != nil {
		r.rrl.Close()
	}
	return nil
}

// Stats returns resolver statistics
type Stats struct {
	Cache cache.Stats
	Pool  worker.Stats
	RRL   *rrl.Stats
}

// GetStats returns current statistics
func (r *Recursive) GetStats() Stats {
	s := Stats{
		Cache: r.cache.GetStats(),
		Pool:  r.workerPool.GetStats(),
	}

	if r.rrl != nil {
		rrlStats := r.rrl.GetStats()
		s.RRL = &rrlStats
	}

	return s
}
