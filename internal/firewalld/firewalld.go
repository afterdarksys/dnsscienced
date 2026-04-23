// Package firewalld implements the DNS Firewall (dnsfirewalld) for dnsscienced.
//
// It sits in the query-processing pipeline immediately after the protective-DNS
// blocklist check and before the cache/resolver.  For every inbound query it
// runs an ordered policy pipeline:
//
//  1. Static rules (config-driven, evaluated first)
//  2. Junk detection (DGA, DNS tunnels, random-subdomain bots)
//  3. Threat-intel scoring (IP rep, zone scores, customer metadata)
//  4. Starlark policy scripts (expressive, hot-reloadable)
//  5. Default action (allow / nxdomain / drop)
//
// Each stage may emit a Decision that short-circuits the remaining stages.
// Only the first decisive result is used.
package firewalld

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Verdict is the firewall decision for a query.
type Verdict int

const (
	VerdictAllow    Verdict = iota // pass through to resolver/cache
	VerdictNXDomain                // synthesise NXDOMAIN
	VerdictDrop                    // silently discard
	VerdictRewrite                 // CNAME-rewrite to Decision.Target
	VerdictRedirect                // forward to Decision.Server (upstream)
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "ALLOW"
	case VerdictNXDomain:
		return "NXDOMAIN"
	case VerdictDrop:
		return "DROP"
	case VerdictRewrite:
		return "REWRITE"
	case VerdictRedirect:
		return "REDIRECT"
	default:
		return "UNKNOWN"
	}
}

// Decision is the result of firewall evaluation for one query.
type Decision struct {
	Verdict Verdict
	// Target is the CNAME target when Verdict == VerdictRewrite.
	Target string
	// Server is "ip:port" when Verdict == VerdictRedirect.
	Server string
	// Reason is a short human-readable string logged with every non-ALLOW decision.
	Reason string
	// RuleName is the name of the rule or stage that produced this decision.
	RuleName string
}

// QueryContext carries per-query metadata through the pipeline.
type QueryContext struct {
	// Msg is the inbound DNS message.
	Msg *dns.Msg
	// ClientIP of the querying resolver or stub.
	ClientIP net.IP
	// Name is the FQDN being queried (lower-cased).
	Name string
	// Qtype is the numeric query type.
	Qtype uint16
	// CustomerID is populated from EDNS0 or server-side mapping.
	CustomerID string
}

// Firewall is the DNS firewall engine.
type Firewall struct {
	cfg      Config
	policy   *PolicyEngine
	junk     *JunkDetector
	intel    *ThreatIntel
	starlark  *StarlarkEngine
	forwarder *Forwarder
	pool      *UpstreamPool
	metrics   *Metrics
	logger   zerolog.Logger

	mu      sync.RWMutex
	enabled atomic.Bool

	// counters
	totalQueries   atomic.Uint64
	totalBlocked   atomic.Uint64
	totalNXDomain  atomic.Uint64
	totalDropped   atomic.Uint64
	totalRedirected atomic.Uint64
}

// New creates a Firewall from cfg.  Returns nil, nil when cfg.Enabled is false
// so callers can guard with a nil check without extra plumbing.
func New(cfg Config) (*Firewall, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "allow"
	}
	if cfg.ScriptTimeout == 0 {
		cfg.ScriptTimeout = DefaultConfig().ScriptTimeout
	}

	metrics := newMetrics()

	policy, err := newPolicyEngine(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf("firewalld: build policy engine: %w", err)
	}

	junk := newJunkDetector(cfg.Junk)
	intel := newThreatIntel(cfg.ThreatIntel)

	starlark, err := newStarlarkEngine(cfg.ScriptTimeout)
	if err != nil {
		return nil, fmt.Errorf("firewalld: build starlark engine: %w", err)
	}

	// Initialize upstream pool (D-10).
	pool := newUpstreamPool(cfg.Redirect.Upstreams)

	// Validate: if any rule has redirect action with empty redirect_server but pool is empty, fail fast.
	if len(cfg.Redirect.Upstreams) == 0 {
		for _, r := range cfg.Rules {
			if strings.ToLower(r.Action) == "redirect" && r.RedirectServer == "" {
				return nil, fmt.Errorf("firewalld: rule %q has redirect action but no redirect_server and firewall.redirect.upstreams is empty", r.Name)
			}
		}
	}

	// Load policy scripts from disk.
	for _, path := range cfg.PolicyScripts {
		if err := starlark.LoadFile(path); err != nil {
			return nil, fmt.Errorf("firewalld: load policy script %s: %w", path, err)
		}
	}

	fw := &Firewall{
		cfg:       cfg,
		policy:    policy,
		junk:      junk,
		intel:     intel,
		starlark:  starlark,
		forwarder: NewForwarder(cfg.ScriptTimeout * 1500), // generous: 3× script timeout
		pool:      pool,
		metrics:   metrics,
		logger:    log.With().Str("component", "firewalld").Logger(),
	}
	starlark.pool = pool // Wire pool into starlark engine (D-10, A1).
	fw.enabled.Store(true)

	fw.logger.Info().
		Int("static_rules", len(cfg.Rules)).
		Int("policy_scripts", len(cfg.PolicyScripts)).
		Bool("block_dga", cfg.Junk.BlockDGA).
		Bool("block_exfil", cfg.Junk.BlockDataExfil).
		Msg("DNS firewall started")

	return fw, nil
}

// Check evaluates inbound query r from clientIP and returns a Decision.
// It is safe for concurrent use.  The returned Decision is never nil.
func (fw *Firewall) Check(r *dns.Msg, clientIP net.IP) *Decision {
	if !fw.enabled.Load() || len(r.Question) == 0 {
		return allow()
	}

	fw.totalQueries.Add(1)
	fw.metrics.queriesTotal.Inc()

	q := r.Question[0]
	qctx := &QueryContext{
		Msg:      r,
		ClientIP: clientIP,
		Name:     strings.ToLower(q.Name),
		Qtype:    q.Qtype,
	}
	qctx.CustomerID = extractCustomerID(r, fw.logger)

	// 1. Static policy rules.
	if d := fw.policy.Evaluate(qctx); d.Verdict != VerdictAllow {
		if d.Verdict == VerdictRedirect && d.Server == "" {
			server, err := fw.pool.Next()
			if err != nil {
				fw.logger.Error().Err(err).Msg("redirect pool empty — returning SERVFAIL")
				fail := new(dns.Msg)
				fail.SetReply(r)
				fail.Rcode = dns.RcodeServerFailure
				return &Decision{Verdict: VerdictDrop, Reason: "pool empty"}
			}
			d.Server = server
		}
		return fw.record(d, qctx)
	}

	// 2. Junk detection.
	if d := fw.junk.Detect(qctx); d.Verdict != VerdictAllow {
		return fw.record(d, qctx)
	}

	// 3. Threat-intel scoring.
	score := fw.intel.Score(qctx)
	if score >= fw.cfg.ThreatIntel.BlockThreshold {
		d := &Decision{
			Verdict:  VerdictNXDomain,
			Reason:   fmt.Sprintf("threat score %d >= threshold %d", score, fw.cfg.ThreatIntel.BlockThreshold),
			RuleName: "threat_intel",
		}
		return fw.record(d, qctx)
	}

	// 4. Starlark policy scripts.
	if d := fw.starlark.Run(qctx, score); d.Verdict != VerdictAllow {
		return fw.record(d, qctx)
	}

	// 5. Default action.
	switch fw.cfg.DefaultAction {
	case "nxdomain":
		return fw.record(&Decision{Verdict: VerdictNXDomain, Reason: "default", RuleName: "default"}, qctx)
	case "drop":
		return fw.record(&Decision{Verdict: VerdictDrop, Reason: "default", RuleName: "default"}, qctx)
	default:
		fw.metrics.queriesAllowed.Inc()
		return allow()
	}
}

// Apply builds a DNS response from d.  Returns nil for VerdictAllow and
// VerdictRedirect (caller handles those).
func (fw *Firewall) Apply(r *dns.Msg, d *Decision) *dns.Msg {
	switch d.Verdict {
	case VerdictNXDomain:
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		m.Authoritative = true
		return m

	case VerdictRewrite:
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess
		if len(r.Question) > 0 {
			cname := &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: dns.Fqdn(d.Target),
			}
			m.Answer = append(m.Answer, cname)
		}
		return m

	default:
		return nil
	}
}

// Redirect forwards r to d.Server and returns the upstream response.
// Returns a SERVFAIL response if the upstream is unreachable.
func (fw *Firewall) Redirect(r *dns.Msg, d *Decision) *dns.Msg {
	resp, err := fw.forwarder.Forward(r, d.Server)
	if err != nil {
		fw.logger.Warn().Str("server", d.Server).Err(err).Msg("redirect forward failed")
		fail := new(dns.Msg)
		fail.SetReply(r)
		fail.Rcode = dns.RcodeServerFailure
		return fail
	}
	fw.totalRedirected.Add(1)
	return resp
}

// LoadScript hot-reloads a Starlark policy script by path.
func (fw *Firewall) LoadScript(path string) error {
	return fw.starlark.LoadFile(path)
}

// LoadSource compiles and registers a Starlark policy script from src string.
// id is the caller-supplied unique script identifier used to reference and remove the script.
func (fw *Firewall) LoadSource(id, src string) error {
	return fw.starlark.Load(id, src)
}

// RemoveScript removes a loaded Starlark script by its ID (path).
func (fw *Firewall) RemoveScript(id string) {
	fw.starlark.Remove(id)
}

// Stats returns a snapshot of firewall counters.
func (fw *Firewall) Stats() Stats {
	return Stats{
		TotalQueries:    fw.totalQueries.Load(),
		TotalBlocked:    fw.totalBlocked.Load(),
		TotalNXDomain:   fw.totalNXDomain.Load(),
		TotalDropped:    fw.totalDropped.Load(),
		TotalRedirected: fw.totalRedirected.Load(),
	}
}

// Stats is a snapshot of firewall counters.
type Stats struct {
	TotalQueries    uint64
	TotalBlocked    uint64
	TotalNXDomain   uint64
	TotalDropped    uint64
	TotalRedirected uint64
}

// ThreatIntelEngine exposes the live threat-intel scorer for external feed updates.
func (fw *Firewall) ThreatIntelEngine() *ThreatIntel {
	return fw.intel
}

// Shutdown disables the firewall and stops background goroutines.
func (fw *Firewall) Shutdown() {
	fw.enabled.Store(false)
	fw.logger.Info().Msg("DNS firewall stopped")
}

// record increments counters and logs the decision, then returns it.
func (fw *Firewall) record(d *Decision, qctx *QueryContext) *Decision {
	fw.totalBlocked.Add(1)
	fw.metrics.queriesBlocked.WithLabelValues(d.Verdict.String(), d.RuleName).Inc()

	switch d.Verdict {
	case VerdictNXDomain:
		fw.totalNXDomain.Add(1)
	case VerdictDrop:
		fw.totalDropped.Add(1)
	}

	fw.logger.Debug().
		Str("name", qctx.Name).
		Str("client", qctx.ClientIP.String()).
		Str("verdict", d.Verdict.String()).
		Str("rule", d.RuleName).
		Str("reason", d.Reason).
		Msg("firewall decision")

	return d
}

func allow() *Decision {
	return &Decision{Verdict: VerdictAllow}
}
