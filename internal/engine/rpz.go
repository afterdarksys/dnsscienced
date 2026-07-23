package engine

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// RPZAction represents the action to take when a query matches an RPZ rule.
type RPZAction int

const (
	RPZActionNone     RPZAction = iota // No match - continue normal processing
	RPZActionNXDomain                  // Return NXDOMAIN
	RPZActionNoData                    // Return empty answer (NOERROR but no data)
	RPZActionPassthru                  // Allow the query (whitelist)
	RPZActionDrop                      // Silently drop the query
	RPZActionRewrite                   // Rewrite to a different target
)

// String returns a human-readable representation of the RPZ action.
func (a RPZAction) String() string {
	switch a {
	case RPZActionNone:
		return "NONE"
	case RPZActionNXDomain:
		return "NXDOMAIN"
	case RPZActionNoData:
		return "NODATA"
	case RPZActionPassthru:
		return "PASSTHRU"
	case RPZActionDrop:
		return "DROP"
	case RPZActionRewrite:
		return "REWRITE"
	default:
		return "UNKNOWN"
	}
}

// RPZRule represents a single RPZ rule.
type RPZRule struct {
	Trigger         string    // The trigger domain (e.g., "malware.example.com.")
	Action          RPZAction // What to do when matched
	RewriteTarget   string    // Used only with RPZActionRewrite
	Reason          string    // Human-readable reason (e.g., "malware", "phishing")
	Zone            string    // RPZ zone that supplied the rule
	Source          string    // File or provider that supplied the rule
	descendantsOnly bool      // Standard *. RPZ owners do not match their apex
}

// RPZ implements Response Policy Zones for DNS filtering.
// It supports blocking, rewriting, and passthrough rules.
type RPZ struct {
	mu        sync.RWMutex
	rules     map[string]*RPZRule // Exact match rules
	wildcards map[string]*RPZRule // Wildcard rules (*.domain)
	regex     []rpzRegexRule
	name      string // Zone name for identification
	enabled   bool
}

type rpzRegexRule struct {
	expression *regexp.Regexp
	rule       *RPZRule
}

// NewRPZ creates a new RPZ instance.
func NewRPZ(name string) *RPZ {
	return &RPZ{
		rules:     make(map[string]*RPZRule),
		wildcards: make(map[string]*RPZRule),
		name:      name,
		enabled:   true,
	}
}

// AddRule adds an exact match rule to the RPZ.
func (r *RPZ) AddRule(trigger string, action RPZAction, reason string) {
	r.addRule(trigger, action, "", reason, "", false, false)
}

// AddWildcard adds a wildcard rule to the RPZ.
// The trigger should be the base domain (without the *. prefix).
func (r *RPZ) AddWildcard(trigger string, action RPZAction, reason string) {
	r.addRule(trigger, action, "", reason, "", true, false)
}

// AddRewriteRule adds a rule that rewrites queries to a different target.
func (r *RPZ) AddRewriteRule(trigger, target, reason string) {
	r.addRule(trigger, RPZActionRewrite, target, reason, "", false, false)
}

// AddPassthru adds a passthru (whitelist) rule that overrides blocking rules.
func (r *RPZ) AddPassthru(trigger, reason string) {
	r.addRule(trigger, RPZActionPassthru, "", reason, "", false, false)
}

// AddRegexRule adds a regular-expression QNAME policy. Expressions are
// evaluated against normalized lowercase FQDNs after exact and wildcard rules.
func (r *RPZ) AddRegexRule(
	pattern string,
	action RPZAction,
	rewriteTarget string,
	reason string,
	source string,
) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("RPZ regex pattern is required")
	}
	expression, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("compile RPZ regex %q: %w", pattern, err)
	}
	if action == RPZActionRewrite {
		if rewriteTarget == "" {
			return fmt.Errorf("RPZ regex rewrite %q requires a target", pattern)
		}
		rewriteTarget = dns.Fqdn(strings.ToLower(rewriteTarget))
	}
	rule := &RPZRule{
		Trigger:       pattern,
		Action:        action,
		RewriteTarget: rewriteTarget,
		Reason:        reason,
		Zone:          r.name,
		Source:        source,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.regex = append(r.regex, rpzRegexRule{expression: expression, rule: rule})
	return nil
}

func (r *RPZ) addRule(
	trigger string,
	action RPZAction,
	rewriteTarget string,
	reason string,
	source string,
	wildcard bool,
	descendantsOnly bool,
) {
	trigger = dns.Fqdn(strings.ToLower(trigger))
	if rewriteTarget != "" {
		rewriteTarget = dns.Fqdn(strings.ToLower(rewriteTarget))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rule := &RPZRule{
		Trigger:         trigger,
		Action:          action,
		RewriteTarget:   rewriteTarget,
		Reason:          reason,
		Zone:            r.name,
		Source:          source,
		descendantsOnly: descendantsOnly,
	}
	if wildcard {
		r.wildcards[trigger] = rule
		return
	}
	r.rules[trigger] = rule
}

// Check evaluates a query name against the RPZ rules.
// Returns the matching rule and action, or nil/RPZActionNone if no match.
func (r *RPZ) Check(name string) (*RPZRule, RPZAction) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.enabled {
		return nil, RPZActionNone
	}

	name = dns.Fqdn(strings.ToLower(name))

	// 1. Check exact match first
	if rule, ok := r.rules[name]; ok {
		recordRPZHit(rule)
		return rule, rule.Action
	}

	// 2. Check wildcards by walking up the label tree
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels); i++ {
		wildcard := dns.Fqdn(strings.Join(labels[i:], "."))
		if rule, ok := r.wildcards[wildcard]; ok {
			if rule.descendantsOnly && wildcard == name {
				continue
			}
			recordRPZHit(rule)
			return rule, rule.Action
		}
	}

	for _, candidate := range r.regex {
		if candidate.expression.MatchString(name) {
			recordRPZHit(candidate.rule)
			return candidate.rule, candidate.rule.Action
		}
	}

	return nil, RPZActionNone
}

// ApplyToResponse modifies a DNS response based on RPZ rules.
// Returns true if the response was modified.
func (r *RPZ) ApplyToResponse(msg *dns.Msg) bool {
	if len(msg.Question) == 0 {
		return false
	}

	rule, action := r.Check(msg.Question[0].Name)
	if rule == nil {
		return false
	}

	switch action {
	case RPZActionNXDomain:
		msg.Rcode = dns.RcodeNameError
		msg.Answer = nil
		msg.Ns = nil
		msg.Extra = nil
		return true

	case RPZActionNoData:
		msg.Rcode = dns.RcodeSuccess
		msg.Answer = nil
		return true

	case RPZActionPassthru:
		// Allow the query to proceed normally
		return false

	case RPZActionRewrite:
		// Rewrite the answer to point to the target
		if rule.RewriteTarget != "" {
			msg.Answer = nil
			// Add a CNAME pointing to the rewrite target
			cname := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: rule.RewriteTarget,
			}
			msg.Answer = append(msg.Answer, cname)
			return true
		}
	}

	return false
}

// Enable enables RPZ processing.
func (r *RPZ) Enable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = true
}

// Disable disables RPZ processing.
func (r *RPZ) Disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = false
}

// Clear removes all rules from the RPZ.
func (r *RPZ) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = make(map[string]*RPZRule)
	r.wildcards = make(map[string]*RPZRule)
	r.regex = nil
}

// Stats returns statistics about the RPZ.
func (r *RPZ) Stats() RPZStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return RPZStats{
		Name:          r.name,
		Enabled:       r.enabled,
		ExactRules:    len(r.rules),
		WildcardRules: len(r.wildcards),
		RegexRules:    len(r.regex),
	}
}

// RPZStats holds statistics about an RPZ.
type RPZStats struct {
	Name          string
	Enabled       bool
	ExactRules    int
	WildcardRules int
	RegexRules    int
}

// RPZAggregate manages multiple RPZ zones with priority ordering.
type RPZAggregate struct {
	mu    sync.RWMutex
	zones []*RPZ
}

// NewRPZAggregate creates a new RPZ aggregate.
func NewRPZAggregate() *RPZAggregate {
	return &RPZAggregate{
		zones: make([]*RPZ, 0),
	}
}

// AddZone adds an RPZ zone to the aggregate.
// Zones are checked in the order they are added (first match wins).
func (a *RPZAggregate) AddZone(rpz *RPZ) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.zones = append(a.zones, rpz)
}

// Check evaluates a query against all RPZ zones.
func (a *RPZAggregate) Check(name string) (*RPZRule, RPZAction) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, rpz := range a.zones {
		if rule, action := rpz.Check(name); action != RPZActionNone {
			return rule, action
		}
	}
	return nil, RPZActionNone
}

// Stats returns a stable snapshot of all configured RPZ zones in precedence
// order.
func (a *RPZAggregate) Stats() []RPZStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := make([]RPZStats, 0, len(a.zones))
	for _, rpz := range a.zones {
		stats = append(stats, rpz.Stats())
	}
	return stats
}
