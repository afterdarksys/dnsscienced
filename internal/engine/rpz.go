package engine

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

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
	mu                  sync.RWMutex
	rules               map[string]*RPZRule // Exact match rules
	wildcards           map[string]*RPZRule // Wildcard rules (*.domain)
	nsDNameRules        map[string]*RPZRule
	nsDNameWildcards    map[string]*RPZRule
	nsDNameRuleCount    int
	regex               []rpzRegexRule
	responseIPv4        [33]map[netip.Addr]*RPZRule
	responseIPv6        [129]map[netip.Addr]*RPZRule
	responseIPv4Lengths []int
	responseIPv6Lengths []int
	responseIPRules     int
	clientIPv4          [33]map[netip.Addr]*RPZRule
	clientIPv6          [129]map[netip.Addr]*RPZRule
	clientIPv4Lengths   []int
	clientIPv6Lengths   []int
	clientIPRules       int
	nsIPv4              [33]map[netip.Addr]*RPZRule
	nsIPv6              [129]map[netip.Addr]*RPZRule
	nsIPv4Lengths       []int
	nsIPv6Lengths       []int
	nsIPRules           int
	name                string // Zone name for identification
	enabled             bool
}

// RPZNameserverData is the truthful nameserver data path used by NSDNAME and
// NSIP triggers. Names and addresses may come from parent-side delegation/glue
// or authoritative NS/A/AAAA lookups; both are permitted by the RPZ protocol.
type RPZNameserverData struct {
	Names     []string
	Addresses []netip.Addr
}

type rpzRegexRule struct {
	expression *regexp.Regexp
	rule       *RPZRule
}

// NewRPZ creates a new RPZ instance.
func NewRPZ(name string) *RPZ {
	return &RPZ{
		rules:            make(map[string]*RPZRule),
		wildcards:        make(map[string]*RPZRule),
		nsDNameRules:     make(map[string]*RPZRule),
		nsDNameWildcards: make(map[string]*RPZRule),
		name:             name,
		enabled:          true,
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

// AddResponseIPRule adds an RPZ-IP prefix rule. The prefix must be canonical;
// malformed host bits are rejected by the zone-file loader.
func (r *RPZ) AddResponseIPRule(
	prefix netip.Prefix,
	action RPZAction,
	rewriteTarget string,
	reason string,
	source string,
) error {
	if !prefix.IsValid() || prefix.Bits() < 1 ||
		(prefix.Addr().Is4() && prefix.Bits() > 32) ||
		(!prefix.Addr().Is4() && prefix.Bits() > 128) {
		return fmt.Errorf("invalid RPZ-IP prefix %v", prefix)
	}
	prefix = prefix.Masked()
	if rewriteTarget != "" {
		rewriteTarget = dns.Fqdn(strings.ToLower(rewriteTarget))
	}
	rule := &RPZRule{
		Trigger:       prefix.String(),
		Action:        action,
		RewriteTarget: rewriteTarget,
		Reason:        reason,
		Zone:          r.name,
		Source:        source,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	lengths := &r.responseIPv6Lengths
	table := r.responseIPv6[:]
	if prefix.Addr().Is4() {
		lengths = &r.responseIPv4Lengths
		table = r.responseIPv4[:]
	}
	bits := prefix.Bits()
	if table[bits] == nil {
		table[bits] = make(map[netip.Addr]*RPZRule)
		*lengths = append(*lengths, bits)
		sort.Sort(sort.Reverse(sort.IntSlice(*lengths)))
	}
	if _, exists := table[bits][prefix.Addr()]; !exists {
		r.responseIPRules++
	}
	table[bits][prefix.Addr()] = rule
	return nil
}

// AddClientIPRule adds an RPZ-CLIENT-IP prefix rule.
func (r *RPZ) AddClientIPRule(
	prefix netip.Prefix,
	action RPZAction,
	rewriteTarget string,
	reason string,
	source string,
) error {
	if !prefix.IsValid() || prefix.Bits() < 1 ||
		(prefix.Addr().Is4() && prefix.Bits() > 32) ||
		(!prefix.Addr().Is4() && prefix.Bits() > 128) {
		return fmt.Errorf("invalid RPZ-CLIENT-IP prefix %v", prefix)
	}
	prefix = prefix.Masked()
	if rewriteTarget != "" {
		rewriteTarget = dns.Fqdn(strings.ToLower(rewriteTarget))
	}
	rule := &RPZRule{
		Trigger:       prefix.String(),
		Action:        action,
		RewriteTarget: rewriteTarget,
		Reason:        reason,
		Zone:          r.name,
		Source:        source,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	lengths := &r.clientIPv6Lengths
	table := r.clientIPv6[:]
	if prefix.Addr().Is4() {
		lengths = &r.clientIPv4Lengths
		table = r.clientIPv4[:]
	}
	bits := prefix.Bits()
	if table[bits] == nil {
		table[bits] = make(map[netip.Addr]*RPZRule)
		*lengths = append(*lengths, bits)
		sort.Sort(sort.Reverse(sort.IntSlice(*lengths)))
	}
	if _, exists := table[bits][prefix.Addr()]; !exists {
		r.clientIPRules++
	}
	table[bits][prefix.Addr()] = rule
	return nil
}

// AddNSDNameRule adds an RPZ-NSDNAME exact or wildcard trigger.
func (r *RPZ) AddNSDNameRule(
	trigger string,
	action RPZAction,
	rewriteTarget string,
	reason string,
	source string,
	wildcard bool,
) {
	trigger = dns.Fqdn(strings.ToLower(trigger))
	if rewriteTarget != "" {
		rewriteTarget = dns.Fqdn(strings.ToLower(rewriteTarget))
	}
	rule := &RPZRule{
		Trigger:         trigger,
		Action:          action,
		RewriteTarget:   rewriteTarget,
		Reason:          reason,
		Zone:            r.name,
		Source:          source,
		descendantsOnly: wildcard,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	table := r.nsDNameRules
	if wildcard {
		table = r.nsDNameWildcards
	}
	if _, exists := table[trigger]; !exists {
		r.nsDNameRuleCount++
	}
	table[trigger] = rule
}

// AddNSIPRule adds an RPZ-NSIP prefix rule.
func (r *RPZ) AddNSIPRule(
	prefix netip.Prefix,
	action RPZAction,
	rewriteTarget string,
	reason string,
	source string,
) error {
	if !prefix.IsValid() || prefix.Bits() < 1 ||
		(prefix.Addr().Is4() && prefix.Bits() > 32) ||
		(!prefix.Addr().Is4() && prefix.Bits() > 128) {
		return fmt.Errorf("invalid RPZ-NSIP prefix %v", prefix)
	}
	prefix = prefix.Masked()
	if rewriteTarget != "" {
		rewriteTarget = dns.Fqdn(strings.ToLower(rewriteTarget))
	}
	rule := &RPZRule{
		Trigger:       prefix.String(),
		Action:        action,
		RewriteTarget: rewriteTarget,
		Reason:        reason,
		Zone:          r.name,
		Source:        source,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	lengths := &r.nsIPv6Lengths
	table := r.nsIPv6[:]
	if prefix.Addr().Is4() {
		lengths = &r.nsIPv4Lengths
		table = r.nsIPv4[:]
	}
	bits := prefix.Bits()
	if table[bits] == nil {
		table[bits] = make(map[netip.Addr]*RPZRule)
		*lengths = append(*lengths, bits)
		sort.Sort(sort.Reverse(sort.IntSlice(*lengths)))
	}
	if _, exists := table[bits][prefix.Addr()]; !exists {
		r.nsIPRules++
	}
	table[bits][prefix.Addr()] = rule
	return nil
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
	return r.checkName(name, true)
}

func (r *RPZ) checkName(name string, recordHit bool) (*RPZRule, RPZAction) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.enabled {
		return nil, RPZActionNone
	}

	name = dns.Fqdn(strings.ToLower(name))

	// 1. Check exact match first
	if rule, ok := r.rules[name]; ok {
		if recordHit {
			recordRPZHit(rule)
		}
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
			if recordHit {
				recordRPZHit(rule)
			}
			return rule, rule.Action
		}
	}

	for _, candidate := range r.regex {
		if candidate.expression.MatchString(name) {
			if recordHit {
				recordRPZHit(candidate.rule)
			}
			return candidate.rule, candidate.rule.Action
		}
	}

	return nil, RPZActionNone
}

// HasResponseDependentRules reports whether this zone can only be decided
// after a truthful answer and, potentially, its nameserver data path exist.
func (r *RPZ) HasResponseDependentRules() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled &&
		(r.responseIPRules != 0 || r.nsDNameRuleCount != 0 || r.nsIPRules != 0)
}

// NameserverRequirements reports which expensive nameserver data is needed.
func (r *RPZ) NameserverRequirements() (names bool, addresses bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled && r.nsDNameRuleCount != 0, r.enabled && r.nsIPRules != 0
}

func (r *RPZ) checkClientIP(client netip.Addr, recordHit bool) (*RPZRule, RPZAction) {
	if !client.IsValid() {
		return nil, RPZActionNone
	}
	client = client.Unmap()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.enabled || r.clientIPRules == 0 {
		return nil, RPZActionNone
	}
	rule, _, ok := rpzIPMatch(
		client,
		r.clientIPv4[:],
		r.clientIPv6[:],
		r.clientIPv4Lengths,
		r.clientIPv6Lengths,
	)
	if !ok {
		return nil, RPZActionNone
	}
	if recordHit {
		recordRPZHit(rule)
	}
	return rule, rule.Action
}

// CheckResponse evaluates QNAME and RPZ-IP without nameserver-path data.
func (r *RPZ) CheckResponse(name string, msg *dns.Msg) (*RPZRule, RPZAction) {
	return r.CheckResponseWithNameservers(name, msg, nil)
}

// CheckResponseWithNameservers evaluates all response-dependent triggers in
// protocol precedence order: QNAME, response-IP, NSDNAME, then NSIP.
func (r *RPZ) CheckResponseWithNameservers(
	name string,
	msg *dns.Msg,
	nameservers *RPZNameserverData,
) (*RPZRule, RPZAction) {
	if rule, action := r.Check(name); action != RPZActionNone {
		return rule, action
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.enabled {
		return nil, RPZActionNone
	}

	if best := r.matchResponseIPLocked(msg); best != nil {
		recordRPZHit(best)
		return best, best.Action
	}
	if nameservers == nil {
		return nil, RPZActionNone
	}
	if best := r.matchNSDNameLocked(nameservers.Names); best != nil {
		recordRPZHit(best)
		return best, best.Action
	}
	if best := r.matchNSIPLocked(nameservers.Addresses); best != nil {
		recordRPZHit(best)
		return best, best.Action
	}
	return nil, RPZActionNone
}

func (r *RPZ) matchResponseIPLocked(msg *dns.Msg) *RPZRule {
	if r.responseIPRules == 0 {
		return nil
	}
	return bestRPZIPRule(
		msg.Answer,
		r.responseIPv4[:],
		r.responseIPv6[:],
		r.responseIPv4Lengths,
		r.responseIPv6Lengths,
	)
}

func bestRPZIPRule(
	records []dns.RR,
	ipv4 []map[netip.Addr]*RPZRule,
	ipv6 []map[netip.Addr]*RPZRule,
	ipv4Lengths []int,
	ipv6Lengths []int,
) *RPZRule {
	var best *RPZRule
	bestInternalBits := -1
	var bestAddress [16]byte
	for _, rr := range records {
		var addr netip.Addr
		switch record := rr.(type) {
		case *dns.A:
			ip := record.A.To4()
			if ip == nil {
				continue
			}
			var octets [4]byte
			copy(octets[:], ip)
			addr = netip.AddrFrom4(octets)
		case *dns.AAAA:
			parsed, ok := netip.AddrFromSlice(record.AAAA)
			if !ok {
				continue
			}
			addr = parsed
		default:
			continue
		}
		rule, prefix, ok := rpzIPMatch(
			addr,
			ipv4,
			ipv6,
			ipv4Lengths,
			ipv6Lengths,
		)
		if !ok {
			continue
		}
		internalBits := prefix.Bits()
		if addr.Is4() {
			internalBits += 96
		}
		address := rpzComparableAddress(prefix.Addr())
		if best == nil ||
			internalBits > bestInternalBits ||
			(internalBits == bestInternalBits && bytes.Compare(address[:], bestAddress[:]) < 0) {
			best = rule
			bestInternalBits = internalBits
			bestAddress = address
		}
	}
	return best
}

func (r *RPZ) matchNSDNameLocked(names []string) *RPZRule {
	if r.nsDNameRuleCount == 0 {
		return nil
	}
	var best *RPZRule
	bestName := ""
	bestExact := false
	bestLabels := -1
	for _, name := range names {
		normalized := dns.Fqdn(strings.ToLower(name))
		rule, exact, labels := rpzNameMatch(
			normalized,
			r.nsDNameRules,
			r.nsDNameWildcards,
		)
		if rule != nil && (best == nil ||
			(exact && !bestExact) ||
			(exact == bestExact && labels > bestLabels) ||
			(exact == bestExact && labels == bestLabels &&
				rpzCanonicalNameLess(bestName, normalized))) {
			best = rule
			bestName = normalized
			bestExact = exact
			bestLabels = labels
		}
	}
	return best
}

func rpzNameMatch(
	name string,
	exact map[string]*RPZRule,
	wildcards map[string]*RPZRule,
) (*RPZRule, bool, int) {
	if rule := exact[name]; rule != nil {
		return rule, true, dns.CountLabel(name)
	}
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels); i++ {
		suffix := dns.Fqdn(strings.Join(labels[i:], "."))
		if rule := wildcards[suffix]; rule != nil && suffix != name {
			return rule, false, dns.CountLabel(suffix)
		}
	}
	return nil, false, 0
}

// rpzCanonicalNameLess implements RFC 4034 section 6.1 canonical DNS name
// ordering. RPZ selects the matched NS name appearing last in this order.
func rpzCanonicalNameLess(left, right string) bool {
	leftLabels := dns.SplitDomainName(strings.ToLower(left))
	rightLabels := dns.SplitDomainName(strings.ToLower(right))
	for li, ri := len(leftLabels)-1, len(rightLabels)-1; li >= 0 && ri >= 0; li, ri = li-1, ri-1 {
		if comparison := bytes.Compare([]byte(leftLabels[li]), []byte(rightLabels[ri])); comparison != 0 {
			return comparison < 0
		}
	}
	return len(leftLabels) < len(rightLabels)
}

func (r *RPZ) matchNSIPLocked(addresses []netip.Addr) *RPZRule {
	if r.nsIPRules == 0 {
		return nil
	}
	records := make([]dns.RR, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() {
			continue
		}
		if address.Is4() {
			octets := address.As4()
			records = append(records, &dns.A{A: append([]byte(nil), octets[:]...)})
		} else {
			octets := address.As16()
			records = append(records, &dns.AAAA{AAAA: append([]byte(nil), octets[:]...)})
		}
	}
	return bestRPZIPRule(
		records,
		r.nsIPv4[:],
		r.nsIPv6[:],
		r.nsIPv4Lengths,
		r.nsIPv6Lengths,
	)
}

func rpzIPMatch(
	addr netip.Addr,
	ipv4 []map[netip.Addr]*RPZRule,
	ipv6 []map[netip.Addr]*RPZRule,
	ipv4Lengths []int,
	ipv6Lengths []int,
) (*RPZRule, netip.Prefix, bool) {
	lengths := ipv6Lengths
	table := ipv6
	if addr.Is4() {
		lengths = ipv4Lengths
		table = ipv4
	}
	for _, bits := range lengths {
		prefix := netip.PrefixFrom(addr, bits).Masked()
		if rule := table[bits][prefix.Addr()]; rule != nil {
			return rule, prefix, true
		}
	}
	return nil, netip.Prefix{}, false
}

func rpzComparableAddress(addr netip.Addr) [16]byte {
	if !addr.Is4() {
		return addr.As16()
	}
	var result [16]byte
	v4 := addr.As4()
	copy(result[12:], v4[:])
	return result
}

// ApplyToResponse modifies a DNS response based on RPZ rules.
// Returns true if the response was modified.
func (r *RPZ) ApplyToResponse(msg *dns.Msg) bool {
	if len(msg.Question) == 0 {
		return false
	}

	rule, action := r.CheckResponse(msg.Question[0].Name, msg)
	if rule == nil {
		return false
	}

	switch action {
	case RPZActionNXDomain:
		msg.Rcode = dns.RcodeNameError
		msg.Answer = nil
		msg.Ns = nil
		msg.Extra = nil
		msg.AuthenticatedData = false
		return true

	case RPZActionNoData:
		msg.Rcode = dns.RcodeSuccess
		msg.Answer = nil
		msg.Ns = nil
		msg.Extra = nil
		msg.AuthenticatedData = false
		return true

	case RPZActionPassthru:
		// Allow the query to proceed normally
		return false

	case RPZActionRewrite:
		// Rewrite the answer to point to the target
		if rule.RewriteTarget != "" {
			msg.Answer = nil
			msg.Ns = nil
			msg.Extra = nil
			msg.AuthenticatedData = false
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
	r.nsDNameRules = make(map[string]*RPZRule)
	r.nsDNameWildcards = make(map[string]*RPZRule)
	r.nsDNameRuleCount = 0
	r.regex = nil
	r.responseIPv4 = [33]map[netip.Addr]*RPZRule{}
	r.responseIPv6 = [129]map[netip.Addr]*RPZRule{}
	r.responseIPv4Lengths = nil
	r.responseIPv6Lengths = nil
	r.responseIPRules = 0
	r.clientIPv4 = [33]map[netip.Addr]*RPZRule{}
	r.clientIPv6 = [129]map[netip.Addr]*RPZRule{}
	r.clientIPv4Lengths = nil
	r.clientIPv6Lengths = nil
	r.clientIPRules = 0
	r.nsIPv4 = [33]map[netip.Addr]*RPZRule{}
	r.nsIPv6 = [129]map[netip.Addr]*RPZRule{}
	r.nsIPv4Lengths = nil
	r.nsIPv6Lengths = nil
	r.nsIPRules = 0
}

// Stats returns statistics about the RPZ.
func (r *RPZ) Stats() RPZStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return RPZStats{
		Name:            r.name,
		Enabled:         r.enabled,
		ExactRules:      len(r.rules),
		WildcardRules:   len(r.wildcards),
		RegexRules:      len(r.regex),
		ResponseIPRules: r.responseIPRules,
		ClientIPRules:   r.clientIPRules,
		NSDNameRules:    r.nsDNameRuleCount,
		NSIPRules:       r.nsIPRules,
	}
}

// RPZStats holds statistics about an RPZ.
type RPZStats struct {
	Name            string
	Enabled         bool
	ExactRules      int
	WildcardRules   int
	RegexRules      int
	ResponseIPRules int
	ClientIPRules   int
	NSDNameRules    int
	NSIPRules       int
}

// RPZAggregate manages multiple RPZ zones with priority ordering.
type RPZAggregate struct {
	mu                sync.RWMutex
	zones             []*RPZ
	minNSDots         int
	maxNSLookups      int
	nameserverTimeout time.Duration
}

// NewRPZAggregate creates a new RPZ aggregate.
func NewRPZAggregate() *RPZAggregate {
	return &RPZAggregate{
		zones:             make([]*RPZ, 0),
		minNSDots:         1,
		maxNSLookups:      64,
		nameserverTimeout: 2 * time.Second,
	}
}

// SetNameserverDiscovery configures the bounded NSDNAME/NSIP data-path walk.
func (a *RPZAggregate) SetNameserverDiscovery(
	minNSDots int,
	maxLookups int,
	timeout time.Duration,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.minNSDots = minNSDots
	a.maxNSLookups = maxLookups
	a.nameserverTimeout = timeout
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

// CheckQueryShortcut returns a query-only result when it is safe to decide
// before resolution. A QNAME match in a later zone must wait if an earlier
// zone contains RPZ-IP rules that could take precedence.
func (a *RPZAggregate) CheckQueryShortcut(name string) (*RPZRule, RPZAction, bool) {
	return a.CheckRequestShortcut(name, netip.Addr{})
}

// CheckRequestShortcut evaluates client-IP and QNAME triggers that can be
// decided without a truthful response.
func (a *RPZAggregate) CheckRequestShortcut(
	name string,
	client netip.Addr,
) (*RPZRule, RPZAction, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	priorResponseRules := false
	for _, rpz := range a.zones {
		if rule, action := rpz.checkClientIP(client, false); action != RPZActionNone {
			if priorResponseRules {
				return nil, RPZActionNone, false
			}
			recordRPZHit(rule)
			return rule, action, true
		}
		if rule, action := rpz.checkName(name, false); action != RPZActionNone {
			if priorResponseRules {
				return nil, RPZActionNone, false
			}
			recordRPZHit(rule)
			return rule, action, true
		}
		if rpz.HasResponseDependentRules() {
			priorResponseRules = true
		}
	}
	return nil, RPZActionNone, !priorResponseRules
}

// CheckResponse applies RPZ ordering first and trigger-type ordering second:
// each zone gets a QNAME check followed by its RPZ-IP check before the next
// lower-priority zone is considered.
func (a *RPZAggregate) CheckResponse(name string, msg *dns.Msg) (*RPZRule, RPZAction) {
	return a.CheckRequestResponse(name, netip.Addr{}, msg)
}

// CheckRequestResponse applies response-stage triggers that do not require a
// nameserver path. If an earlier zone needs NSDNAME/NSIP data, it returns no
// match rather than incorrectly allowing a later zone to bypass it.
func (a *RPZAggregate) CheckRequestResponse(
	name string,
	client netip.Addr,
	msg *dns.Msg,
) (*RPZRule, RPZAction) {
	rule, action, decisive := a.CheckRequestResponseShortcut(name, client, msg)
	if !decisive {
		return nil, RPZActionNone
	}
	return rule, action
}

// CheckRequestResponseShortcut returns a response-stage result without
// nameserver discovery when trigger and zone precedence make that result
// final. It stops at the first zone containing NSDNAME/NSIP rules if no
// higher-precedence trigger in that zone matched.
func (a *RPZAggregate) CheckRequestResponseShortcut(
	name string,
	client netip.Addr,
	msg *dns.Msg,
) (*RPZRule, RPZAction, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, rpz := range a.zones {
		if rule, action := rpz.checkClientIP(client, true); action != RPZActionNone {
			return rule, action, true
		}
		if rule, action := rpz.checkName(name, true); action != RPZActionNone {
			return rule, action, true
		}
		rpz.mu.RLock()
		responseRule := rpz.matchResponseIPLocked(msg)
		needsNameservers := rpz.enabled &&
			(rpz.nsDNameRuleCount != 0 || rpz.nsIPRules != 0)
		rpz.mu.RUnlock()
		if responseRule != nil {
			recordRPZHit(responseRule)
			return responseRule, responseRule.Action, true
		}
		if needsNameservers {
			return nil, RPZActionNone, false
		}
	}
	return nil, RPZActionNone, true
}

// CheckRequestResponseWithNameservers applies complete trigger precedence.
func (a *RPZAggregate) CheckRequestResponseWithNameservers(
	name string,
	client netip.Addr,
	msg *dns.Msg,
	nameservers *RPZNameserverData,
) (*RPZRule, RPZAction) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, rpz := range a.zones {
		if rule, action := rpz.checkClientIP(client, true); action != RPZActionNone {
			return rule, action
		}
		if rule, action := rpz.CheckResponseWithNameservers(name, msg, nameservers); action != RPZActionNone {
			return rule, action
		}
	}
	return nil, RPZActionNone
}

// NameserverRequirements reports whether any active zone needs NS names or
// addresses. It lets the server avoid nameserver-path discovery for ordinary
// RPZ configurations.
type RPZNameserverRequirements struct {
	Names      bool
	Addresses  bool
	MinNSDots  int
	MaxLookups int
	Timeout    time.Duration
}

func (a *RPZAggregate) NameserverRequirements() RPZNameserverRequirements {
	a.mu.RLock()
	defer a.mu.RUnlock()
	requirements := RPZNameserverRequirements{
		MinNSDots:  a.minNSDots,
		MaxLookups: a.maxNSLookups,
		Timeout:    a.nameserverTimeout,
	}
	for _, rpz := range a.zones {
		zoneNames, zoneAddresses := rpz.NameserverRequirements()
		requirements.Names = requirements.Names || zoneNames
		requirements.Addresses = requirements.Addresses || zoneAddresses
	}
	return requirements
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
