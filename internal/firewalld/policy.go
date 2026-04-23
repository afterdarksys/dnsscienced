package firewalld

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// PolicyEngine evaluates static rules in declaration order.
// The first matching rule wins; unmatched queries get VerdictAllow.
type PolicyEngine struct {
	rules []compiledRule
}

type compiledRule struct {
	cfg    RuleConfig
	net    *net.IPNet // compiled ClientCIDR, nil means any
	qtype  uint16     // 0 means any
	verdict Verdict
}

func newPolicyEngine(rules []RuleConfig) (*PolicyEngine, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		compiled = append(compiled, cr)
	}
	return &PolicyEngine{rules: compiled}, nil
}

func compileRule(r RuleConfig) (compiledRule, error) {
	cr := compiledRule{cfg: r}

	// Parse CIDR.
	if r.Match.ClientCIDR != "" {
		_, ipnet, err := net.ParseCIDR(r.Match.ClientCIDR)
		if err != nil {
			return cr, fmt.Errorf("invalid client_cidr %q: %w", r.Match.ClientCIDR, err)
		}
		cr.net = ipnet
	}

	// Parse query type.
	if r.Match.QueryType != "" {
		t, ok := dns.StringToType[strings.ToUpper(r.Match.QueryType)]
		if !ok {
			return cr, fmt.Errorf("unknown query type %q", r.Match.QueryType)
		}
		cr.qtype = t
	}

	// Parse verdict.
	switch strings.ToLower(r.Action) {
	case "allow":
		cr.verdict = VerdictAllow
	case "nxdomain":
		cr.verdict = VerdictNXDomain
	case "drop":
		cr.verdict = VerdictDrop
	case "rewrite":
		if r.RewriteTarget == "" {
			return cr, fmt.Errorf("rewrite action requires rewrite_target")
		}
		cr.verdict = VerdictRewrite
	case "redirect":
		cr.verdict = VerdictRedirect
		// redirect_server is optional; empty means use the global upstream pool (D-07).
	case "":
		return cr, fmt.Errorf("action is required")
	default:
		return cr, fmt.Errorf("unknown action %q", r.Action)
	}

	return cr, nil
}

// Evaluate returns the first matching rule's decision or VerdictAllow.
func (pe *PolicyEngine) Evaluate(qctx *QueryContext) *Decision {
	for i := range pe.rules {
		cr := &pe.rules[i]
		if cr.matches(qctx) {
			return &Decision{
				Verdict:  cr.verdict,
				Target:   cr.cfg.RewriteTarget,
				Server:   cr.cfg.RedirectServer,
				Reason:   fmt.Sprintf("static rule %q matched", cr.cfg.Name),
				RuleName: cr.cfg.Name,
			}
		}
	}
	return allow()
}

func (cr *compiledRule) matches(qctx *QueryContext) bool {
	m := &cr.cfg.Match

	// Domain suffix.
	if m.DomainSuffix != "" {
		suffix := dns.Fqdn(strings.ToLower(m.DomainSuffix))
		if !strings.HasSuffix(qctx.Name, suffix) {
			return false
		}
	}

	// Exact domain.
	if m.DomainExact != "" {
		want := dns.Fqdn(strings.ToLower(m.DomainExact))
		if qctx.Name != want {
			return false
		}
	}

	// Client CIDR.
	if cr.net != nil && !cr.net.Contains(qctx.ClientIP) {
		return false
	}

	// Query type.
	if cr.qtype != 0 && qctx.Qtype != cr.qtype {
		return false
	}

	// IsJunk flag — skip here; junk detection runs as its own stage.
	// If a rule sets IsJunk, that rule matches only after junk detection
	// signals positive.  We handle this by re-evaluating rules inside
	// the junk stage (see JunkDetector.Detect).

	return true
}
