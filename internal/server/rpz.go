package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dnsscience/dnsscienced/internal/ede"
	"github.com/dnsscience/dnsscienced/internal/engine"
	"github.com/miekg/dns"
)

// RPZConfig controls production response-policy-zone loading.
type RPZConfig struct {
	Enabled bool            `yaml:"enabled"`
	Zones   []RPZZoneConfig `yaml:"zones"`
}

// RPZZoneConfig identifies one policy source. Lower priority values are
// evaluated first; list order breaks ties.
type RPZZoneConfig struct {
	Name       string               `yaml:"name"`
	File       string               `yaml:"file,omitempty"`
	Reason     string               `yaml:"reason,omitempty"`
	Priority   int                  `yaml:"priority,omitempty"`
	RegexRules []RPZRegexRuleConfig `yaml:"regex_rules,omitempty"`
}

// RPZRegexRuleConfig adds a regex policy after the zone's exact and wildcard
// rules. Action is one of nxdomain, nodata, passthru, drop, or rewrite.
type RPZRegexRuleConfig struct {
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"`
	Target  string `yaml:"target,omitempty"`
	Reason  string `yaml:"reason,omitempty"`
}

// ReloadRPZ parses every configured policy before atomically replacing the
// active aggregate. A malformed reload leaves the last valid policy active.
func (s *Server) ReloadRPZ(cfg RPZConfig) error {
	if !cfg.Enabled {
		s.rpz.Store(nil)
		s.cfg.RPZ = cfg
		return nil
	}
	if len(cfg.Zones) == 0 {
		return fmt.Errorf("enabled but no policy zones are configured")
	}

	zones := append([]RPZZoneConfig(nil), cfg.Zones...)
	sort.SliceStable(zones, func(i, j int) bool {
		return zones[i].Priority < zones[j].Priority
	})

	aggregate := engine.NewRPZAggregate()
	seen := make(map[string]struct{}, len(zones))
	for i, zoneCfg := range zones {
		name := strings.TrimSpace(zoneCfg.Name)
		if name == "" {
			return fmt.Errorf("zone %d: name is required", i)
		}
		if zoneCfg.File == "" && len(zoneCfg.RegexRules) == 0 {
			return fmt.Errorf("zone %q: file or regex_rules is required", name)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate RPZ zone name %q", name)
		}
		seen[key] = struct{}{}

		var policy *engine.RPZ
		if zoneCfg.File != "" {
			var err error
			policy, err = engine.LoadRPZFile(name, zoneCfg.File, zoneCfg.Reason)
			if err != nil {
				return fmt.Errorf("zone %q: %w", name, err)
			}
		} else {
			policy = engine.NewRPZ(name)
		}
		for ruleIndex, regexCfg := range zoneCfg.RegexRules {
			action, err := parseRPZAction(regexCfg.Action)
			if err != nil {
				return fmt.Errorf("zone %q regex rule %d: %w", name, ruleIndex, err)
			}
			reason := regexCfg.Reason
			if reason == "" {
				reason = zoneCfg.Reason
			}
			if err := policy.AddRegexRule(
				regexCfg.Pattern,
				action,
				regexCfg.Target,
				reason,
				"config:"+name,
			); err != nil {
				return fmt.Errorf("zone %q regex rule %d: %w", name, ruleIndex, err)
			}
		}
		aggregate.AddZone(policy)
	}

	s.rpz.Store(aggregate)
	s.cfg.RPZ = cfg
	return nil
}

func parseRPZAction(value string) (engine.RPZAction, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "nxdomain":
		return engine.RPZActionNXDomain, nil
	case "nodata":
		return engine.RPZActionNoData, nil
	case "passthru", "allow":
		return engine.RPZActionPassthru, nil
	case "drop":
		return engine.RPZActionDrop, nil
	case "rewrite":
		return engine.RPZActionRewrite, nil
	default:
		return engine.RPZActionNone, fmt.Errorf("unknown action %q", value)
	}
}

// GetRPZStats returns the active policy-zone snapshot in precedence order.
func (s *Server) GetRPZStats() []engine.RPZStats {
	active := s.rpz.Load()
	if active == nil {
		return nil
	}
	return active.Stats()
}

func (s *Server) applyRPZ(req, resp *dns.Msg) (matched bool, drop bool, rule *engine.RPZRule) {
	active := s.rpz.Load()
	if active == nil || len(req.Question) != 1 {
		return false, false, nil
	}

	rule, action := active.Check(req.Question[0].Name)
	if rule == nil || action == engine.RPZActionNone || action == engine.RPZActionPassthru {
		return false, false, rule
	}
	if action == engine.RPZActionDrop {
		return true, true, rule
	}

	resp.Answer = nil
	resp.Ns = nil
	switch action {
	case engine.RPZActionNXDomain:
		resp.Rcode = dns.RcodeNameError
	case engine.RPZActionNoData:
		resp.Rcode = dns.RcodeSuccess
	case engine.RPZActionRewrite:
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = append(resp.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			Target: rule.RewriteTarget,
		})
	}
	if req.IsEdns0() != nil {
		ede.NewEDE(ede.InfoCodeFiltered, "Filtered by RPZ "+rule.Zone).AddToMessage(resp)
	}
	return true, false, rule
}
