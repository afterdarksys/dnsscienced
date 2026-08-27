package server

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/ede"
	"github.com/afterdarksys/dnsscienced/internal/engine"
	"github.com/miekg/dns"
)

// RPZConfig controls production response-policy-zone loading.
type RPZConfig struct {
	Enabled                 bool            `yaml:"enabled"`
	MinNSDots               int             `yaml:"min_ns_dots"`
	MaxNSLookups            int             `yaml:"max_ns_lookups"`
	NameserverLookupTimeout time.Duration   `yaml:"nameserver_lookup_timeout"`
	Zones                   []RPZZoneConfig `yaml:"zones"`
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
		return nil
	}
	if len(cfg.Zones) == 0 {
		return fmt.Errorf("enabled but no policy zones are configured")
	}
	if cfg.MinNSDots < 0 || cfg.MinNSDots > 127 {
		return fmt.Errorf("min_ns_dots must be between 0 and 127 (got %d)", cfg.MinNSDots)
	}
	if cfg.MaxNSLookups == 0 {
		cfg.MaxNSLookups = 64
	}
	if cfg.MaxNSLookups < 1 || cfg.MaxNSLookups > 256 {
		return fmt.Errorf("max_ns_lookups must be between 1 and 256 (got %d)", cfg.MaxNSLookups)
	}
	if cfg.NameserverLookupTimeout == 0 {
		cfg.NameserverLookupTimeout = 2 * time.Second
	}
	if cfg.NameserverLookupTimeout < 10*time.Millisecond ||
		cfg.NameserverLookupTimeout > 30*time.Second {
		return fmt.Errorf(
			"nameserver_lookup_timeout must be between 10ms and 30s (got %s)",
			cfg.NameserverLookupTimeout,
		)
	}
	zones := append([]RPZZoneConfig(nil), cfg.Zones...)
	sort.SliceStable(zones, func(i, j int) bool {
		return zones[i].Priority < zones[j].Priority
	})

	aggregate := engine.NewRPZAggregate()
	aggregate.SetNameserverDiscovery(
		cfg.MinNSDots,
		cfg.MaxNSLookups,
		cfg.NameserverLookupTimeout,
	)
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
	matched, drop, rule, _ = s.applyRPZQuery(req, resp, nil)
	return matched, drop, rule
}

func (s *Server) applyRPZQuery(
	req, resp *dns.Msg,
	clientIP net.IP,
) (matched bool, drop bool, rule *engine.RPZRule, decisive bool) {
	active := s.rpz.Load()
	if active == nil || len(req.Question) != 1 {
		return false, false, nil, true
	}

	rule, action, decisive := active.CheckRequestShortcut(
		req.Question[0].Name,
		rpzClientAddress(clientIP),
	)
	if !decisive {
		return false, false, nil, false
	}
	matched, drop, rule = applyRPZAction(req, resp, rule, action)
	return matched, drop, rule, true
}

func (s *Server) applyRPZResponse(
	req, resp *dns.Msg,
	clientIP net.IP,
) (matched bool, drop bool, rule *engine.RPZRule) {
	active := s.rpz.Load()
	if active == nil || len(req.Question) != 1 {
		return false, false, nil
	}
	rule, action, decisive := active.CheckRequestResponseShortcut(
		req.Question[0].Name,
		rpzClientAddress(clientIP),
		resp,
	)
	if !decisive {
		// Authoritative responses do not have a recursive delegation data
		// path. Do not let a lower-priority zone bypass an unresolved NS rule.
		return false, false, nil
	}
	return applyRPZAction(req, resp, rule, action)
}

func (s *Server) applyRPZResponseWithNameservers(
	req, resp *dns.Msg,
	clientIP net.IP,
	nameservers *engine.RPZNameserverData,
) (matched bool, drop bool, rule *engine.RPZRule) {
	active := s.rpz.Load()
	if active == nil || len(req.Question) != 1 {
		return false, false, nil
	}
	rule, action := active.CheckRequestResponseWithNameservers(
		req.Question[0].Name,
		rpzClientAddress(clientIP),
		resp,
		nameservers,
	)
	return applyRPZAction(req, resp, rule, action)
}

func rpzClientAddress(clientIP net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(clientIP)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func applyRPZAction(
	req, resp *dns.Msg,
	rule *engine.RPZRule,
	action engine.RPZAction,
) (matched bool, drop bool, matchedRule *engine.RPZRule) {
	if rule == nil || action == engine.RPZActionNone || action == engine.RPZActionPassthru {
		return false, false, rule
	}
	if action == engine.RPZActionDrop {
		return true, true, rule
	}

	resp.Answer = nil
	resp.Ns = nil
	resp.Extra = nil
	resp.AuthenticatedData = false
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
		ede.EDEFiltered.AddToMessage(resp)
	}
	return true, false, rule
}
