package firewalld

import "time"

// Config holds the DNS firewall configuration.
type Config struct {
	Enabled bool `yaml:"enabled"`

	// Policy rules evaluated in order; first match wins.
	// Starlark policy scripts are appended after static rules.
	Rules []RuleConfig `yaml:"rules"`

	// Starlark policy scripts loaded from disk.
	PolicyScripts []string `yaml:"policy_scripts"`

	// Threat intel scoring thresholds.
	ThreatIntel ThreatIntelConfig `yaml:"threat_intel"`

	// Junk detection settings.
	Junk JunkConfig `yaml:"junk"`

	// Default action when no rule matches: allow | nxdomain | drop
	DefaultAction string `yaml:"default_action"`

	// Max time a Starlark policy script may run per query.
	ScriptTimeout time.Duration `yaml:"script_timeout"`

	// Redirect holds upstream pool configuration for VerdictRedirect.
	Redirect RedirectConfig `yaml:"redirect"`
}

// RuleConfig defines a static policy rule.
type RuleConfig struct {
	// Name is used in logs and metrics.
	Name string `yaml:"name"`

	// Match conditions (all non-zero fields must match).
	Match MatchConfig `yaml:"match"`

	// Action to take on match: allow | nxdomain | drop | rewrite | redirect
	Action string `yaml:"action"`

	// RewriteTarget is the CNAME target used when Action == "rewrite".
	RewriteTarget string `yaml:"rewrite_target"`

	// RedirectServer is the upstream address used when Action == "redirect".
	// Format: "ip:port"
	RedirectServer string `yaml:"redirect_server"`
}

// MatchConfig describes query-match criteria.
type MatchConfig struct {
	// Domain suffix match (e.g. ".example.com" matches "foo.example.com").
	DomainSuffix string `yaml:"domain_suffix"`

	// Exact domain match (FQDN with trailing dot).
	DomainExact string `yaml:"domain_exact"`

	// Client CIDR (e.g. "10.0.0.0/8").
	ClientCIDR string `yaml:"client_cidr"`

	// Query type string: A, AAAA, MX, etc. Empty means any.
	QueryType string `yaml:"query_type"`

	// ThreatScore minimum (0-100). 0 means no threshold.
	ThreatScoreMin int `yaml:"threat_score_min"`

	// Customer account type: free | paid | enterprise | any
	AccountType string `yaml:"account_type"`

	// IsJunk matches when junk detection fires.
	IsJunk bool `yaml:"is_junk"`
}

// ThreatIntelConfig controls threat scoring behaviour.
type ThreatIntelConfig struct {
	// BlockThreshold: queries scoring above this are blocked by default.
	BlockThreshold int `yaml:"block_threshold"`

	// StaticIPScores maps client IP prefixes to scores (0-100).
	StaticIPScores map[string]int `yaml:"static_ip_scores"`

	// ZoneScores maps zone names to baseline scores (0-100).
	// Higher score = more suspicious zone.
	ZoneScores map[string]int `yaml:"zone_scores"`

	// CustomerMeta maps customer IDs to metadata.
	CustomerMeta map[string]CustomerMeta `yaml:"customer_meta"`

	// Feed poller configuration (D-07 through D-14)
	// FeedURL is the HTTP(S) URL to poll for domain/IP threat scores.
	// If empty, no poller is started (D-09).
	FeedURL string `yaml:"feed_url"`

	// PollInterval is how often the feed URL is fetched. Default: 5m (D-08).
	PollInterval time.Duration `yaml:"poll_interval"`

	// Timeout is the HTTP request timeout per fetch cycle. Default: 30s (D-08).
	Timeout time.Duration `yaml:"timeout"`

	// TLSSkipVerify disables TLS certificate verification (operator opt-in only).
	TLSSkipVerify bool `yaml:"tls_skip_verify"`

	// AuthToken is sent as "Authorization: Bearer <value>" when non-empty (D-11).
	// Never logged — only presence is logged (D-12).
	AuthToken string `yaml:"auth_token"`

	// Headers are additional HTTP request headers added to each feed fetch (D-10).
	Headers map[string]string `yaml:"headers"`
}

// CustomerMeta holds per-customer metadata used in scoring.
type CustomerMeta struct {
	AccountType string `yaml:"account_type"` // free | paid | enterprise
	// TrustBonus subtracts from threat score (0-50).
	TrustBonus int `yaml:"trust_bonus"`
}

// JunkConfig controls junk/bogus query detection.
type JunkConfig struct {
	// BlockDGA blocks DGA-detected domains.
	BlockDGA bool `yaml:"block_dga"`

	// BlockDataExfil blocks DNS tunnel / data-exfiltration patterns.
	BlockDataExfil bool `yaml:"block_data_exfil"`

	// BlockRandomSubdomain blocks high-entropy random subdomain labels.
	BlockRandomSubdomain bool `yaml:"block_random_subdomain"`

	// RandomSubdomainThreshold: entropy cutoff for subdomain junk detection (default 4.0).
	RandomSubdomainThreshold float64 `yaml:"random_subdomain_threshold"`
}

// RedirectConfig holds upstream pool configuration for VerdictRedirect.
type RedirectConfig struct {
	// Upstreams is the list of upstream DNS targets for redirect load balancing.
	// Each entry is "ip:port". At least one entry is required for redirect verdicts
	// that do not have a per-rule redirect_server override.
	Upstreams []string `yaml:"upstreams"`
}

// DefaultConfig returns a safe default configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		DefaultAction: "allow",
		ScriptTimeout: 2 * time.Millisecond,
		ThreatIntel: ThreatIntelConfig{
			BlockThreshold: 80,
			StaticIPScores: make(map[string]int),
			ZoneScores:     make(map[string]int),
			CustomerMeta:   make(map[string]CustomerMeta),
			PollInterval:   5 * time.Minute,
			Timeout:        30 * time.Second,
		},
		Junk: JunkConfig{
			BlockDGA:                 true,
			BlockDataExfil:           true,
			BlockRandomSubdomain:     false,
			RandomSubdomainThreshold: 4.0,
		},
	}
}
