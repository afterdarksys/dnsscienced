package defensive

import "time"

// Config holds configuration for all defensive DNS features
type Config struct {
	// Stale Answer Support (RFC 8767)
	StaleAnswers StaleAnswerConfig

	// EDNS UDP Size Controls
	EDNS EDNSConfig

	// DNSSEC Validation Controls
	DNSSEC DNSSECConfig

	// Fetch Quotas and Rate Limiting
	FetchQuotas FetchQuotaConfig

	// DNS Name Compression
	Compression CompressionConfig

	// DNS Cookies (RFC 7873)
	Cookies CookiePolicy

	// Blackhole / ACLs
	Blackhole BlackholeConfig

	// Query Logging
	QueryLogging QueryLoggingConfig

	// RRset Ordering
	RRsetOrder RRsetOrderConfig

	// View/Split-Horizon Support
	Views []ViewConfig
}

// StaleAnswerConfig controls serving of stale/expired cache entries (RFC 8767)
type StaleAnswerConfig struct {
	Enabled       bool          `yaml:"enabled"`         // Enable stale answer support
	MaxStaleTime  time.Duration `yaml:"max_stale_time"`  // Maximum age of stale records to serve
	ClientTimeout time.Duration `yaml:"client_timeout"`  // Timeout before serving stale answer
	ServeOnError  bool          `yaml:"serve_on_error"`  // Serve stale on SERVFAIL from upstream
}

// EDNSConfig controls EDNS settings for broken firewalls/clients
type EDNSConfig struct {
	UDPSize    int  `yaml:"udp_size"`     // Advertised EDNS UDP size
	MaxUDPSize int  `yaml:"max_udp_size"` // Maximum UDP response size
	Enabled    bool `yaml:"enabled"`      // Enable EDNS0 support
}

// DNSSECConfig controls DNSSEC validation behavior
type DNSSECConfig struct {
	Validation           bool     `yaml:"validation"`               // Enable DNSSEC validation
	TrustAnchorFile      string   `yaml:"trust_anchor_file"`        // Path to trust anchor file
	BreakValidation      bool     `yaml:"break_validation"`         // BYPASS validation for troubleshooting
	PermissiveMode       bool     `yaml:"permissive_mode"`          // Log but don't fail on validation errors
	NegativeTrustAnchors []string `yaml:"negative_trust_anchors"`   // Domains to skip validation
}

// FetchQuotaConfig controls query limits to upstream servers
type FetchQuotaConfig struct {
	Enabled          bool `yaml:"enabled"`            // Enable fetch quotas
	FetchesPerServer int  `yaml:"fetches_per_server"` // Max concurrent queries to one server
	FetchesPerZone   int  `yaml:"fetches_per_zone"`   // Max concurrent queries per zone
	SpilloverQuota   int  `yaml:"spillover_quota"`    // Additional quota when server is unresponsive
}

// CompressionConfig controls DNS name compression
type CompressionConfig struct {
	Enabled        bool `yaml:"enabled"`         // Enable DNS name compression
	NoCaseCompress bool `yaml:"no_case_compress"` // Disable case-preserving compression for broken clients
}

// CookiePolicy defines DNS Cookie enforcement policy
type CookiePolicy struct {
	RequireServerCookie bool `yaml:"require_server_cookie"` // Require valid cookie for recursive queries
	StrictValidation    bool `yaml:"strict_validation"`     // Strict cookie validation (reject invalid)
}

// BlackholeConfig defines blocked client networks
type BlackholeConfig struct {
	Enabled bool     `yaml:"enabled"` // Enable blackhole functionality
	CIDRs   []string `yaml:"cidrs"`   // List of CIDR blocks to blackhole
	Action  string   `yaml:"action"`  // Action: "drop" (silent) or "refused" (send REFUSED)
}

// QueryLoggingConfig controls query logging for troubleshooting
type QueryLoggingConfig struct {
	Enabled         bool     `yaml:"enabled"`          // Enable query logging
	LogFile         string   `yaml:"log_file"`         // Path to query log file
	Categories      []string `yaml:"categories"`       // Categories to log
	IncludeClients  []string `yaml:"include_clients"`  // Only log queries from these CIDRs
	ExcludeClients  []string `yaml:"exclude_clients"`  // Don't log queries from these CIDRs
	LogNonCompliant bool     `yaml:"log_noncompliant"` // Log queries with protocol violations
}

// RRsetOrderConfig controls ordering of records in responses
type RRsetOrderConfig struct {
	Method string `yaml:"method"` // Method: "random", "cyclic", "fixed", "none"
	Seed   int64  `yaml:"seed"`   // Random seed for reproducible ordering
}

// ViewConfig defines split-horizon DNS configuration
type ViewConfig struct {
	Name         string   `yaml:"name"`          // View name
	MatchClients []string `yaml:"match_clients"` // Client CIDRs that match this view
	ZonesDir     string   `yaml:"zones_dir"`     // Alternative zones directory for this view
	Recursion    bool     `yaml:"recursion"`     // Allow recursion for this view
	Priority     int      `yaml:"priority"`      // View priority (higher = checked first)
}
