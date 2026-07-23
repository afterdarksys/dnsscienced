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

	// Broken Record Handling
	BrokenRecords BrokenRecordConfig
}

// StaleAnswerConfig controls serving of stale/expired cache entries (RFC 8767)
type StaleAnswerConfig struct {
	Enabled       bool          `yaml:"enabled"`        // Enable stale answer support
	MaxStaleTime  time.Duration `yaml:"max_stale_time"` // Maximum age of stale records to serve
	ClientTimeout time.Duration `yaml:"client_timeout"` // Timeout before serving stale answer
	ServeOnError  bool          `yaml:"serve_on_error"` // Serve stale on SERVFAIL from upstream
}

// EDNSConfig controls EDNS settings for broken firewalls/clients
type EDNSConfig struct {
	UDPSize    int  `yaml:"udp_size"`     // Advertised EDNS UDP size
	MaxUDPSize int  `yaml:"max_udp_size"` // Maximum UDP response size
	Enabled    bool `yaml:"enabled"`      // Enable EDNS0 support
}

// DNSSECConfig controls DNSSEC validation behavior
type DNSSECConfig struct {
	// Validation mode
	Validation      bool   `yaml:"validation"`        // Enable DNSSEC validation
	ValidationMode  string `yaml:"validation_mode"`   // "strict", "permissive", "log-only"
	TrustAnchorFile string `yaml:"trust_anchor_file"` // Legacy defensive compatibility setting
	RootKeyFile     string `yaml:"root_key_file"`     // Path to root KSK file (for bootstrapping)

	// Troubleshooting and compatibility
	BreakValidation      bool     `yaml:"break_validation"`       // BYPASS validation for troubleshooting
	PermissiveMode       bool     `yaml:"permissive_mode"`        // Deprecated: use validation_mode instead
	NegativeTrustAnchors []string `yaml:"negative_trust_anchors"` // Domains to skip validation

	// Validation behavior
	AcceptBogus      bool `yaml:"accept_bogus"`      // Accept bogus responses (set CD bit)
	RequireAD        bool `yaml:"require_ad"`        // Require AD bit from upstreams
	ValidateUpstream bool `yaml:"validate_upstream"` // Validate upstream resolver's AD bit locally

	// Chain of trust
	ChainValidation bool `yaml:"chain_validation"` // Full chain-of-trust validation
	DSLookup        bool `yaml:"ds_lookup"`        // Query parent zones for DS records
	MaxChainDepth   int  `yaml:"max_chain_depth"`  // Maximum DNSSEC chain depth (default: 20)

	// Caching
	CachePositive bool          `yaml:"cache_positive"` // Cache validated responses
	CacheNegative bool          `yaml:"cache_negative"` // Cache NSEC/NSEC3 proofs
	CacheBogus    bool          `yaml:"cache_bogus"`    // Cache bogus responses (to avoid re-validation)
	CacheTTL      time.Duration `yaml:"cache_ttl"`      // TTL for DNSSEC cache entries

	// Key management
	AutoTrustAnchor   bool          `yaml:"auto_trust_anchor"`   // Legacy; configure resolver.dnssec instead
	TrustAnchorUpdate time.Duration `yaml:"trust_anchor_update"` // Legacy; configure resolver.dnssec instead

	// Algorithm support
	DisabledAlgorithms []string `yaml:"disabled_algorithms"` // DNSSEC algorithms to reject

	// NSEC/NSEC3 handling
	NSEC3MaxIterations uint16 `yaml:"nsec3_max_iterations"` // Maximum NSEC3 iterations to accept
	ValidateNSEC       bool   `yaml:"validate_nsec"`        // Validate NSEC/NSEC3 proofs

	// Error handling
	FailOnBogus   bool `yaml:"fail_on_bogus"`   // Return SERVFAIL on bogus (vs return bogus data)
	FailOnMissing bool `yaml:"fail_on_missing"` // SERVFAIL when DNSSEC expected but missing
	LogValidation bool `yaml:"log_validation"`  // Log all validation results
	LogFailures   bool `yaml:"log_failures"`    // Log validation failures only
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
	Enabled        bool `yaml:"enabled"`          // Enable DNS name compression
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

// BrokenRecordConfig controls handling of non-RFC-compliant records
// Useful for migrating from broken DNS providers (looking at you, OCI!)
type BrokenRecordConfig struct {
	// Maximum TXT record string length (RFC 1035 says 255, but some providers violate this)
	// Default: 255 (RFC compliant)
	// Set higher (e.g., 512, 1024) to accept broken records from cloud providers
	TXTByteMax int `yaml:"txt_byte_max"`

	// Log warnings when broken records are encountered
	LogBroken bool `yaml:"log_broken"`

	// Reject broken records instead of accepting them
	// If false: Accept and serve broken records (compatibility mode)
	// If true: Reject broken records (strict RFC compliance)
	RejectBroken bool `yaml:"reject_broken"`
}
