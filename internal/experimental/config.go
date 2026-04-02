package experimental

import "time"

// Config holds configuration for experimental/draft IETF protocols
type Config struct {
	// Enable experimental/draft features
	Enabled bool `yaml:"enabled"`

	// Individual protocol enablement flags
	DNSSD        DnssdConfig        `yaml:"dns_sd"`
	DoQ          DoQConfig          `yaml:"doq"`
	DSO          DSOConfig          `yaml:"dso"`
	DELEG        DelegConfig        `yaml:"deleg"`
	DID          DIDConfig          `yaml:"did"`
	IoTDNS       IoTDNSConfig       `yaml:"iot_dns"`
	PROXYv2      PROXYv2Config      `yaml:"proxyv2"`
	ProtectiveDNS ProtectiveDNSConfig `yaml:"protective_dns"`
}

// DnssdConfig holds DNS-SD Service Registration Protocol configuration
// RFC 9665 - DNS-SD Service Registration Protocol
type DnssdConfig struct {
	// Enable DNS-SD SRP (Service Registration Protocol)
	Enabled bool `yaml:"enabled"`

	// Allow dynamic service registration
	AllowRegistration bool `yaml:"allow_registration"`

	// Default TTL for registered services
	DefaultTTL time.Duration `yaml:"default_ttl"`

	// Maximum services per client
	MaxServicesPerClient int `yaml:"max_services_per_client"`

	// Service lease timeout
	LeaseTimeout time.Duration `yaml:"lease_timeout"`

	// Require authentication for registration
	RequireAuth bool `yaml:"require_auth"`

	// Browse domains for service discovery
	BrowseDomains []string `yaml:"browse_domains"`
}

// DoQConfig holds DNS over QUIC configuration
// RFC 9250 - DNS over Dedicated QUIC Connections
type DoQConfig struct {
	// Enable DNS over QUIC
	Enabled bool `yaml:"enabled"`

	// QUIC listen address (default: ":853")
	Address string `yaml:"address"`

	// TLS certificate file
	CertFile string `yaml:"cert_file"`

	// TLS key file
	KeyFile string `yaml:"key_file"`

	// Maximum concurrent streams per connection
	MaxStreams int `yaml:"max_streams"`

	// Idle timeout for QUIC connections
	IdleTimeout time.Duration `yaml:"idle_timeout"`

	// Enable 0-RTT (early data)
	Enable0RTT bool `yaml:"enable_0rtt"`
}

// DSOConfig holds DNS Stateful Operations configuration
// RFC 8490 - DNS Stateful Operations (DSO)
type DSOConfig struct {
	// Enable DNS Stateful Operations
	Enabled bool `yaml:"enabled"`

	// Keep-alive interval for DSO sessions
	KeepAlive time.Duration `yaml:"keep_alive"`

	// Inactivity timeout
	InactivityTimeout time.Duration `yaml:"inactivity_timeout"`

	// Maximum number of concurrent DSO sessions
	MaxSessions int `yaml:"max_sessions"`

	// Enable push notifications
	EnablePush bool `yaml:"enable_push"`

	// Enable long-lived queries
	EnableSubscribe bool `yaml:"enable_subscribe"`
}

// DelegConfig holds DELEG record configuration
// draft-ietf-dnsop-deleg - Extensible Delegation for DNS
type DelegConfig struct {
	// Enable DELEG record support
	Enabled bool `yaml:"enabled"`

	// Allow DELEG records in zone files
	AllowInZones bool `yaml:"allow_in_zones"`

	// Cache DELEG responses
	EnableCaching bool `yaml:"enable_caching"`

	// DELEG cache TTL
	CacheTTL time.Duration `yaml:"cache_ttl"`

	// Supported delegation types
	SupportedTypes []string `yaml:"supported_types"` // e.g., ["ipv4", "ipv6", "dohpath"]
}

// DIDConfig holds DNS DID (Decentralized Identifiers) configuration
// draft-duda-dnsop-dns-did - Decentralized Identifiers in DNS
type DIDConfig struct {
	// Enable DNS DID support
	Enabled bool `yaml:"enabled"`

	// DID methods supported (e.g., "did:dns", "did:web")
	SupportedMethods []string `yaml:"supported_methods"`

	// Resolution timeout for DID documents
	ResolutionTimeout time.Duration `yaml:"resolution_timeout"`

	// Cache DID documents
	EnableCaching bool `yaml:"enable_caching"`

	// DID document cache TTL
	CacheTTL time.Duration `yaml:"cache_ttl"`

	// Verify signatures on DID documents
	VerifySignatures bool `yaml:"verify_signatures"`

	// Trust anchor for DID verification
	TrustAnchor string `yaml:"trust_anchor"`
}

// IoTDNSConfig holds IoT DNS Guidelines configuration
// draft-ietf-iotops-iot-dns-guidelines - IoT DNS Guidelines
type IoTDNSConfig struct {
	// Enable IoT DNS optimizations
	Enabled bool `yaml:"enabled"`

	// Enable aggressive negative caching for IoT devices
	AggressiveNCaching bool `yaml:"aggressive_ncaching"`

	// Minimum TTL for IoT device queries (prevent battery drain)
	MinTTL time.Duration `yaml:"min_ttl"`

	// Maximum TTL for IoT device queries
	MaxTTL time.Duration `yaml:"max_ttl"`

	// Enable UDP payload size optimization for constrained devices
	OptimizeUDPSize bool `yaml:"optimize_udp_size"`

	// Maximum UDP payload size for IoT devices (RFC 6891)
	MaxUDPPayload int `yaml:"max_udp_payload"`

	// Enable response minimization for bandwidth-constrained devices
	MinimalResponses bool `yaml:"minimal_responses"`

	// Enable DNS push for battery-saving (RFC 8765)
	EnablePush bool `yaml:"enable_push"`

	// Detect and optimize for CoAP-based IoT devices
	CoAPOptimization bool `yaml:"coap_optimization"`
}

// PROXYv2Config holds PROXY protocol v2 configuration
// Enables DNSScienced to run behind HAProxy/nginx and preserve client IPs
type PROXYv2Config struct {
	// Enable PROXY protocol v2 support
	Enabled bool `yaml:"enabled"`

	// Trusted proxy addresses (CIDR format)
	// Only accept PROXY headers from these sources
	TrustedProxies []string `yaml:"trusted_proxies"`

	// Require PROXY header on all connections
	// If false, connections without PROXY header are accepted
	RequireHeader bool `yaml:"require_header"`

	// Timeout for reading PROXY header
	HeaderTimeout time.Duration `yaml:"header_timeout"`

	// Use X-Forwarded-For fallback if PROXY header missing
	AllowXFF bool `yaml:"allow_xff"`

	// Log proxy header parsing for debugging
	LogHeaders bool `yaml:"log_headers"`

	// Reject connections from non-proxied sources when required
	RejectNonProxied bool `yaml:"reject_non_proxied"`
}

// ProtectiveDNSConfig holds Protective DNS configuration
// draft-liu-dnsop-protective-dns - Considerations for Protective DNS Server Operators
type ProtectiveDNSConfig struct {
	// Enable Protective DNS (malicious domain blocking)
	Enabled bool `yaml:"enabled"`

	// Response rewriting strategy
	// "redirect" - Redirect to safe IP
	// "localhost" - Return 127.0.0.1/::1
	// "cname" - CNAME to landing page
	// "empty" - Empty answer section
	// "nxdomain" - Return NXDOMAIN
	// "servfail" - Return SERVFAIL
	Strategy string `yaml:"strategy"`

	// Redirect target for "redirect" strategy
	RedirectIPv4 string `yaml:"redirect_ipv4"`
	RedirectIPv6 string `yaml:"redirect_ipv6"`

	// CNAME target for "cname" strategy
	CNAMETarget string `yaml:"cname_target"`

	// Landing page URL (for user notification)
	LandingPageURL string `yaml:"landing_page_url"`

	// Extended DNS Errors (EDE) - RFC 8914
	EnableEDE bool `yaml:"enable_ede"` // Add Extended DNS Error codes

	// EDE info code for blocked domains (default: 15 - Blocked)
	EDEInfoCode uint16 `yaml:"ede_info_code"`

	// EDE extra text message
	EDEExtraText string `yaml:"ede_extra_text"`

	// Blocklist sources
	BlocklistFiles []string `yaml:"blocklist_files"` // Local blocklist files
	BlocklistFeeds []Feed   `yaml:"blocklist_feeds"` // Remote threat feeds

	// Blocklist categories to enable
	Categories []string `yaml:"categories"` // e.g., ["malware", "phishing", "c2", "cryptomining"]

	// Allowlist (domains to never block)
	AllowlistFiles []string `yaml:"allowlist_files"`
	AllowlistDomains []string `yaml:"allowlist_domains"`

	// Blocklist update settings
	UpdateInterval time.Duration `yaml:"update_interval"` // How often to update feeds
	AutoUpdate     bool          `yaml:"auto_update"`     // Automatically update feeds

	// Performance tuning
	BlocklistCacheSize int           `yaml:"blocklist_cache_size"` // In-memory blocklist cache entries
	LookupTimeout      time.Duration `yaml:"lookup_timeout"`       // Blocklist lookup timeout

	// Logging and monitoring
	LogBlocks     bool   `yaml:"log_blocks"`      // Log blocked queries
	LogFile       string `yaml:"log_file"`        // Protective DNS log file
	LogFormat     string `yaml:"log_format"`      // "json" or "text"
	MetricsPrefix string `yaml:"metrics_prefix"`  // Prometheus metrics prefix

	// Exemptions
	ExemptClients []string `yaml:"exempt_clients"` // CIDRs exempt from blocking
	ExemptDomains []string `yaml:"exempt_domains"` // Domains to never check

	// Fallback behavior on blocklist lookup failure
	FailOpen bool `yaml:"fail_open"` // true = allow on error, false = block on error

	// DNSSEC handling
	PreserveDNSSEC bool `yaml:"preserve_dnssec"` // Maintain DNSSEC validation for blocked responses

	// Response customization
	CustomTTL     uint32 `yaml:"custom_ttl"`      // TTL for rewritten responses (0 = no caching)
	MinimizeResponse bool `yaml:"minimize_response"` // Minimize response size for blocked queries
}

// Feed represents a threat intelligence feed
type Feed struct {
	Name     string        `yaml:"name"`     // Feed name/identifier
	URL      string        `yaml:"url"`      // Feed URL
	Format   string        `yaml:"format"`   // "domains", "hosts", "rpz", "json"
	Category string        `yaml:"category"` // Threat category: malware, phishing, c2, etc.
	Enabled  bool          `yaml:"enabled"`  // Enable this feed
	Priority int           `yaml:"priority"` // Feed priority (higher = checked first)
	Interval time.Duration `yaml:"interval"` // Update interval (overrides global)

	// Authentication
	APIKey    string            `yaml:"api_key"`    // API key for authenticated feeds
	Headers   map[string]string `yaml:"headers"`    // Custom HTTP headers

	// Validation
	ValidateHTTPS bool `yaml:"validate_https"` // Require HTTPS with valid cert
	ValidateHash  bool `yaml:"validate_hash"`  // Verify feed integrity hash

	// Filtering
	IncludePatterns []string `yaml:"include_patterns"` // Only include matching domains
	ExcludePatterns []string `yaml:"exclude_patterns"` // Exclude matching domains
}

// DefaultConfig returns default experimental features configuration
func DefaultConfig() Config {
	return Config{
		Enabled: false, // Disabled by default for production stability
		DNSSD: DnssdConfig{
			Enabled:              false,
			AllowRegistration:    false,
			DefaultTTL:           3600 * time.Second, // 1 hour
			MaxServicesPerClient: 10,
			LeaseTimeout:         7200 * time.Second, // 2 hours
			RequireAuth:          true,
			BrowseDomains:        []string{"local."},
		},
		DoQ: DoQConfig{
			Enabled:     false,
			Address:     ":853",
			MaxStreams:  100,
			IdleTimeout: 30 * time.Second,
			Enable0RTT:  false,
		},
		DSO: DSOConfig{
			Enabled:           false,
			KeepAlive:         60 * time.Second,
			InactivityTimeout: 300 * time.Second,
			MaxSessions:       1000,
			EnablePush:        false,
			EnableSubscribe:   false,
		},
		DELEG: DelegConfig{
			Enabled:        false,
			AllowInZones:   false,
			EnableCaching:  true,
			CacheTTL:       3600 * time.Second,
			SupportedTypes: []string{"ipv4", "ipv6", "dohpath"},
		},
		DID: DIDConfig{
			Enabled:           false,
			SupportedMethods:  []string{"did:dns"},
			ResolutionTimeout: 5 * time.Second,
			EnableCaching:     true,
			CacheTTL:          3600 * time.Second,
			VerifySignatures:  true,
			TrustAnchor:       "",
		},
		IoTDNS: IoTDNSConfig{
			Enabled:            false,
			AggressiveNCaching: true,
			MinTTL:             300 * time.Second,  // 5 minutes
			MaxTTL:             86400 * time.Second, // 24 hours
			OptimizeUDPSize:    true,
			MaxUDPPayload:      512, // Conservative for IoT
			MinimalResponses:   true,
			EnablePush:         false,
			CoAPOptimization:   false,
		},
		PROXYv2: PROXYv2Config{
			Enabled:          false,
			TrustedProxies:   []string{"127.0.0.1/8", "::1/128"},
			RequireHeader:    false,
			HeaderTimeout:    5 * time.Second,
			AllowXFF:         false,
			LogHeaders:       false,
			RejectNonProxied: false,
		},
		ProtectiveDNS: ProtectiveDNSConfig{
			Enabled:      false,
			Strategy:     "nxdomain",
			RedirectIPv4: "0.0.0.0",
			RedirectIPv6: "::",
			CNAMETarget:  "blocked.dnsscienced.local.",
			LandingPageURL: "https://blocked.example.com",
			EnableEDE:    true,
			EDEInfoCode:  15, // RFC 8914 - Blocked
			EDEExtraText: "Blocked by Protective DNS: malicious domain",
			BlocklistFiles: []string{},
			BlocklistFeeds: []Feed{},
			Categories:     []string{"malware", "phishing", "c2"},
			AllowlistFiles: []string{},
			AllowlistDomains: []string{},
			UpdateInterval:   24 * time.Hour,
			AutoUpdate:       true,
			BlocklistCacheSize: 1000000, // 1M entries
			LookupTimeout:    100 * time.Millisecond,
			LogBlocks:        true,
			LogFile:          "/var/log/dnsscienced/protective.log",
			LogFormat:        "json",
			MetricsPrefix:    "protective_dns",
			ExemptClients:    []string{"127.0.0.0/8", "::1/128"},
			ExemptDomains:    []string{},
			FailOpen:         false,
			PreserveDNSSEC:   false,
			CustomTTL:        60,
			MinimizeResponse: true,
		},
	}
}

// IsAnyEnabled returns true if any experimental feature is enabled
func (c *Config) IsAnyEnabled() bool {
	if !c.Enabled {
		return false
	}
	return c.DNSSD.Enabled || c.DoQ.Enabled || c.DSO.Enabled ||
		c.DELEG.Enabled || c.DID.Enabled || c.IoTDNS.Enabled ||
		c.PROXYv2.Enabled || c.ProtectiveDNS.Enabled
}

// EnabledFeatures returns a list of enabled experimental features
func (c *Config) EnabledFeatures() []string {
	if !c.Enabled {
		return nil
	}

	var features []string
	if c.DNSSD.Enabled {
		features = append(features, "DNS-SD SRP (RFC 9665)")
	}
	if c.DoQ.Enabled {
		features = append(features, "DNS over QUIC (RFC 9250)")
	}
	if c.DSO.Enabled {
		features = append(features, "DNS Stateful Operations (RFC 8490)")
	}
	if c.DELEG.Enabled {
		features = append(features, "DELEG Record (draft-ietf-dnsop-deleg)")
	}
	if c.DID.Enabled {
		features = append(features, "DNS DID (draft-duda-dnsop-dns-did)")
	}
	if c.IoTDNS.Enabled {
		features = append(features, "IoT DNS Guidelines (draft-ietf-iotops-iot-dns-guidelines)")
	}
	if c.PROXYv2.Enabled {
		features = append(features, "PROXY Protocol v2 (HAProxy Support)")
	}
	if c.ProtectiveDNS.Enabled {
		features = append(features, "Protective DNS (draft-liu-dnsop-protective-dns)")
	}
	return features
}
