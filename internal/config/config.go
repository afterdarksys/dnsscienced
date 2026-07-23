package config

import (
	"fmt"
	"math"
	"net"
	"os"
	"time"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/defensive"
	"github.com/dnsscience/dnsscienced/internal/experimental"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
	"github.com/dnsscience/dnsscienced/internal/logging"
	"github.com/dnsscience/dnsscienced/internal/resolver"
	"github.com/dnsscience/dnsscienced/internal/server"
	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration structure
type Config struct {
	Runtime  RuntimeConfig   `yaml:"runtime"`
	Server   server.Config   `yaml:"server"`
	Resolver resolver.Config `yaml:"resolver"`
	// Backward-compatible top-level aliases used by config.example.yaml. Load
	// overlays these onto the corresponding live server configuration.
	Cache        cache.Config        `yaml:"cache"`
	Firewall     firewalld.Config    `yaml:"firewall"`
	Experimental experimental.Config `yaml:"experimental"`
	Logging      logging.Config      `yaml:"logging"`

	// Zone loading configuration
	ZonesDir string `yaml:"zones_dir"`

	// Admin API configuration
	Admin AdminConfig `yaml:"admin"`

	// Defensive DNS configuration for handling broken clients and edge cases
	Defensive defensive.Config `yaml:"defensive"`

	// DHCP Configuration (Placeholder for future implementation)
	DHCP DHCPConfig `yaml:"dhcp"`

	// Masters - BIND-style secondary zone configuration
	// Map of zone name to list of master servers
	Masters map[string][]string `yaml:"masters"`

	// Forwarders - BIND-style conditional forwarding
	// Map of zone name to list of forward servers (empty string key = global forwarders)
	Forwarders map[string][]string `yaml:"forwarders"`

	// Zones - per-zone configuration (BIND-style zone stanzas)
	Zones []ZoneConfig `yaml:"zones"`

	// TSIG keys for authenticated zone transfers (RFC 2845)
	TsigKeys []TsigKeyConfig `yaml:"tsig_keys"`
}

// RuntimeConfig controls the Go runtime independently of DNS request
// concurrency. Zero values leave environment-derived Go defaults unchanged.
type RuntimeConfig struct {
	// MaxProcs limits Go code executing simultaneously. It is not an OS thread
	// count; zero preserves the runtime/container-aware default.
	MaxProcs int `yaml:"max_procs"`
	// GCPercent overrides GOGC when present. -1 disables collection.
	GCPercent *int `yaml:"gc_percent"`
	// MemoryLimitMB overrides GOMEMLIMIT when positive.
	MemoryLimitMB int64 `yaml:"memory_limit_mb"`
}

// Validate rejects runtime values that could overflow or create an unusable
// process. Deliberately generous upper bounds retain room for large servers.
func (c RuntimeConfig) Validate() error {
	if c.MaxProcs < 0 || c.MaxProcs > 65536 {
		return fmt.Errorf("runtime.max_procs must be between 0 and 65536")
	}
	if c.GCPercent != nil && (*c.GCPercent < -1 || *c.GCPercent > 10000) {
		return fmt.Errorf("runtime.gc_percent must be between -1 and 10000")
	}
	const bytesPerMiB = int64(1024 * 1024)
	if c.MemoryLimitMB < 0 || c.MemoryLimitMB > math.MaxInt64/bytesPerMiB {
		return fmt.Errorf("runtime.memory_limit_mb is out of range")
	}
	return nil
}

// TsigKeyConfig holds TSIG key configuration for zone transfers and dynamic updates (RFC 2845).
type TsigKeyConfig struct {
	// Name is the key name (FQDN, e.g., "xfer-key.example.com.")
	Name string `yaml:"name"`
	// Algorithm: "hmac-sha256", "hmac-sha384", or "hmac-sha512"
	Algorithm string `yaml:"algorithm"`
	// Secret is the base64-encoded shared secret
	Secret string `yaml:"secret"`
}

// APIKey represents a named API key for admin authentication.
// The ID is used in audit logs (per D-08); the Secret is the bearer token value.
type APIKey struct {
	ID     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

// AdminConfig holds admin API configuration
type AdminConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Listen       string   `yaml:"listen"`
	APIKeys      []APIKey `yaml:"api_keys"` // named key structs per D-04
	TLSCertFile  string   `yaml:"tls_cert_file"`
	TLSKeyFile   string   `yaml:"tls_key_file"`
	TLSClientCAs string   `yaml:"tls_client_cas"` // path to PEM CA bundle for mTLS client verification
}

// ZoneConfig holds per-zone configuration (BIND-style)
type ZoneConfig struct {
	// Zone name (e.g., "example.com.")
	Name string `yaml:"name"`

	// Zone type: "primary", "secondary", "forward", "stub", "hint"
	Type string `yaml:"type"`

	// File path for primary zones
	File string `yaml:"file,omitempty"`

	// Masters for secondary zones (can also use global masters{} block)
	Masters []string `yaml:"masters,omitempty"`

	// Forwarders for forward zones (can also use global forwarders{} block)
	Forwarders []string `yaml:"forwarders,omitempty"`

	// Forward mode: "first" (try forwarders first, fall back to recursive) or "only" (only use forwarders)
	ForwardMode string `yaml:"forward_mode,omitempty"`

	// Security features
	Enable0x20      *bool `yaml:"enable_0x20,omitempty"`      // Override global 0x20 setting (nil = use global)
	EnableDNSSEC    *bool `yaml:"enable_dnssec,omitempty"`    // Enable DNSSEC for this zone
	EnableScrubbing *bool `yaml:"enable_scrubbing,omitempty"` // Override global scrubbing setting

	// DNSSEC signing configuration (for primary zones)
	DNSSECSigning *ZoneDNSSECConfig `yaml:"dnssec_signing,omitempty"`

	// AXFR/IXFR configuration
	AllowTransfer []string `yaml:"allow_transfer,omitempty"` // CIDRs allowed to AXFR
	AlsoNotify    []string `yaml:"also_notify,omitempty"`    // Additional NOTIFY targets

	// Dynamic DNS Update configuration (RFC 2136)
	AllowUpdate    []string `yaml:"allow_update,omitempty"`    // CIDRs allowed to send UPDATE; empty = REFUSED (D-15)
	PersistUpdates *bool    `yaml:"persist_updates,omitempty"` // nil/false = in-memory only; true = write-back to zone file (D-11)

	// Zone transfer options (for secondary zones)
	TransferSource  string        `yaml:"transfer_source,omitempty"`   // Source IP for AXFR
	TransferTSIGKey string        `yaml:"transfer_tsig_key,omitempty"` // Named key from tsig_keys
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty"`  // Override SOA refresh

	// AllowAXFRFallback controls whether IXFR failures fall back to a full AXFR.
	// Set to false to force operators to fix IXFR issues rather than silently
	// pulling full zones (NSD allow-axfr-fallback: no). Defaults to true.
	AllowAXFRFallback *bool `yaml:"allow_axfr_fallback,omitempty"`

	// Zone freshness bounds prevent transfer flooding (too-frequent NOTIFY) and
	// stale-zone attacks (ignoring SOA TTL refresh). (NSD min/max-refresh/retry-time)
	MaxRefreshTime time.Duration `yaml:"max_refresh_time,omitempty"` // Upper bound on SOA refresh
	MinRefreshTime time.Duration `yaml:"min_refresh_time,omitempty"` // Lower bound on SOA refresh
	MaxRetryTime   time.Duration `yaml:"max_retry_time,omitempty"`   // Upper bound on transfer retry
	MinRetryTime   time.Duration `yaml:"min_retry_time,omitempty"`   // Lower bound on transfer retry

	// RRLWhitelist lists response types exempt from RRL for this zone.
	// Valid values: "nxdomain", "noerror", "error", "referral", "wildcard", "any".
	// (NSD rrl-whitelist per-zone directive)
	RRLWhitelist []string `yaml:"rrl_whitelist,omitempty"`

	// VerifyZONEMD enables RFC 8976 ZONEMD integrity verification at zone load.
	// A zone whose digest does not match its ZONEMD RR will be refused.
	// (NSD 4.3.0+ automatic ZONEMD verification)
	VerifyZONEMD bool `yaml:"verify_zonemd,omitempty"`

	// DSYNC controls RFC 9859 DSYNC outbound notification for this zone.
	DSYNC *ZoneDSYNCConfig `yaml:"dsync,omitempty"`
}

// ZoneDNSSECConfig holds DNSSEC signing configuration for a zone
type ZoneDNSSECConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Algorithm         string        `yaml:"algorithm"`          // "ECDSAP256SHA256", "ECDSAP384SHA384", "RSASHA256", etc.
	KSKSize           int           `yaml:"ksk_size,omitempty"` // Key size for KSK (RSA only)
	ZSKSize           int           `yaml:"zsk_size,omitempty"` // Key size for ZSK (RSA only)
	KSKLifetime       time.Duration `yaml:"ksk_lifetime"`       // KSK rotation interval
	ZSKLifetime       time.Duration `yaml:"zsk_lifetime"`       // ZSK rotation interval
	SignatureValidity time.Duration `yaml:"signature_validity"` // How long signatures are valid
	SignatureRefresh  time.Duration `yaml:"signature_refresh"`  // Re-sign before expiry
	NSEC3             bool          `yaml:"nsec3"`              // Use NSEC3 instead of NSEC
	NSEC3Iterations   uint16        `yaml:"nsec3_iterations"`   // NSEC3 iterations
	NSEC3SaltLength   uint8         `yaml:"nsec3_salt_length"`  // NSEC3 salt length in bytes
}

// ZoneDSYNCConfig controls RFC 9859 generalized notifications for a zone.
type ZoneDSYNCConfig struct {
	// NotifyParent enables outbound NOTIFY to discovered _dsync parent endpoints
	// when this zone's CDS/CSYNC records change.
	NotifyParent bool `yaml:"notify_parent"`

	// PropagationDelay: wait this long after serial increment before sending
	// outbound NOTIFY. Default: 60s (RFC 9859 recommendation).
	PropagationDelay time.Duration `yaml:"propagation_delay"`

	// WebhookURL: POST endpoint called on accepted inbound NOTIFY (per D-02).
	WebhookURL string `yaml:"webhook_url,omitempty"`

	// WebhookBodyFormat: "json" (default) or "base64" wire format (per D-03).
	WebhookBodyFormat string `yaml:"webhook_body_format,omitempty"`

	// AllowedSources: CIDRs/IPs allowed to send NOTIFY for this zone (per D-05).
	AllowedSources []string `yaml:"allowed_sources,omitempty"`

	// RateLimitPerMin: max NOTIFY per source IP per minute (per D-13). 0 = use default (5/min).
	RateLimitPerMin int `yaml:"rate_limit_per_min,omitempty"`
}

// DHCPConfig holds DHCP server configuration
type DHCPConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Interfaces []string `yaml:"interfaces"`

	// High Availability / Failover settings
	Failover FailoverConf `yaml:"failover"`

	// Lease Configuration (Timing)
	Lease LeaseConf `yaml:"lease"`

	// Boot/PXE Configuration (Global defaults)
	Boot BootConf `yaml:"boot"`

	// DHCP Snooping / Option 82 Handling
	Snooping SnoopingConf `yaml:"snooping"`

	// Custom Option Definitions (Schema for non-standard options)
	OptionDefs []OptionDef `yaml:"option_defs"`

	// Global Options (applied to all)
	GlobalOptions map[string]string `yaml:"global_options"`

	// Option Sets (reusable groups of options)
	// Key is the name of the set (e.g., "voip-phones", "access-points")
	OptionSets map[string]map[string]string `yaml:"option_sets"`

	// Classes define groups of devices based on matching criteria
	// Used for: SIP Phones, Routers, Mobile Devices, etc.
	Classes []ClassConf `yaml:"classes"`

	// Hosts define static reservations (fixed-address)
	Hosts []HostConf `yaml:"hosts"`

	// Subnets define IP ranges and network-specific topology
	Subnets []SubnetConf `yaml:"subnets"`
}

// OptionDef defines a custom DHCP option
type OptionDef struct {
	Name string `yaml:"name"` // Unique name used in options maps
	Code int    `yaml:"code"` // Option Code (1-255)
	Type string `yaml:"type"` // Data type: string, ip, int, boolean, hex
}

// SnoopingConf defines configuration for DHCP Snooping / Relay Agent Info (Option 82)
type SnoopingConf struct {
	Enabled       bool     `yaml:"enabled"`        // Enable processing of Option 82
	TrustedRelays []string `yaml:"trusted_relays"` // CIDRs of permitted Relay Agents
	TrustAll      bool     `yaml:"trust_all"`      // Accept Option 82 from any source
}

// LeaseConf defines lease timing configuration
type LeaseConf struct {
	Default time.Duration `yaml:"default"` // Default lease time
	Max     time.Duration `yaml:"max"`     // Maximum lease time
	Min     time.Duration `yaml:"min"`     // Minimum lease time
}

// BootConf defines PXE/Boot options
type BootConf struct {
	Filename   string `yaml:"filename"`    // Boot filename (e.g., pxelinux.0)
	NextServer string `yaml:"next_server"` // TFTP Server IP (siaddr)
	ServerName string `yaml:"server_name"` // Server Hostname (sname)
}

// HostConf defines a static host reservation
type HostConf struct {
	Hostname  string            `yaml:"hostname"`
	MAC       string            `yaml:"mac"`
	IP        string            `yaml:"ip"`
	OptionSet string            `yaml:"option_set"`
	Options   map[string]string `yaml:"options"`
	Boot      BootConf          `yaml:"boot"` // Per-host boot settings
}

// FailoverConf defines DHCP failover and HA settings
type FailoverConf struct {
	Enabled bool   `yaml:"enabled"`
	Name    string `yaml:"name"` // Name of the failover peer relationship

	// Role: "primary" or "secondary" (standard DHCP failover)
	Role string `yaml:"role"`

	// Peer address for state synchronization
	Peer string `yaml:"peer"`

	// Failover Mode: "hot-standby" (Active/Passive) or "load-balance" (Active/Active)
	Mode string `yaml:"mode"`

	// MCLT: Maximum Client Lead Time (seconds)
	// Critical for cross-site failover to define how long a partner extends a lease
	// before assuming the partner is down.
	MCLT time.Duration `yaml:"mclt"`

	// Split: Load balancing split (0-255). 128 = 50/50.
	Split int `yaml:"split"`

	// SiteID: Identifier for the physical location/datacenter
	SiteID string `yaml:"site_id"`

	// VRRP Integration: If used with VRRP, we might only want to serve
	// when we own the Virtual IP, or we bind specifically to the VRRP interface.
	VRRPInterface string `yaml:"vrrp_interface"` // Interface monitoring VRRP state
	SharedSecret  string `yaml:"shared_secret"`
}

// ClassConf defines a device classification
type ClassConf struct {
	Name string `yaml:"name"`

	// Match criteria (simplified for config definition)
	// e.g., "option[60] contains 'Polycom'" or "mac startsWith '00:04:f2'"
	Match string `yaml:"match"`

	// Options to apply to this class
	OptionSet string            `yaml:"option_set"` // Reference to an OptionSet
	Options   map[string]string `yaml:"options"`    // Direct overrides
}

// SubnetConf defines a DHCP subnet configuration
type SubnetConf struct {
	Subnet string `yaml:"subnet"` // CIDR
	Range  string `yaml:"range"`  // Start-End

	// Overrides
	Lease LeaseConf `yaml:"lease"`
	Boot  BootConf  `yaml:"boot"`

	// Options specific to this subnet (Gateway, Mask, etc.)
	OptionSet string            `yaml:"option_set"`
	Options   map[string]string `yaml:"options"`
}

// Load reads configuration from a YAML file
func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Start with default values
	// Note: We need to figure out how to merge defaults.
	// For now, we'll unmarshal into zero structs and let the application merge/apply defaults.
	// Or we can populate defaults first.

	cfg := &Config{
		Server:  server.DefaultConfig(),
		Logging: logging.DefaultConfig(),
		// resolver config doesn't have a global default func, usually part of server config.
		// But in our structure, server.Config contains RecursiveConfig.
		// Wait, server.Config ALREADY contains RecursiveConfig, CookieConfig, and RRLConfig.
		// So we strictly only need to load server.Config if that's the root.
		// However, separating them in YAML might be cleaner if we want to extract them.

		// Let's re-examine server.Config structure.
		// server.Config HAS RecursiveConfig (resolver.Config).
		// So simpler approach: Just load server.Config?

		// But User wants "rich configuration file" and "dhcp".
		// Wrapping it in a top-level Config struct is better for extensibility (like adding DHCP).
	}

	// Create a temporary struct matching the YAML structure to decode
	// We want to decode onto the defaults.

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	if err := cfg.Runtime.Validate(); err != nil {
		return nil, err
	}

	// Historical examples placed these sections at the top level while the
	// daemon only read their nested server equivalents. Decode each present
	// section onto the already-defaulted live configuration so omitted values
	// retain secure defaults.
	if err := overlayTopLevel(data, "resolver", &cfg.Server.RecursiveConfig); err != nil {
		return nil, fmt.Errorf("parse resolver config: %w", err)
	}
	if err := overlayTopLevel(data, "cache", &cfg.Server.RecursiveConfig.CacheConfig); err != nil {
		return nil, fmt.Errorf("parse cache config: %w", err)
	}
	cfg.Resolver = cfg.Server.RecursiveConfig
	cfg.Cache = cfg.Server.RecursiveConfig.CacheConfig
	if err := overlayTopLevel(data, "firewall", &cfg.Server.Firewall); err != nil {
		return nil, fmt.Errorf("parse firewall config: %w", err)
	}
	cfg.Firewall = cfg.Server.Firewall
	if err := overlayTopLevel(data, "experimental", &cfg.Server.Experimental); err != nil {
		return nil, fmt.Errorf("parse experimental config: %w", err)
	}
	cfg.Experimental = cfg.Server.Experimental

	// Post-processing
	// 1. Parse RRL ExemptCIDRs into ExemptPrefixes
	if len(cfg.Server.RRLConfig.ExemptCIDRs) > 0 {
		for _, cidr := range cfg.Server.RRLConfig.ExemptCIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid rrl exempt cidr %s: %w", cidr, err)
			}
			cfg.Server.RRLConfig.ExemptPrefixes = append(cfg.Server.RRLConfig.ExemptPrefixes, ipnet)
		}
	}

	return cfg, nil
}

func overlayTopLevel(data []byte, key string, target any) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return err
	}
	if len(document.Content) == 0 || len(document.Content[0].Content) == 0 {
		return nil
	}
	mapping := document.Content[0]
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1].Decode(target)
		}
	}
	return nil
}
