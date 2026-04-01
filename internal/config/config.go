package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/dnsscience/dnsscienced/internal/resolver"
	"github.com/dnsscience/dnsscienced/internal/server"
	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration structure
type Config struct {
	Server   server.Config   `yaml:"server"`
	Resolver resolver.Config `yaml:"resolver"`

	// DHCP Configuration (Placeholder for future implementation)
	DHCP DHCPConfig `yaml:"dhcp"`
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
		Server: server.DefaultConfig(),
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
