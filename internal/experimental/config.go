package experimental

import "time"

// Config holds configuration for experimental/draft IETF protocols
type Config struct {
	// Enable experimental/draft features
	Enabled bool `yaml:"enabled"`

	// Individual protocol enablement flags
	DNSSD  DnssdConfig  `yaml:"dns_sd"`
	DoQ    DoQConfig    `yaml:"doq"`
	DSO    DSOConfig    `yaml:"dso"`
	DELEG  DelegConfig  `yaml:"deleg"`
	DID    DIDConfig    `yaml:"did"`
	IoTDNS IoTDNSConfig `yaml:"iot_dns"`
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
	}
}

// IsAnyEnabled returns true if any experimental feature is enabled
func (c *Config) IsAnyEnabled() bool {
	if !c.Enabled {
		return false
	}
	return c.DNSSD.Enabled || c.DoQ.Enabled || c.DSO.Enabled ||
		c.DELEG.Enabled || c.DID.Enabled || c.IoTDNS.Enabled
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
	return features
}
