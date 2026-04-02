package dnssec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidationResult represents the result of DNSSEC validation
type ValidationResult struct {
	// Validation status
	Secure    bool   // Cryptographically validated
	Bogus     bool   // Validation failed (bad signature, etc.)
	Insecure  bool   // Not signed (no DNSSEC)
	Indeterminate bool // Unable to determine (network error, etc.)

	// Details
	Error        error  // Validation error if any
	ErrorMessage string // Human-readable error message
	ChainDepth   int    // Length of the DNSSEC chain validated

	// Trust chain
	TrustChain []TrustAnchor // Chain of trust from root to target
	DSRecords  []dns.DS      // DS records in the chain
	DNSKEYs    []dns.DNSKEY  // DNSKEY records validated

	// Signature information
	Signatures []dns.RRSIG // RRSIG records validated
	ValidFrom  time.Time   // Earliest signature inception
	ValidUntil time.Time   // Latest signature expiration
}

// TrustAnchor represents a DNSSEC trust anchor in the chain
type TrustAnchor struct {
	Name      string      // Zone name
	DNSKEY    dns.DNSKEY  // Key
	DS        *dns.DS     // DS record from parent (nil for root)
	Validated bool        // Whether this anchor was validated
	Error     error       // Validation error if any
}

// Validator performs DNSSEC validation
type Validator struct {
	// Configuration
	config ValidatorConfig

	// Trust anchors (root keys)
	trustAnchors []dns.DNSKEY

	// Negative trust anchors (domains to skip validation)
	negativeTrustAnchors map[string]bool

	// Resolver for querying DNSKEY and DS records
	resolver DNSResolver

	// Cache for validated keys and signatures
	cache *ValidationCache
}

// ValidatorConfig holds DNSSEC validator configuration
type ValidatorConfig struct {
	// Chain validation settings
	MaxChainDepth   int           // Maximum chain depth (default: 20)
	DSLookup        bool          // Query parent zones for DS records
	AcceptBogus     bool          // Accept bogus responses (don't fail)
	FailOnBogus     bool          // Return error on bogus
	FailOnMissing   bool          // Fail when DNSSEC expected but missing

	// Caching
	CachePositive   bool          // Cache validated responses
	CacheNegative   bool          // Cache NSEC/NSEC3 proofs
	CacheBogus      bool          // Cache bogus responses
	CacheTTL        time.Duration // Cache TTL

	// NSEC/NSEC3 settings
	NSEC3MaxIterations uint16 // Maximum NSEC3 iterations to accept
	ValidateNSEC       bool   // Validate NSEC/NSEC3 proofs

	// Algorithm support
	DisabledAlgorithms map[uint8]bool // Algorithms to reject

	// Logging
	LogValidation bool // Log all validation attempts
	LogFailures   bool // Log failures only
}

// DNSResolver interface for querying DNS records
type DNSResolver interface {
	Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

// DefaultValidatorConfig returns secure default configuration
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		MaxChainDepth:      20,
		DSLookup:           true,
		AcceptBogus:        false,
		FailOnBogus:        true,
		FailOnMissing:      false,
		CachePositive:      true,
		CacheNegative:      true,
		CacheBogus:         true,
		CacheTTL:           time.Hour,
		NSEC3MaxIterations: 150, // RFC 5155 recommendation
		ValidateNSEC:       true,
		DisabledAlgorithms: make(map[uint8]bool),
		LogValidation:      false,
		LogFailures:        true,
	}
}

// NewValidator creates a new DNSSEC validator
func NewValidator(config ValidatorConfig, resolver DNSResolver) (*Validator, error) {
	if resolver == nil {
		return nil, fmt.Errorf("resolver cannot be nil")
	}

	if config.MaxChainDepth == 0 {
		config.MaxChainDepth = 20
	}

	v := &Validator{
		config:               config,
		trustAnchors:         make([]dns.DNSKEY, 0),
		negativeTrustAnchors: make(map[string]bool),
		resolver:             resolver,
		cache:                NewValidationCache(config.CacheTTL),
	}

	return v, nil
}

// AddTrustAnchor adds a trust anchor (typically root KSK)
func (v *Validator) AddTrustAnchor(key dns.DNSKEY) {
	v.trustAnchors = append(v.trustAnchors, key)
}

// AddNegativeTrustAnchor adds a domain to skip validation
func (v *Validator) AddNegativeTrustAnchor(domain string) {
	v.negativeTrustAnchors[strings.ToLower(dns.Fqdn(domain))] = true
}

// LoadTrustAnchorsFromFile loads trust anchors from a file (RFC 5011 format)
func (v *Validator) LoadTrustAnchorsFromFile(filename string) error {
	// Parse trust anchor file
	// Format: ". IN DNSKEY 257 3 8 AwEAAa..."
	// This is a simplified implementation - production should handle RFC 5011 format
	return fmt.Errorf("LoadTrustAnchorsFromFile not yet implemented")
}

// Validate performs DNSSEC validation on a DNS response
func (v *Validator) Validate(ctx context.Context, msg *dns.Msg, qname string, qtype uint16) (*ValidationResult, error) {
	qname = dns.Fqdn(strings.ToLower(qname))

	// Check negative trust anchors
	if v.isNegativeTrustAnchor(qname) {
		return &ValidationResult{
			Insecure:     true,
			ErrorMessage: "Domain in negative trust anchors (validation skipped)",
		}, nil
	}

	// Check if response has DNSSEC records
	if !hasDNSSECRecords(msg) {
		if v.config.FailOnMissing {
			return &ValidationResult{
				Bogus:        true,
				ErrorMessage: "DNSSEC expected but not present",
			}, fmt.Errorf("DNSSEC expected but not present")
		}
		return &ValidationResult{
			Insecure:     true,
			ErrorMessage: "Response not signed",
		}, nil
	}

	// Validate the response
	result, err := v.validateResponse(ctx, msg, qname, qtype)
	if err != nil {
		if v.config.LogFailures {
			// Log validation failure
		}
		return result, err
	}

	if v.config.LogValidation {
		// Log successful validation
	}

	return result, nil
}

// validateResponse performs the actual DNSSEC validation
func (v *Validator) validateResponse(ctx context.Context, msg *dns.Msg, qname string, qtype uint16) (*ValidationResult, error) {
	result := &ValidationResult{
		TrustChain: make([]TrustAnchor, 0),
	}

	// Extract RRSIGs from response
	rrsigs := extractRRSIGs(msg, qname, qtype)
	if len(rrsigs) == 0 {
		result.Bogus = true
		result.ErrorMessage = "No RRSIG records found"
		return result, fmt.Errorf("no RRSIG records found for %s/%d", qname, qtype)
	}

	result.Signatures = rrsigs

	// Build and validate chain of trust
	if err := v.buildTrustChain(ctx, qname, result); err != nil {
		result.Bogus = true
		result.Error = err
		result.ErrorMessage = fmt.Sprintf("Trust chain validation failed: %v", err)
		return result, err
	}

	// Verify signatures
	if err := v.verifySignatures(msg, qname, qtype, result); err != nil {
		result.Bogus = true
		result.Error = err
		result.ErrorMessage = fmt.Sprintf("Signature verification failed: %v", err)
		return result, err
	}

	// Validation successful
	result.Secure = true
	return result, nil
}

// buildTrustChain builds the DNSSEC chain of trust from root to target zone
func (v *Validator) buildTrustChain(ctx context.Context, qname string, result *ValidationResult) error {
	labels := dns.SplitDomainName(qname)

	// Start from root
	currentZone := "."

	// Walk down the chain
	for i := len(labels) - 1; i >= 0; i-- {
		nextZone := dns.Fqdn(strings.Join(labels[i:], "."))

		// Check chain depth
		if result.ChainDepth >= v.config.MaxChainDepth {
			return fmt.Errorf("max chain depth exceeded")
		}

		// Query for DS record at parent zone
		if v.config.DSLookup && currentZone != nextZone {
			dsRecords, err := v.queryDS(ctx, nextZone, currentZone)
			if err != nil {
				return fmt.Errorf("DS lookup failed for %s: %w", nextZone, err)
			}

			if len(dsRecords) > 0 {
				result.DSRecords = append(result.DSRecords, dsRecords...)
			}
		}

		// Query for DNSKEY at target zone
		dnskeys, err := v.queryDNSKEY(ctx, nextZone)
		if err != nil {
			return fmt.Errorf("DNSKEY lookup failed for %s: %w", nextZone, err)
		}

		// Validate DNSKEYs against DS records
		// (Simplified - full implementation would validate each key)
		if len(dnskeys) > 0 {
			result.DNSKEYs = append(result.DNSKEYs, dnskeys...)
		}

		result.ChainDepth++
		currentZone = nextZone
	}

	return nil
}

// verifySignatures verifies RRSIG signatures for the response
func (v *Validator) verifySignatures(msg *dns.Msg, qname string, qtype uint16, result *ValidationResult) error {
	// Extract RRset to verify
	rrset := extractRRset(msg, qname, qtype)
	if len(rrset) == 0 {
		return fmt.Errorf("no RRset found to verify")
	}

	// Verify each signature
	for _, rrsig := range result.Signatures {
		// Check signature validity period
		now := time.Now()
		if now.Before(rrsig.Inception) || now.After(rrsig.Expiration) {
			return fmt.Errorf("signature outside validity period")
		}

		// Update result validity times
		if result.ValidFrom.IsZero() || rrsig.Inception.Before(result.ValidFrom) {
			result.ValidFrom = rrsig.Inception
		}
		if result.ValidUntil.IsZero() || rrsig.Expiration.After(result.ValidUntil) {
			result.ValidUntil = rrsig.Expiration
		}

		// Find matching DNSKEY
		dnskey := findDNSKEY(result.DNSKEYs, rrsig.SignerName, rrsig.KeyTag)
		if dnskey == nil {
			return fmt.Errorf("no DNSKEY found for RRSIG (keytag=%d)", rrsig.KeyTag)
		}

		// Verify signature (using miekg/dns)
		if err := rrsig.Verify(dnskey, rrset); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	return nil
}

// queryDS queries for DS records at parent zone
func (v *Validator) queryDS(ctx context.Context, zone string, parent string) ([]dns.DS, error) {
	msg, err := v.resolver.Query(ctx, zone, dns.TypeDS)
	if err != nil {
		return nil, err
	}

	dsRecords := make([]dns.DS, 0)
	for _, rr := range msg.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			dsRecords = append(dsRecords, *ds)
		}
	}

	return dsRecords, nil
}

// queryDNSKEY queries for DNSKEY records
func (v *Validator) queryDNSKEY(ctx context.Context, zone string) ([]dns.DNSKEY, error) {
	msg, err := v.resolver.Query(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}

	dnskeys := make([]dns.DNSKEY, 0)
	for _, rr := range msg.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			// Check if algorithm is disabled
			if v.config.DisabledAlgorithms[key.Algorithm] {
				continue
			}
			dnskeys = append(dnskeys, *key)
		}
	}

	return dnskeys, nil
}

// isNegativeTrustAnchor checks if a domain is in negative trust anchors
func (v *Validator) isNegativeTrustAnchor(qname string) bool {
	qname = dns.Fqdn(strings.ToLower(qname))

	// Check exact match and parent zones
	labels := dns.SplitDomainName(qname)
	for i := 0; i < len(labels); i++ {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		if v.negativeTrustAnchors[zone] {
			return true
		}
	}

	return false
}

// Helper functions

func hasDNSSECRecords(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG || rr.Header().Rrtype == dns.TypeDS {
			return true
		}
	}
	return false
}

func extractRRSIGs(msg *dns.Msg, qname string, qtype uint16) []dns.RRSIG {
	rrsigs := make([]dns.RRSIG, 0)

	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			if rrsig.TypeCovered == qtype && strings.EqualFold(rrsig.Header().Name, qname) {
				rrsigs = append(rrsigs, *rrsig)
			}
		}
	}

	return rrsigs
}

func extractRRset(msg *dns.Msg, qname string, qtype uint16) []dns.RR {
	rrset := make([]dns.RR, 0)

	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qtype && strings.EqualFold(rr.Header().Name, qname) {
			rrset = append(rrset, rr)
		}
	}

	return rrset
}

func findDNSKEY(dnskeys []dns.DNSKEY, signerName string, keyTag uint16) *dns.DNSKEY {
	for i := range dnskeys {
		key := &dnskeys[i]
		if strings.EqualFold(key.Header().Name, signerName) && key.KeyTag() == keyTag {
			return key
		}
	}
	return nil
}
